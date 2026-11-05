"""Bounded official verification web flows for a saved account."""
import argparse
from functools import partial
import hashlib
import imaplib
import importlib.util
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
from urllib.parse import urlencode

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[2]
ROOT = Path('F:/PhoneExit Resources/Vampir')
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.account_store import AccountStore
from vampir_core.sdk_config import select_sdk_build_code
from vampir_core.sdk_launcher_admission import scope
from vampir_core.socks_route import SocksRoute

SHA = re.compile('[a-f0-9]{64}')
KNOWLEDGE = HERE.parent / 'resource-tools/vampir/knowledge'
ENDPOINTS = {
    'device-registration': ('deviceWebViewUrl', 'https://profile-auth-view.netmarble.com/secure/device'),
    'workplace': ('unrestrictionWebViewUrl', 'https://profile-auth-view.netmarble.com/restriction'),
}
BROWSER_RESULTS = frozenset(('verified', 'cancelled', 'invalid_context', 'timeout', 'browser_failed',
    'multiple_mail_requests', 'server_rejected', 'response_unknown', 'mail_unavailable',
    'abnormal_pattern', 'captcha_required', 'form_unknown'))


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def selected_profile():
    path = KNOWLEDGE / 'sdk-launcher-runtime-profile-current.json'
    value = json.loads(path.read_bytes())
    digest = value['profile']['sha256']
    if value['schema'] != 1 or not SHA.fullmatch(digest):
        raise ValueError('Invalid SDK profile pointer')
    check_source(value['source_sha256'])
    expected = ROOT / 'sdk-launcher-profiles' / digest / 'manifest.json'
    if Path(value['profile']['path']).resolve() != expected.resolve():
        raise ValueError('SDK profile pointer is outside the immutable library')
    return 'sdk-launcher:' + digest


def check_source(source_sha256):
    contract = json.loads((KNOWLEDGE / 'verification-web-current.json').read_bytes())
    forms = contract.get('forms', {})
    if (contract.get('schema') != 1 or contract.get('source_sha256') != source_sha256
            or set(forms) != set(ENDPOINTS)
            or any((form.get('config_key'), form.get('endpoint')) != ENDPOINTS[purpose]
                   for purpose, form in forms.items())):
        raise ValueError('Verification web contract is not available for this client SHA')


def web_url(purpose, prepared, data, device_name):
    key, endpoint = ENDPOINTS[purpose]
    if prepared.constants.get(key) != endpoint:
        raise ValueError('Official verification web endpoint changed')
    profile, binding, geo = prepared.profile, prepared.binding, prepared.geo
    if profile['game_code'] != 'thered' or not data.access_token or not data.player_id:
        raise ValueError('SDK context lacks verification data')
    if not re.fullmatch('[A-Z]{2}', data.joined_country_code or ''):
        raise ValueError('SDK joined country is missing')
    fields = dict(gameCode=profile['game_code'], buildCode=select_sdk_build_code(profile['build_code']),
        playerId=data.player_id, accessToken=data.access_token, nmDeviceKey=binding.nm_device_key,
        countryCode=geo.iso_country, joinedCountryCode=data.joined_country_code,
        language=profile['language'], osType=profile['os_type'], deviceIp=geo.client_ip,
        deviceName=device_name, webViewType='sdk')
    if purpose == 'device-registration':
        fields['deviceKey'] = binding.device_key
    url = endpoint + '?' + urlencode(fields)
    if len(url) > 32768:
        raise ValueError('Verification URL exceeds budget')
    return url


def browser(purpose, *, url, email, directory, port, library, mailbox, progress):
    command = ['powershell.exe', '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File',
               str(HERE / 'windows/verification-browser.ps1')]
    request = dict(url=url, purpose=purpose, game_code='thered', email=email,
        directory=str(directory), port=port or 0, library=str(library))
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    def terminate():
        if process.poll() is None:
            subprocess.run(['taskkill.exe', '/PID', str(process.pid), '/T', '/F'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           creationflags=subprocess.CREATE_NO_WINDOW)

    watchdog = threading.Timer(630, terminate)
    watchdog.start()
    try:
        process.stdin.write(json.dumps(request).encode('utf-8') + b'\n')
        process.stdin.flush()
        event = process.stdout.readline(128).strip()
        if event == b'mail_sent':
            progress('verification_mail')
            try:
                code = mailbox.get_code(600, cancelled=lambda: process.poll() is not None)
            except (OSError, RuntimeError, ValueError, imaplib.IMAP4.error):
                code = ''
            if process.poll() is None:
                process.stdin.write(code.encode('ascii') + b'\n')
                process.stdin.flush()
            code = None
            event = process.stdout.readline(128).strip()
        status = event.decode('ascii', 'replace')
        if process.wait(timeout=10) != 0 or status not in BROWSER_RESULTS:
            return 'browser_failed'
        return status
    finally:
        watchdog.cancel()
        terminate()
        try:
            process.wait(timeout=10)
        finally:
            process.stdin.close()
            process.stdout.close()


def verify(store, account, *, selector=None, manual_sign_in=False, progress=lambda stage: None):
    email, password, settings = store.credential(account)
    settings = AccountStore.assignment(settings)
    if not settings['enabled'] or not email.endswith('@vampir.top'):
        raise ValueError('An enabled @vampir.top account is required')
    mail_password = store.reveal_password(account, 'mail')
    selector = selector or selected_profile()
    port = settings['socks_port']
    route = SocksRoute(port) if port is not None else None
    runner = load('run-nid-sdk-sign-in')
    nid = load('nid-browser')

    def sign_in(manual):
        with scope(selector, root=ROOT, workspace=WORKSPACE):
            progress('configuration')
            prepared = runner.load_inputs(email, route=route, selected_profile=selector,
                                          device_settings=settings['device_settings'])
            check_source(prepared.source_sha256)
            def sign_in_progress(stage):
                progress('manual_nid_browser' if manual and stage == 'nid_browser' else stage)
            capture = partial(nid.capture_nid_credential, bind_manual_email=True) if manual else nid.capture_nid_credential
            data = runner.run(email, password='' if manual else password, timeout=180, selected_profile=selector,
                auth_flow='launcher', socks_port=port, _prepared_inputs=prepared, _capture=capture,
                device_settings=settings['device_settings'], _progress=sign_in_progress)
        return data, prepared

    try:
        data, prepared = sign_in(manual_sign_in)
    except nid.NidBrowserStatusError as error:
        if manual_sign_in or error.browser_status != 'login_failed':
            raise
        # NID refused before SDK or mail actions. Open the same account's form without autofill.
        data, prepared = sign_in(True)
    password = None
    if data.verification_steps is None:
        return 'unknown_player_status', []
    completed = []
    if not data.verification_steps:
        return 'verified', completed
    mail = load('nid-mail-code')
    library = nid._library()
    private_key = '|'.join((email, prepared.binding.device_key, prepared.binding.nm_device_key, str(port)))
    directory = HERE / '.local/verification-browser' / hashlib.sha256(private_key.encode()).hexdigest()[:32]
    for purpose in data.verification_steps:
        url = web_url(purpose, prepared, data, socket.gethostname()[:20])
        progress('verify_' + purpose)
        mailbox = mail.RegistrationMailbox(email, mail_password,
            purpose=purpose if purpose == 'device-registration' else 'account-protection')
        try:
            result = browser(purpose, url=url, email=email, directory=directory, port=port,
                             library=library, mailbox=mailbox, progress=progress)
        finally:
            mailbox.close()
        if result != 'verified':
            return result, completed
        completed.append(purpose)
    return 'verified', completed


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Верификация одного сохранённого аккаунта Vampir')
    parser.add_argument('--account', required=True)
    parser.add_argument('--manual-sign-in', action='store_true')
    parser.add_argument('--store', type=Path, default=HERE / '.local/console.sqlite3')
    args = parser.parse_args()
    try:
        status, completed = verify(AccountStore(args.store), args.account, manual_sign_in=args.manual_sign_in,
            progress=lambda stage: print(json.dumps(dict(stage=stage)), flush=True))
    except (ValueError, RuntimeError, OSError, KeyError) as error:
        status, completed = 'local_error', []
        print(json.dumps(dict(error_type=type(error).__name__)), flush=True)
    print(json.dumps(dict(status=status, completed=completed)), flush=True)
    sys.exit(0 if status == 'verified' else 2)
