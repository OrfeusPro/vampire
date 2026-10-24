"""Explicit bot-account registration through a selected direct or SOCKS route.

Passwords enter only on stdin. No SDK player creation, game process or tokens on disk.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import imaplib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def prepare_observed_profile(runner, address, *, selected_profile='recovered-base'):
    if selected_profile == 'recovered-release':
        loader = module('registration_source', 'sdk-source-profile.py')
        source = loader.load_release_profile('nid', root=runner.ROOT)
    elif selected_profile == 'recovered-base':
        source_path = runner.ROOT / 'code-clues/nid-windows-initial-profile.json'
        if hashlib.sha256(source_path.read_bytes()).hexdigest() != runner.PROFILE_SHA:
            raise ValueError('NID source profile changed')
        source = json.loads(source_path.read_text('utf-8'))
    else:
        raise ValueError('Unknown source profile')
    if hashlib.sha256(Path(source['source']).read_bytes()).hexdigest() != source['source_sha256']:
        raise ValueError('Installed client changed')
    identity = runner.observe_windows_device_identity(store_name='Netmarble', game_code='thered')
    registry = runner.DeviceRegistry(HERE / '.local/accounts.sqlite3')
    binding = registry.register(address, kind='real')
    provenance = ('HKCU stored identity; observed ' + datetime.now(timezone.utc).date().isoformat() +
        '; client SHA256 ' + source['source_sha256'] +
        '; active SDK cache and server binding unverified; ')
    if binding.identity_recorded:
        if (binding.device_key, binding.nm_device_key) != (identity.device_key, identity.nm_device_key):
            raise ValueError('Observed SDK identity differs from registered profile')
    else:
        registry.record_real_identity(address, device_key=identity.device_key, nm_device_key=identity.nm_device_key,
            source=provenance + identity.sdk_registry_path + ' DeviceKey; ' + identity.nm_registry_path + ' NMDeviceKey')
    if binding.nid_identity_recorded:
        if binding.nid_device_key != identity.nid_device_key:
            raise ValueError('Observed NID identity differs from registered profile')
    else:
        registry.record_real_nid_identity(address, nid_device_key=identity.nid_device_key,
            source=provenance + identity.sdk_registry_path + ' DeviceKeyForNetmarbleId')


def run(address, *, password, mail_password, socks_port=None, timeout=300, accept_required_terms=False,
        selected_profile='recovered-base', _progress=None, _code_provider=None, device_settings=None):
    if accept_required_terms is not True: raise ValueError('Explicit acceptance of required terms is missing')
    runner = module('registration_runner', 'run-nid-sdk-sign-in.py')
    browser = module('registration_browser', 'nid-browser.py')
    mail = module('registration_mail', 'nid-mail-code.py')
    route = runner.SocksRoute(socks_port) if socks_port is not None else None
    # Opening the named mailbox first establishes a UID baseline before Send.
    if _code_provider is not None and not callable(_code_provider):
        raise TypeError('Expected explicit code provider')
    mailbox = mail.RegistrationMailbox(address, mail_password) if _code_provider is None else None
    try:
        prepare_observed_profile(runner, address, selected_profile=selected_profile)
        binding, profile, constants = runner.load_inputs(address, route=route, selected_profile=selected_profile, **({'device_settings':device_settings} if device_settings else {}))
        context = runner.prepare_nid_sign_in_context(binding=binding, **profile)
        url = runner.bind_nid_web_url(context, constants=constants, max_url_size=32768)
        completed = False
        confirmed_steps = set()
        def progress(state):
            nonlocal completed
            completed = completed or state.get('complete') is True
            confirmed_steps.update(key for key in ('terms_submitted', 'email_sent', 'code_submitted', 'password_submitted')
                if state.get(key) is True)
            if _progress:
                _progress(state)
                return
            print(json.dumps(dict(registration_stage=state.get('path'),
                mail_sent=bool(state.get('email_sent')), waiting_for_code=bool(state.get('need_code')),
                registration_complete=bool(state.get('complete')), stopped=state.get('stopped'))), flush=True)
        account_directory = hashlib.sha256(address.strip().lower().encode('utf-8')).hexdigest()[:24]
        provider = browser.capture_nid_credential(url, expected_game_code=profile['game_code'],
            data_directory=HERE / '.local/nid-accounts' / account_directory / ('registration-socks-' + str(socks_port) if route else 'registration-direct'),
            timeout=timeout, expected_email=address, sign_in_password=password, socks_port=socks_port,
            register_account=True, code_provider=mailbox.get_code if mailbox is not None else _code_provider, progress=progress)
        # The official SDK webview signs in immediately after email signup and
        # can return the validated callback without visiting /email/complete.
        # A callback alone is insufficient: require every explicit signup step.
        if not completed and confirmed_steps != {'terms_submitted', 'email_sent', 'code_submitted', 'password_submitted'}:
            raise RuntimeError('Registration completion was not observed')
        return provider
    finally:
        if mailbox is not None:
            mailbox.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--email', required=True)
    parser.add_argument('--socks-port', type=int)
    parser.add_argument('--profile', choices=['recovered-base', 'recovered-release'], default='recovered-base')
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--accept-required-terms', action='store_true', required=True,
        help='Explicitly accept required Terms of Service and Privacy Policy; no marketing consent')
    parser.add_argument('--passwords-stdin', action='store_true', required=True,
        help='Two lines: Netmarble password, then mailbox password; no command-line secrets')
    args = parser.parse_args()
    try:
        password = sys.stdin.readline(258).rstrip('\r\n')
        mail_password = sys.stdin.readline(258).rstrip('\r\n')
        if not password or not mail_password or max(len(password), len(mail_password)) > 256:
            raise ValueError('Invalid password input')
        provider = run(args.email, password=password, mail_password=mail_password,
            socks_port=args.socks_port, timeout=args.timeout, accept_required_terms=args.accept_required_terms,
            selected_profile=args.profile)
        password = mail_password = None
        print(json.dumps(dict(nid_callback_accepted=True, joined_country=provider.joined_country_code,
            sdk_player_created=False, game_session_ready=False)))
    except (ValueError, RuntimeError, PermissionError, KeyError, OSError, imaplib.IMAP4.error):
        print(json.dumps(dict(nid_callback_accepted=False, error='registration_not_completed')))
        sys.exit(2)
