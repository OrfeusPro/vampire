"""Windows NID browser adapter. Auth URL/callback travel only through pipes.

No real login is started by importing this module. --smoke uses only synthetic
HTML and a synthetic callback; it never visits the auth endpoint.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.nid_result import parse_nid_email_callback
from vampir_core.nid_web_url import NidWebUrl
from vampir_core.socks_route import SocksRoute


class NidBrowserStatusError(RuntimeError):
    def __init__(self, status, step, http_status=None, code=None, response_state=None):
        super().__init__('NID browser did not return a sign-in result')
        self.browser_status = status if status in ('timeout', 'cancelled', 'browser_initialization_failed',
            'browser_process_failed', 'untrusted_callback_origin', 'login_failed') else 'unknown'
        self.sign_in_step = step if step in ('manual', 'waiting', 'opened_email', 'filled',
            'submitted', 'form_changed', 'script_failed') else 'unknown'
        self.nid_http_status = http_status if type(http_status) is int and 100 <= http_status <= 599 else None
        self.nid_error_code = code if type(code) is int and -(2**31) <= code < 2**31 else None
        self.nid_response_state = response_state if response_state in ('not_observed', 'non_json', 'length_limit',
            'body_limit', 'length_mismatch', 'numeric_code', 'no_numeric_code', 'read_failed',
            'invalid_utf8', 'content_unavailable', 'response_observation_failed') else 'not_observed'


def _library():
    lock = json.loads((HERE.parent / 'resource-tools/vampir/webview2.lock.json').read_text('utf-8'))
    folder = Path('F:/PhoneExit Resources/Vampir/tools/webview2') / lock['version']
    for name, digest in lock['files'].items():
        path = folder / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Install the pinned WebView2 host DLLs before opening NID')
    return folder


def _run(*, url, game_code, timeout, data_directory, smoke, account_hint='', sign_in_password='', socks_port=None,
         register_account=False, code_provider=None, progress=None):
    if sys.platform != 'win32': raise RuntimeError('NID browser adapter requires Windows')
    if socks_port is not None: SocksRoute(socks_port)
    if type(timeout) is not int or not 1 <= timeout <= 900: raise ValueError('Invalid browser timeout')
    if (type(game_code) is not str or not 1 <= len(game_code) <= 64 or
            any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in game_code)):
        raise ValueError('Invalid NID game scope')
    if (type(sign_in_password) is not str or len(sign_in_password) > 256 or
            (sign_in_password and (not account_hint or len(account_hint) > 320))):
        raise ValueError('Invalid explicit sign-in credentials')
    if type(register_account) is not bool or (register_account and
            (smoke or not sign_in_password or not callable(code_provider))):
        raise ValueError('Registration requires a password and mail-code provider')
    request = json.dumps(dict(url=url, game_code=game_code, timeout=timeout,
        data_directory=str(Path(data_directory).resolve()), library=str(_library()), smoke=smoke,
        account_hint=account_hint, sign_in_password=sign_in_password, socks_port=socks_port or 0,
        register_account=register_account))
    command = ['powershell.exe', '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass',
               '-File', str(HERE / 'windows/nid-browser.ps1')]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    watchdog = None
    try:
        if register_account:
            def terminate():
                subprocess.run(['taskkill.exe', '/PID', str(process.pid), '/T', '/F'],
                    capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            watchdog = threading.Timer(timeout + 20, terminate)
            watchdog.start()
            process.stdin.write((request + '\n').encode('utf-8'))
            process.stdin.flush()
            sent_code = False
            budget = 0
            while True:
                line = process.stdout.readline(16385)
                budget += len(line)
                if not line or budget > 65536 or len(line) > 16384:
                    raise RuntimeError('Registration helper response limit or EOF')
                event = json.loads(line.decode('utf-8-sig'))
                if 'registration' not in event:
                    output = line
                    process.wait(timeout=10)
                    break
                state = event['registration']
                if not isinstance(state, dict): raise ValueError('Invalid registration state')
                if progress: progress(state)
                if state.get('need_code') and not sent_code:
                    code = code_provider()
                    if type(code) is not str or len(code) != 5 or not code.isascii() or not code.isdigit():
                        raise ValueError('Invalid email verification code')
                    process.stdin.write((code + '\n').encode('ascii'))
                    process.stdin.flush()
                    sent_code = True
                    code = None
        else:
            output, _ = process.communicate((request + '\n').encode('utf-8'), timeout=timeout + 20)
    except BaseException:
        # Kill only the helper process tree created above if normal timed UI
        # shutdown fails or its owning caller is interrupted.
        subprocess.run(['taskkill.exe', '/PID', str(process.pid), '/T', '/F'],
                       capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        process.communicate()
        raise RuntimeError('NID browser helper did not finish normally') from None
    finally:
        if watchdog: watchdog.cancel()
        request = None
        if process.poll() is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream and not stream.closed: stream.close()
    if process.returncode or len(output) > 65536:
        raise RuntimeError('NID browser helper failed')
    try:
        result = json.loads(output.decode('utf-8-sig'))
        if not isinstance(result, dict) or not isinstance(result.get('status'), str): raise ValueError
    except (ValueError, UnicodeError):
        raise RuntimeError('Invalid NID browser helper response') from None
    return result


def capture_nid_credential(plan, *, expected_game_code, data_directory, timeout=300, expected_email='', sign_in_password='', socks_port=None,
                           register_account=False, code_provider=None, progress=None):
    """Open official sign-in UI; the user completes login/verification there.

    The parent validates the captured route and email result, then returns a
    redacted provider credential. No token files, OS scheme handler or SDK HTTP.
    This is route/origin handling, not proof of server token validity.
    """
    if not isinstance(plan, NidWebUrl): raise TypeError('Expected a prepared NID URL')
    if type(register_account) is not bool: raise ValueError('Explicit registration mode required')
    try:
        parts = urlsplit(plan.url)
        params = parse_qs(parts.query, keep_blank_values=True, strict_parsing=True)
        if (len(plan.url) > 131072 or parts.scheme != 'https' or parts.netloc != 'members.netmarble.com'
                or parts.path != '/auth' or parts.fragment or params.get('gameCode') != [expected_game_code]
                or params.get('webViewType') != ['sdk'] or params.get('authType') != ['signin']):
            raise ValueError
    except ValueError:
        raise ValueError('NID browser requires the expected SDK sign-in context') from None
    registration = dict(register_account=True, code_provider=code_provider, progress=progress) if register_account else {}
    result = _run(url=plan.url, game_code=expected_game_code, timeout=timeout,
                  data_directory=data_directory, smoke=False, account_hint=expected_email,
                  sign_in_password=sign_in_password, socks_port=socks_port, **registration)
    if result['status'] != 'callback':
        error = NidBrowserStatusError(result['status'], result.get('sign_in_step'),
            result.get('nid_http_status'), result.get('nid_error_code'), result.get('nid_response_state'))
        result.clear()
        raise error
    callback = result.get('callback')
    try:
        return parse_nid_email_callback(callback, expected_game_code=expected_game_code)
    except ValueError:
        raise ValueError('NID browser result was not an accepted email sign-in') from None
    finally:
        result.clear()
        callback = None


def smoke():
    result = _run(url='', game_code='thered', timeout=15,
                  data_directory=HERE / '.local/webview-smoke', smoke=True)
    if result.get('status') != 'callback': raise RuntimeError('Browser smoke did not capture callback')
    credential = parse_nid_email_callback(result['callback'], expected_game_code='thered')
    if credential.access_token != 'synthetic-token' or credential.netmarble_id != 'synthetic-id':
        raise RuntimeError('Browser smoke callback differs')
    if result.get('blocked_external', 0) < 2 or result.get('blocked_popups', 0) < 1:
        raise RuntimeError('Browser smoke did not exercise URI/popup cancellation')
    if (result.get('nid_http_status'), result.get('nid_error_code'), result.get('nid_response_state')) != (400, 321, 'numeric_code'):
        raise RuntimeError('Synthetic response diagnostic failed: ' + str(result.get('nid_response_state')))
    return dict(synthetic_only=True, callback_captured=True, blocked_external=result['blocked_external'],
                blocked_popups=result['blocked_popups'], response_code_checked=True, game_started=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--smoke', action='store_true', required=True)
    parser.parse_args()
    print(json.dumps(smoke()))
