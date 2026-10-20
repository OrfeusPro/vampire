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
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.nid_result import parse_nid_email_callback
from vampir_core.nid_web_url import NidWebUrl


def _library():
    lock = json.loads((HERE.parent / 'resource-tools/vampir/webview2.lock.json').read_text('utf-8'))
    folder = Path('F:/PhoneExit Resources/Vampir/tools/webview2') / lock['version']
    for name, digest in lock['files'].items():
        path = folder / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Install the pinned WebView2 host DLLs before opening NID')
    return folder


def _run(*, url, game_code, timeout, data_directory, smoke, account_hint='', sign_in_password=''):
    if sys.platform != 'win32': raise RuntimeError('NID browser adapter requires Windows')
    if type(timeout) is not int or not 1 <= timeout <= 900: raise ValueError('Invalid browser timeout')
    if (type(game_code) is not str or not 1 <= len(game_code) <= 64 or
            any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in game_code)):
        raise ValueError('Invalid NID game scope')
    if (type(sign_in_password) is not str or len(sign_in_password) > 256 or
            (sign_in_password and (not account_hint or len(account_hint) > 320))):
        raise ValueError('Invalid explicit sign-in credentials')
    request = json.dumps(dict(url=url, game_code=game_code, timeout=timeout,
        data_directory=str(Path(data_directory).resolve()), library=str(_library()), smoke=smoke,
        account_hint=account_hint, sign_in_password=sign_in_password))
    command = ['powershell.exe', '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass',
               '-File', str(HERE / 'windows/nid-browser.ps1')]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        output, _ = process.communicate(request.encode('utf-8'), timeout=timeout + 20)
    except BaseException:
        # Kill only the helper process tree created above if normal timed UI
        # shutdown fails or its owning caller is interrupted.
        subprocess.run(['taskkill.exe', '/PID', str(process.pid), '/T', '/F'],
                       capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        process.communicate()
        raise RuntimeError('NID browser helper did not finish normally') from None
    finally:
        request = None
    if process.returncode or len(output) > 65536:
        raise RuntimeError('NID browser helper failed')
    try:
        result = json.loads(output.decode('utf-8-sig'))
        if not isinstance(result, dict) or not isinstance(result.get('status'), str): raise ValueError
    except (ValueError, UnicodeError):
        raise RuntimeError('Invalid NID browser helper response') from None
    return result


def capture_nid_credential(plan, *, expected_game_code, data_directory, timeout=300, expected_email='', sign_in_password=''):
    """Open official sign-in UI; the user completes login/verification there.

    The parent validates the captured route and email result, then returns a
    redacted provider credential. No token files, OS scheme handler or SDK HTTP.
    This is route/origin handling, not proof of server token validity.
    """
    if not isinstance(plan, NidWebUrl): raise TypeError('Expected a prepared NID URL')
    try:
        parts = urlsplit(plan.url)
        params = parse_qs(parts.query, keep_blank_values=True, strict_parsing=True)
        if (len(plan.url) > 131072 or parts.scheme != 'https' or parts.netloc != 'members.netmarble.com'
                or parts.path != '/auth' or parts.fragment or params.get('gameCode') != [expected_game_code]
                or params.get('webViewType') != ['sdk'] or params.get('authType') != ['signin']):
            raise ValueError
    except ValueError:
        raise ValueError('NID browser requires the expected SDK sign-in context') from None
    result = _run(url=plan.url, game_code=expected_game_code, timeout=timeout,
                  data_directory=data_directory, smoke=False, account_hint=expected_email,
                  sign_in_password=sign_in_password)
    if result['status'] != 'callback':
        raise RuntimeError('NID browser did not return a sign-in result')
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
    return dict(synthetic_only=True, callback_captured=True, blocked_external=result['blocked_external'],
                blocked_popups=result['blocked_popups'], game_started=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--smoke', action='store_true', required=True)
    parser.parse_args()
    print(json.dumps(smoke()))
