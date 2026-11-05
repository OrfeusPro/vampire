"""One explicit SDK entry attempt using a saved account; private DPAPI capture.

Captures SDK HTTP application payloads, not TLS records or traffic of the game
launched by the user. Passwords are passed to the existing NID helper in memory.
The public inventory retains field paths/types, never field values.
"""
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import re
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlsplit
import uuid

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.account_store import AccountStore, WindowsVault
from vampir_core.sdk_sign_in_http import execute_launcher_token, execute_launcher_sign_in, SdkSignInHttpError, _NoRedirect


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def shape(value, prefix='$', depth=0):
    """Bounded schema only. Never turn arbitrary response strings into labels."""
    if depth > 8:
        return {prefix: 'depth_limit'}
    if type(value) is dict:
        result = {prefix: 'object'}
        for key, child in list(value.items())[:128]:
            if type(key) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,79}', key):
                result.update(shape(child, prefix + '.' + key, depth + 1))
        return result
    if type(value) is list:
        result = {prefix: 'array'}
        for child in value[:8]:
            result.update(shape(child, prefix + '[]', depth + 1))
        return result
    return {prefix: {str: 'string', int: 'integer', float: 'number', bool: 'boolean', type(None): 'null'}.get(type(value), 'unknown')}


class Capture:
    def __init__(self, folder, *, protect=None, limit=4 * 1024 * 1024):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=False)
        self.protect = protect or (lambda raw: WindowsVault()._call(raw, False))
        self.limit, self.used, self.sequence = limit, 0, 0
        self.started = time.monotonic()
        self.inventory = []

    def record(self, kind, raw):
        if time.monotonic() - self.started > 600:
            raise RuntimeError('Private capture expired')
        if type(raw) is not bytes or len(raw) > 256 * 1024:
            raise ValueError('Private record exceeds budget')
        if self.used + len(raw) > self.limit:
            raise RuntimeError('Private capture limit')
        self.used += len(raw)
        for offset in range(0, max(1, len(raw)), 40000):
            record = json.dumps(dict(sequence=self.sequence, kind=kind,
                payload=base64.b64encode(raw[offset:offset + 40000]).decode('ascii')), separators=(',', ':')).encode()
            encrypted = self.protect(record)
            with (self.folder / 'sdk-http.dpapi').open('ab') as stream:
                stream.write(struct.pack('<I', len(encrypted)))
                stream.write(encrypted)
            self.sequence += 1

    def inspect(self, stage, body):
        try:
            fields = shape(json.loads(body))
        except (ValueError, RecursionError, UnicodeError):
            fields = {'$': 'non_json'}
        self.inventory.append(dict(stage=stage, fields=fields))

    def executor(self, stage, execute):
        def run(plan, *, expected_url, route=None):
            opener = route.opener(_NoRedirect()) if route else urllib.request.build_opener(
                urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl.create_default_context()), _NoRedirect())
            received = bytearray()

            def observe(response):
                self.record(stage + ':response_headers', json.dumps(dict(status=response.status,
                    headers=list(response.headers.items()))).encode())
                original = response.read1

                def read(size=-1):
                    chunk = original(size)
                    self.record(stage + ':response_body', chunk)
                    received.extend(chunk)
                    return chunk
                response.read1 = read
                return response

            def open_request(request, **kwargs):
                self.record(stage + ':request_attempt', json.dumps(dict(url=request.full_url,
                    method=request.get_method(), headers=request.header_items(),
                    body=base64.b64encode(request.data).decode('ascii'))).encode())
                self.inspect(stage + ':request', request.data)
                self.inventory.append(dict(stage=stage + ':headers',
                    fields={key: 'string' for key, _ in request.header_items()}))
                try:
                    return observe(opener.open(request, **kwargs))
                except urllib.error.HTTPError as error:
                    observe(error)
                    raise

            try:
                return execute(plan, expected_url=expected_url, route=route, _open=open_request)
            finally:
                self.inspect(stage + ':response', bytes(received))
        return run

    def finish(self, result):
        report = dict(schema=1, scope='SDK HTTP application payloads only',
            protection='Windows DPAPI CurrentUser', result=result,
            duration_seconds=round(time.monotonic() - self.started, 3),
            captured_bytes=self.used, records=self.sequence, inventory=self.inventory,
            game_session_ready=False)
        (self.folder / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        return report


def run(account, profile, *, timeout=180):
    if not re.fullmatch('[0-9a-f]{64}', profile):
        raise ValueError('Expected full SDK Launcher profile SHA')
    if type(timeout) is not int or not 1 <= timeout <= 300:
        raise ValueError('SDK diagnostic timeout must be 1..300 seconds')
    store = AccountStore(HERE / '.local/console.sqlite3')
    email, password, settings = store.credential(account)
    settings = AccountStore.assignment(settings)
    capture = Capture(HERE / '.local/verification-captures' / uuid.uuid4().hex)
    browser = load('nid-browser')

    def credential(url, **kwargs):
        names = sorted({key for key, _ in parse_qsl(urlsplit(url.url).query, keep_blank_values=True)})
        capture.inventory.append(dict(stage='nid:query', fields={key: 'string' for key in names}))
        return browser.capture_nid_credential(url, **kwargs)

    result = dict(sdk_response_accepted=False)
    try:
        runner = load('run-nid-sdk-sign-in')
        data = runner.run(email, password=password, timeout=timeout,
            selected_profile='sdk-launcher:' + profile, auth_flow='launcher',
            socks_port=settings['socks_port'], device_settings=settings['device_settings'],
            _capture=credential,
            _execute_token=capture.executor('launcher/token', execute_launcher_token),
            _execute=capture.executor('launcher/sign-in', execute_launcher_sign_in),
            _progress=lambda stage: print(json.dumps(dict(stage=stage)), flush=True))
        result = dict(sdk_response_accepted=True, player_id_present=bool(data.player_id),
            sdk_token_present=bool(data.access_token))
        data = None
    except SdkSignInHttpError as error:
        result.update(error=error.kind, http_status=error.status, sdk_error_code=error.sdk_code)
    except browser.NidBrowserStatusError as error:
        result.update(error='nid_not_completed', browser_status=error.browser_status,
            sign_in_step=error.sign_in_step, nid_http_status=error.nid_http_status,
            nid_error_code=error.nid_error_code, nid_error_hint=error.nid_error_hint)
    except (ValueError, RuntimeError, PermissionError, KeyError, OSError) as error:
        import traceback
        capture.record('local_error', traceback.format_exc().encode('utf-8'))
        result.update(error='entry_not_completed', error_type=type(error).__name__)
    finally:
        password = None
        report = capture.finish(result)
        print(json.dumps(dict(report=str(capture.folder / 'report.json'), result=report['result'],
            game_session_ready=False)), flush=True)
    return result['sdk_response_accepted']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Один SDK-вход сохранённого аккаунта с приватной диагностикой')
    parser.add_argument('--account', required=True, help='Локальный ID аккаунта, без паролей в аргументах')
    parser.add_argument('--profile', required=True, help='Полный SHA immutable SDK Launcher профиля')
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    sys.exit(0 if run(args.account, args.profile, timeout=args.timeout) else 2)
