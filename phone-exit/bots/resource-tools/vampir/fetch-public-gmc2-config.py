"""One explicit public SDK config probe; never login or acquire device identity."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import ssl
import sys
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
sys.path.insert(0, str(HERE.parents[2] / '.tools/vampir-python-runtime'))
from vampir_core.socks_route import SocksRoute
ROOT = Path('F:/PhoneExit Resources/Vampir')
PROFILE_SHA = 'ed169b12eb7f0f0ccd0a83c93aa16f4e683212eb088bce82df27a0d712456abb'
MAX_BODY = 2 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def profile(selected_profile='recovered-base'):
    if selected_profile == 'recovered-release':
        spec = importlib.util.spec_from_file_location('gmc2_release_source', HERE.parents[1] / 'vampir-headless/sdk-source-profile.py')
        loader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loader)
        return loader.load_release_profile('public_gmc2', root=ROOT)
    if selected_profile != 'recovered-base':
        raise ValueError('Select a verified SDK source profile')
    path = ROOT / 'code-clues/headless-gmc2-public-profile.json'
    payload = path.read_bytes()
    if digest(payload) != PROFILE_SHA:
        raise ValueError('Public GMC2 source profile changed')
    report = json.loads(payload)
    if digest(Path(report['source']).read_bytes()) != report['sha256']:
        raise ValueError('Public GMC2 compiled source changed')
    return report


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(request, *, route=None):
    expected = 'https://apis.netmarble.com/gc2/template-groups/netmarbles-v5/5.2.11?game=v5&country=G9&build=A&engine=unreal&market=nmp'
    if request['url'] != expected or request['method'] != 'GET' or dict(request['headers']).get('nmDeviceKey') != '':
        raise ValueError('Unsupported public GMC2 request')
    headers = dict(request['headers'])
    if any(name.lower() in ('accesstoken', 'playerid', 'authorization', 'cookie') for name in headers):
        raise ValueError('Public GMC2 probe cannot carry account credentials')
    headers.update({'User-Agent': 'PhoneExit-Vampir-Research/1', 'Accept-Encoding': 'identity'})
    if route is not None and not isinstance(route, SocksRoute): raise ValueError('Invalid explicit GMC2 route')
    opener = route.opener(NoRedirect()) if route else urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    deadline = time.monotonic() + 30
    try:
        response = opener.open(urllib.request.Request(request['url'], headers=headers), timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        if response.geturl() != request['url']:
            raise ValueError('Unexpected public GMC2 response URL')
        if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
            raise ValueError('Unsupported public GMC2 encoding')
        lengths = response.headers.get_all('Content-Length', [])
        if len(lengths) > 1 or (lengths and (not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0]) > 10)):
            raise ValueError('Invalid public GMC2 length')
        expected_size = int(lengths[0]) if lengths else None
        if expected_size is not None and expected_size > MAX_BODY:
            raise ValueError('Public GMC2 body exceeds budget')
        body = bytearray()
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError('Public GMC2 read budget exceeded')
            block = response.read1(min(65536, MAX_BODY + 1 - len(body)))
            if not block:
                break
            body.extend(block)
            if len(body) > MAX_BODY:
                raise ValueError('Public GMC2 body exceeds budget')
        if expected_size is not None and expected_size != len(body):
            raise ValueError('Incomplete public GMC2 body')
        selected = [(name, value) for name, value in response.headers.items() if name.lower() in
                    ('content-type', 'content-length', 'content-encoding', 'etag', 'deckey', 'date', 'last-modified')]
        status = response.code
    metadata = dict(status=status, headers=selected, tls_certificate_verification=True,
        redirects_followed=False, environment_proxy_used=False, account_credentials_sent=False,
        device_identity_sent=False, max_body_bytes=MAX_BODY, timeout_seconds=10, read_budget_seconds=30,
        request_header_overrides={'User-Agent': 'PhoneExit-Vampir-Research/1', 'Accept-Encoding': 'identity'},
        transport='Python urllib HTTPS, not native SDK transport replay')
    if route: metadata['socks5_loopback_port'] = route.port
    return bytes(body), metadata


def save(report, body):
    if digest(body) != report['body_sha256']:
        raise ValueError('Public GMC2 snapshot body mismatch')
    manifest = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')
    identity = digest(manifest)
    folder = ROOT / 'public-gmc2-snapshots' / identity
    folder.mkdir(parents=True, exist_ok=True)
    for name, data in (('manifest.json', manifest), ('body.bin', body)):
        path = folder / name
        try:
            with path.open('xb') as stream:
                stream.write(data)
        except FileExistsError:
            if path.read_bytes() != data:
                raise ValueError('Immutable public GMC2 snapshot differs') from None
    return folder / 'manifest.json', identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch', action='store_true', required=True)
    parser.add_argument('--socks-port', type=int)
    parser.add_argument('--profile', choices=['recovered-base', 'recovered-release'], default='recovered-base')
    args = parser.parse_args()
    source = profile(args.profile)
    body, transport = fetch(source['request'], route=SocksRoute(args.socks_port) if args.socks_port is not None else None)
    report = dict(schema_version=1, fetched_utc=datetime.now(timezone.utc).isoformat(),
        tool_sha256=digest(Path(__file__).read_bytes()), profile_sha256=source.get('profile_sha256', PROFILE_SHA),
        selected_profile=args.profile,
        profile=source['profile'], request=source['request'], transport=transport,
        body_sha256=digest(body), body_bytes=len(body), active_settings_verified=False,
        authentication_attempted=False, network_ready=False)
    manifest, identity = save(report, body)
    pointer = dict(manifest=str(manifest), sha256=identity, status=transport['status'], body_bytes=len(body),
                   deckey_present=any(name.lower() == 'deckey' for name, _ in transport['headers']), network_ready=False)
    (ROOT / 'code-clues/public-gmc2-recovery.json').write_text(json.dumps(pointer, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(pointer, indent=2))


if __name__ == '__main__':
    main()
