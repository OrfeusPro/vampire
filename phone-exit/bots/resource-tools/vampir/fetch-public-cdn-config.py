"""Explicit public HTTPS probe for the recovered base profile; no account login."""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import ssl
import sys
import time
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / 'vampir-shared'))
from vampir_core.cdn_config import decode_cdn_config_document, read_cdn_sdk_environment
from vampir_core.cdn_servers import select_cdn_server
from vampir_core.sdk_config import prepare_cdn_config_url_ascii, select_game_sdk_zone

ROOT = Path('F:/PhoneExit Resources/Vampir')
PROFILE_ID = '393c0697115ec6beceeb0e822bed0f6907eab83dfe9a47f81e9c7875deff35db'
PUBLIC_URL = 'https://red.gcdn.netmarble.com/red/config/window/real/1_12_14/config.json'
MAX_BODY = 2 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def profile():
    path = ROOT / 'resource-config-snapshots' / PROFILE_ID / 'manifest.json'
    if digest(path.read_bytes()) != PROFILE_ID:
        raise ValueError('Base profile manifest changed')
    report = json.loads(path.read_text('utf-8'))
    config = next(c for c in report['configs'] if c['snapshot_file'] == 'DefaultGame.ini')
    if digest((path.parent / 'DefaultGame.ini').read_bytes()) != config['payload_sha256']:
        raise ValueError('Base profile payload changed')
    values = {row['key']: row['value'] for row in config['values']}
    raw_url = prepare_cdn_config_url_ascii(normal=values['CdnConfigUrl'], qa=values['CdnConfigUrlQA'],
        prefix=values['ConfigPrefix'], app_version=values['AppVersion'], platform_code=2)
    url = 'https://' + raw_url
    if url != PUBLIC_URL or values['CdnConfig'] != 'True':
        raise ValueError('Unsupported public CDN profile')
    return dict(config_snapshot_sha256=PROFILE_ID, archive_sha256=report['archive_sha256'],
        ini_sha256=config['payload_sha256'], source_values=config['values'], raw_url=raw_url,
        url=url, https_added_by_local_policy=True, active_profile_verified=False)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(url):
    if url != PUBLIC_URL:
        raise ValueError('Only the recovered public CDN URL is supported')
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                         urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(url, headers={'User-Agent': 'Aqua/1.0', 'Accept-Encoding': 'identity'})
    deadline = time.monotonic() + 30
    with opener.open(request, timeout=10) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError('Unexpected public CDN response')
        if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
            raise ValueError('Unsupported public CDN content encoding')
        lengths = response.headers.get_all('Content-Length', [])
        if len(lengths) > 1 or (lengths and (not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0]) > 10)):
            raise ValueError('Invalid public CDN content length')
        expected = int(lengths[0]) if lengths else None
        if expected is not None and expected > MAX_BODY:
            raise ValueError('Public CDN body exceeds limit')
        body = bytearray()
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError('Public CDN read budget exceeded')
            chunk = response.read1(min(65536, MAX_BODY + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > MAX_BODY:
                raise ValueError('Public CDN body exceeds limit')
        if expected is not None and len(body) != expected:
            raise ValueError('Incomplete public CDN body')
        headers = list(response.headers.items())
    return bytes(body), dict(status=200, headers=headers, tls_certificate_verification=True,
        redirects_followed=False, proxy_environment_used=False, timeout_per_operation_seconds=10,
        read_budget_seconds=30, max_body_bytes=MAX_BODY, transport='Python urllib HTTPS; not native HTTP wire replay')


def analyze(body):
    document = decode_cdn_config_document(body)
    environment = read_cdn_sdk_environment(document)
    selection = select_cdn_server(document)
    canonical = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return dict(document_sha256=digest(canonical), environment=environment,
        sdk_mode=select_game_sdk_zone(environment), server_selection=asdict(selection),
        config_applied=False, lobby_connection_attempted=False, authentication_attempted=False)


def save(report, body):
    if report['body_sha256'] != digest(body):
        raise ValueError('Public CDN snapshot body mismatch')
    manifest = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')
    identity = digest(manifest)
    folder = ROOT / 'public-cdn-snapshots' / identity
    folder.mkdir(parents=True, exist_ok=True)
    for name, data in (('manifest.json', manifest), ('body.bin', body)):
        target = folder / name
        try:
            with target.open('xb') as stream:
                stream.write(data)
        except FileExistsError:
            if target.read_bytes() != data:
                raise ValueError('Immutable public CDN snapshot differs') from None
    return folder / 'manifest.json', identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch', action='store_true', help='Perform one public HTTPS GET; no redirects or account credentials')
    parser.add_argument('--snapshot', type=Path, help='Decode an existing snapshot offline')
    args = parser.parse_args()
    if args.fetch == bool(args.snapshot):
        parser.error('Select --fetch or --snapshot')
    if args.snapshot:
        manifest = args.snapshot.read_bytes()
        if digest(manifest) != args.snapshot.parent.name:
            raise ValueError('Public CDN manifest changed')
        report = json.loads(manifest)
        body = (args.snapshot.parent / 'body.bin').read_bytes()
        if digest(body) != report['body_sha256'] or analyze(body) != report['analysis']:
            raise ValueError('Public CDN snapshot changed')
        print(json.dumps(dict(offline_verified=True, body_bytes=len(body), environment=report['analysis']['environment'])))
        return
    provenance = profile()
    body, transport = fetch(provenance['url'])
    report = dict(schema_version=1, fetched_utc=datetime.now(timezone.utc).isoformat(),
        tool_sha256=digest(Path(__file__).read_bytes()), profile=provenance,
        transport=transport, body_sha256=digest(body), body_bytes=len(body), analysis=analyze(body),
        native_config_acceptance_verified=False, active_runtime_settings_verified=False, network_ready=False)
    manifest, identity = save(report, body)
    pointer = dict(manifest=str(manifest), sha256=identity, body_bytes=len(body),
                   environment=report['analysis']['environment'], network_ready=False)
    (ROOT / 'code-clues/public-cdn-recovery.json').write_text(json.dumps(pointer, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(pointer, indent=2))


if __name__ == '__main__':
    main()
