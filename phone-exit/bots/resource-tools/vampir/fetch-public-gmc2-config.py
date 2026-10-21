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
from vampir_core.gmc2_http import fetch, NoRedirect, MAX_BODY


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
