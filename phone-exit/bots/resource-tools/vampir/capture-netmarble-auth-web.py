"""Capture public NID auth HTML and its declared module script, without login."""
import argparse
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import ssl
import sys
import time
import urllib.request
from urllib.parse import urljoin, urlsplit

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
SDK_SNAPSHOT = 'b18141355f468fda8e654da37927f9323bf59ee5018f1fd00b1326eed6aae1f1'
sys.path.insert(0, str(HERE.parent.parent / 'vampir-shared'))
from vampir_core.gmc2_response import decode_gmc2_configuration


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []
    def handle_starttag(self, tag, attributes):
        values = dict(attributes)
        if tag == 'script' and values.get('type') == 'module' and values.get('src'):
            self.urls.append(values['src'])


def module_url(html, base):
    parser = Scripts()
    parser.feed(html.decode('utf-8', 'strict'))
    if len(parser.urls) != 1:
        raise ValueError('Expected exactly one public auth module script')
    url = urljoin(base, parser.urls[0])
    checked_url(url)
    return url


def checked_url(url):
    parts = urlsplit(url)
    if (parts.scheme != 'https' or parts.netloc != 'members.netmarble.com' or parts.query or parts.fragment
            or not (parts.path == '/auth' or (parts.path.startswith('/assets/') and parts.path.endswith('.js')))
            or '..' in parts.path or '%' in parts.path or '\\' in parts.path):
        raise ValueError('Auth capture URL outside explicit public scope')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(url, limit):
    checked_url(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    deadline = time.monotonic() + 30
    request = urllib.request.Request(url, headers={'User-Agent': 'PhoneExit-Vampir-Research/1', 'Accept-Encoding': 'identity'})
    with opener.open(request, timeout=10) as response:
        if response.status != 200 or response.geturl() != url or response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
            raise ValueError('Unexpected public auth asset response')
        body = bytearray()
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError('Public auth read budget exceeded')
            block = response.read1(min(65536, limit + 1 - len(body)))
            if not block:
                break
            body.extend(block)
            if len(body) > limit:
                raise ValueError('Public auth asset exceeds byte budget')
        lengths = response.headers.get_all('Content-Length', [])
        if len(lengths) > 1 or (lengths and (not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0]) > 10 or int(lengths[0]) != len(body))):
            raise ValueError('Invalid public auth content length')
        headers = [(k, v) for k, v in response.headers.items() if k.lower() in ('content-type', 'content-length', 'etag', 'last-modified', 'date')]
    return bytes(body), dict(url=url, status=200, headers=headers, sha256=digest(body), size=len(body), limit=limit)


def source_url():
    folder = ROOT / 'public-gmc2-snapshots' / SDK_SNAPSHOT
    manifest = (folder / 'manifest.json').read_bytes()
    if digest(manifest) != SDK_SNAPSHOT:
        raise ValueError('SDK source manifest changed')
    report = json.loads(manifest)
    body = (folder / 'body.bin').read_bytes()
    if digest(body) != report['body_sha256']:
        raise ValueError('SDK source body changed')
    configuration = decode_gmc2_configuration(body, report['transport']['headers'])
    url = configuration.constants.get('authWebViewUrl')
    if url != 'https://members.netmarble.com/auth':
        raise ValueError('Unsupported source authWebViewUrl')
    return url


def save(report, files):
    if set(files) != {'auth.html', 'auth.js'}:
        raise ValueError('Unsupported auth capture output files')
    for name, body in files.items():
        record = report['files'][name]
        if record['sha256'] != digest(body) or record['size'] != len(body):
            raise ValueError('Auth capture file metadata mismatch')
    payload = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')
    identity = digest(payload)
    folder = ROOT / 'auth-web-snapshots' / identity
    folder.mkdir(parents=True, exist_ok=True)
    for name, body in {**files, 'manifest.json': payload}.items():
        path = folder / name
        try:
            with path.open('xb') as stream:
                stream.write(body)
        except FileExistsError:
            if path.read_bytes() != body:
                raise ValueError('Immutable auth web snapshot differs') from None
    return folder / 'manifest.json', identity


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch', action='store_true', required=True)
    parser.parse_args()
    base = source_url()
    html, html_record = fetch(base, 2 * 1024 * 1024)
    js_url = module_url(html, base)
    script, script_record = fetch(js_url, 4 * 1024 * 1024)
    report = dict(schema_version=1, captured_utc=datetime.now(timezone.utc).isoformat(),
        tool_sha256=digest(Path(__file__).read_bytes()), sdk_snapshot_sha256=SDK_SNAPSHOT,
        files={'auth.html': html_record, 'auth.js': script_record},
        tls_certificate_verification=True, redirects_followed=False, environment_proxy_used=False,
        cookies_used=False, javascript_executed=False, account_authentication_attempted=False,
        request_count=2, network_ready=False)
    manifest, identity = save(report, {'auth.html': html, 'auth.js': script})
    pointer = dict(manifest=str(manifest), sha256=identity, html_bytes=len(html), script_bytes=len(script),
                   account_authentication_attempted=False)
    (ROOT / 'code-clues/nid-auth-web-capture.json').write_text(json.dumps(pointer, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(pointer, indent=2))
