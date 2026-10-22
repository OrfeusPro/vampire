"""Publish only the dedicated browser diagnostic folder; FTP credentials via stdin."""
import ftplib
import hashlib
import io
import json
from pathlib import Path
import ssl
import sys
import urllib.request

cfg = json.load(sys.stdin)
suffix = '/phone-exit-api/private/releases/'
base = cfg['base'].rstrip('/') + '/'
if base not in {'/phone-exit-api/private/releases/', '/public_html/hosting-webrtc-probe/phone-exit-api/private/releases/', '/hosting-webrtc-probe/phone-exit-api/private/releases/'}:
    raise RuntimeError('Unexpected product FTP location')
target = base[:-len(suffix)] + '/phone-exit-browser-test'
source = Path(__file__).resolve().parents[1] / 'diagnostics/browser'
marker = b'phone-exit-browser-probe-v1\n'
with ftplib.FTP_TLS(context=ssl.create_default_context(), timeout=30) as ftp:
    ftp.connect('skm351.hostsila.org', 21)
    ftp.login(cfg['user'], cfg['password'])
    ftp.prot_p()
    try:
        ftp.mkd(target)
        ftp.storbinary('STOR ' + target + '/owner.txt', io.BytesIO(marker))
    except ftplib.error_perm:
        found = io.BytesIO()
        ftp.retrbinary('RETR ' + target + '/owner.txt', found.write)
        if found.getvalue() != marker:
            raise RuntimeError('Existing directory is not this diagnostic')
    for name in ['shared.js', 'probe.js', 'index.php']:
        data = (source / name).read_bytes()
        ftp.storbinary('STOR ' + target + '/' + name + '.next', io.BytesIO(data))
        check = io.BytesIO()
        ftp.retrbinary('RETR ' + target + '/' + name + '.next', check.write)
        if hashlib.sha256(check.getvalue()).digest() != hashlib.sha256(data).digest():
            raise RuntimeError('FTPS hash mismatch')
        ftp.rename(target + '/' + name + '.next', target + '/' + name)
url = 'https://demochko.com/hosting-webrtc-probe/phone-exit-browser-test/'
for name in ['shared.js', 'probe.js']:
    with urllib.request.urlopen(url + name, timeout=20) as response:
        if response.read() != (source / name).read_bytes():
            raise RuntimeError('HTTPS source mismatch')
with urllib.request.urlopen(url, timeout=20) as response:
    if response.headers.get('Referrer-Policy') != 'no-referrer' or b'probe.js' not in response.read():
        raise RuntimeError('Page headers or script missing')
print('Dedicated browser diagnostic published and verified over FTPS/HTTPS. Existing endpoints unchanged.')
