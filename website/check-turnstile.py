"""Reject forged order requests without creating orders or sending email."""
import http.cookiejar
import json
import pathlib
import re
import sys
import urllib.error
import urllib.request

production = '--production' in sys.argv
base = 'https://vampir.top' if production else 'http://127.0.0.1:8787'
root = pathlib.Path(__file__).resolve().parent
before = set((root / 'var/orders').glob('*.json'))
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
with client.open(base + '/') as response:
    html = response.read().decode()
csrf = re.search(r'<meta name="csrf-token" content="([^"]+)"', html).group(1)
assert 'id="order-turnstile"' in html
assert 'data-sitekey="0x4AAAAAAFY1pvcWcGmKXFv3"' in html
payload = dict(amount=1000, consent='on', region='GLOBAL', server='TECHNICAL BLOCKED REQUEST',
    contact='technical_test_only', currency='USD', payment_currency='USDT', language='en')
for token in [None, '', [], 'x' * 2049, 'XXXX.DUMMY.TOKEN.XXXX']:
    body = dict(payload)
    if token is not None: body['cf-turnstile-response'] = token
    request = urllib.request.Request(base + '/api/order.php', data=json.dumps(body).encode(), headers={
        'Content-Type': 'application/json', 'X-CSRF-Token': csrf,
    })
    try: client.open(request)
    except urllib.error.HTTPError as error:
        assert error.code == 403, error.code
        assert json.loads(error.read()) == {'error': 'turnstile_failed'}
    else: raise AssertionError('Unverified order accepted')
if not production: assert before == set((root / 'var/orders').glob('*.json'))
for path in ['/turnstile.local.php', '/turnstile.php']:
    try: client.open(base + path)
    except urllib.error.HTTPError as error: assert error.code in [403, 404]
    else: raise AssertionError('Private backend file is publicly accessible')
print('Turnstile HTTP gate: missing, empty, wrong type, oversized and forged tokens rejected; private config inaccessible')
