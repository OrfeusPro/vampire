"""Read-only multilingual seller pages and negative API tests; no mail is sent."""
import html as html_module
import http.cookiejar
import json
import pathlib
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
ROOT = pathlib.Path(__file__).resolve().parent
BASE = 'https://vampir.top' if '--production' in sys.argv else 'http://127.0.0.1:8787'
registry = json.loads((ROOT/'dist/locales/languages.json').read_text(encoding='utf-8'))
for entry in registry['languages']:
    code=entry['code']
    home='/' if code=='en' else '/'+('ua' if code=='uk' else code.lower())+'/'
    path=home+'sell/'
    with urllib.request.urlopen(BASE+path) as response:
        html=response.read().decode()
        assert response.status==200 and response.url==BASE+path
        assert response.headers['Content-Language']==code
    d=json.loads((ROOT/('dist/locales/'+code+'.json')).read_text(encoding='utf-8'))
    assert '<title>'+html_module.escape(d['sellPageTitle'],quote=True).replace('&#x27;','&#039;')+'</title>' in html
    assert 'href="https://vampir.top'+path+'"' in html
    assert html.count('rel="alternate"')==51
    assert 'name="amount" value="5000" placeholder="5 000" type="number" min="5000"' in html
    assert 'name="asking_price"' in html and 'id="order-price-total"' not in html
    assert 'id="order-turnstile"' in html and '"pageType":"sell"' in html
    assert html_module.escape(d['sellSeoIntro'],quote=True).replace('&#x27;','&#039;') in html
    with urllib.request.urlopen(BASE+home) as response: main=response.read().decode()
    assert html_module.escape(d['sellHomeQuestion'],quote=True).replace('&#x27;','&#039;') in main
    assert 'class="sell-faq-link" href="'+path+'"' in main
with urllib.request.urlopen(BASE+'/sitemap.xml') as response:
    urls=[x.text for x in ET.fromstring(response.read()).iter('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')]
    assert len(urls)==100 and len(set(urls))==100 and sum(u.endswith('/sell/') for u in urls)==50
client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
with client.open(BASE+'/sell/') as response: html=response.read().decode()
csrf=re.search(r'<meta name="csrf-token" content="([^"]+)"',html).group(1)
payload=dict(kind='sell',amount=5000,consent='on',region='SEA',server='TEST BLOCKED OFFER',contact='test_only',currency='USD',payment_currency='USDT',language='en')
for change,expected in [({'amount':4999},422),({'asking_price':'-1'},422),({'asking_price':'nan'},422),({'asking_price':[]},422),({'asking_price':'1000001'},422),({'kind':'other'},422),({'asking_price':''},403),({'asking_price':'39.50'},403)]:
    request=urllib.request.Request(BASE+'/api/order.php',data=json.dumps(payload|change).encode(),headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
    try: client.open(request)
    except urllib.error.HTTPError as error:
        assert error.code==expected,(change,error.code)
        if expected==403: assert json.loads(error.read())['error']=='turnstile_failed'
    else: raise AssertionError('Unverified offer accepted')
print('50 seller pages, SEO, FAQ links, 100 sitemap URLs, minimum/price validation and Turnstile gate: OK')
