"""Read-only HTTP checks for language routes and search metadata."""
import json
import pathlib
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from html.parser import HTMLParser

ROOT = pathlib.Path(__file__).resolve().parent
BASE = 'http://127.0.0.1:8787'
class Page(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.tags = []
        self.feed(html)
    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

registry = json.loads((ROOT / 'dist/locales/languages.json').read_text(encoding='utf-8'))
for entry in registry['languages']:
    if not entry['enabled']: continue
    code = entry['code']
    path = '/' if code == 'en' else '/' + ('ua' if code == 'uk' else code.lower()) + '/'
    with urllib.request.urlopen(BASE + path) as response:
        html = response.read().decode('utf-8')
        assert response.status == 200
        assert response.headers['Content-Language'] == code
        assert 'noindex' in response.headers['X-Robots-Tag']
    page = Page(html)
    assert next(a['lang'] for t,a in page.tags if t == 'html') == code
    canonical = [a['href'] for t,a in page.tags if t == 'link' and a.get('rel') == 'canonical']
    assert canonical == ['https://vampir.top' + path], (code, canonical)
    alternates = [a for t,a in page.tags if t == 'link' and a.get('rel') == 'alternate']
    assert len(alternates) == 51
    links = [a for t,a in page.tags if 'data-language' in a]
    assert len(links) == 50 and all(a.get('href','').startswith('/') for a in links)
    title = json.loads((ROOT / ('dist/locales/'+code+'.json')).read_text(encoding='utf-8'))['pageTitle']
    import html as html_module
    assert '<title>' + html_module.escape(title, quote=True).replace('&#x27;', '&#039;') + '</title>' in html
print('50 SSR routes, lang/title/canonical, 51 hreflang entries and crawlable links: OK')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None
opener = urllib.request.build_opener(NoRedirect)
for source, target in [('/ru','/ru/'),('/ua','/ua/'),('/uk/','/ua/'),('/en/','/'),('/index.php','/'),('/?lang=de','/de/'),('/?lang=ua','/ua/'),('/SR-Latn','/sr-latn/')]:
    try: opener.open(BASE + source)
    except urllib.error.HTTPError as error:
        assert error.code == 301 and error.headers['Location'] == target, (source, error.code)
    else: raise AssertionError('Expected redirect: '+source)
try: urllib.request.urlopen(BASE + '/not-a-language/')
except urllib.error.HTTPError as error: assert error.code == 404
else: raise AssertionError('Missing 404')
with urllib.request.urlopen(BASE + '/sitemap.xml') as response:
    tree = ET.fromstring(response.read())
    assert len(tree) == 50
with urllib.request.urlopen(BASE + '/robots.txt') as response:
    assert 'Disallow: /\n' in response.read().decode()
print('301 aliases, real 404, 50 sitemap URLs and local robots: OK')
# Verify public-host directives without changing DNS or publishing.
for path in ['/', '/robots.txt']:
    request = urllib.request.Request(BASE + path, headers={'Host': 'vampir.top'})
    with urllib.request.urlopen(request) as response:
        text = response.read().decode('utf-8')
        assert 'noindex' not in (response.headers.get('X-Robots-Tag') or '')
        if path == '/': assert 'index, follow, max-image-preview:large' in text
        else: assert 'Sitemap: https://vampir.top/sitemap.xml' in text
print('Production indexing directives: OK')
