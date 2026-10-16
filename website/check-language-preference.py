"""HTTP checks: language negotiation, remembered choice and stable crawler URLs."""
import sys
import urllib.request
import urllib.error

BASE = 'https://vampir.top' if '--production' in sys.argv else 'http://127.0.0.1:8787'
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None
opener = urllib.request.build_opener(NoRedirect)

def check(path, language, expected, cookie='', agent='Mozilla/5.0 TestBrowser', accept='text/html'):
    request = urllib.request.Request(BASE + path, headers={
        'Accept-Language': language, 'User-Agent': agent, 'Accept': accept, 'Cookie': cookie,
    })
    try: response = opener.open(request)
    except urllib.error.HTTPError as error: response = error
    with response:
        if expected:
            assert response.status == 302, (path, language, response.status)
            assert response.headers['Location'] == expected
            assert 'no-store' in response.headers['Cache-Control']
            assert 'Cookie' in response.headers['Vary']
        else:
            assert response.status == 200, (path, language, response.status)
            assert 'Location' not in response.headers

check('/', 'uk-UA,ru;q=0.8,en;q=0.5', '/ua/')
check('/', 'de-DE,de;q=0.9', '/de/')
check('/', 'fr;q=0.5,pl;q=0.9', '/pl/')
check('/', 'sr-Latn-RS,sr;q=0.8', '/sr-latn/')
check('/', 'ja-JP,de;q=0.7', '/de/')
check('/', 'fr;q=0,en;q=0.5', None)
check('/', 'ja-JP,*;q=0.5', None)
check('/', 'ru', None, 'vampir_language=en')
check('/', 'uk', '/de/', 'vampir_language=de')
check('/', 'ru', '/ru/', 'vampir_language=invalid')
check('/?utm_source=test', 'ru', '/ru/?utm_source=test')
check('/fr/', 'ru', None, 'vampir_language=de')
for agent in ['Googlebot', 'Mozilla/5.0 (compatible; Googlebot/2.1)', 'Mozilla/5.0 bingbot', 'Mozilla/5.0 YandexBot', 'Mozilla/5.0 Applebot', 'Mozilla/5.0 facebookexternalhit', 'curl/8.0']:
    check('/', 'ru', None, 'vampir_language=de', agent)
check('/', 'ru', None, accept='application/json')
print('Language preference: browser negotiation, cookie override, explicit paths, bots and cache headers OK')
