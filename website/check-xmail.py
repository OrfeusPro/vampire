"""Exercise real HTTP auth and mailbox reads. Never prints credentials or mail contents."""
import concurrent.futures
import http.cookiejar
import json
import pathlib
import re
import sys
import urllib.request
import urllib.error
root=pathlib.Path(__file__).resolve().parent
base='https://vampir.top' if '--production' in sys.argv else 'http://127.0.0.1:8787'
client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def page():
    with client.open(base+'/xmail/') as response:
        html=response.read().decode();assert response.status==200
        assert 'noindex' in response.headers['X-Robots-Tag']
        assert 'no-store' in response.headers['Cache-Control']
        assert "frame-ancestors 'none'" in response.headers['Content-Security-Policy']
        return html,re.search(r'<meta name="csrf-token" content="([^"]+)"',html).group(1)
def api(data,csrf,expected=200):
    request=urllib.request.Request(base+'/xmail/api',data=json.dumps(data).encode(),headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
    try: response=client.open(request,timeout=55)
    except urllib.error.HTTPError as error:response=error
    with response:
        assert response.status==expected,(data['action'],response.status)
        return json.loads(response.read())
html,csrf=page();assert 'id="login-form"' in html and '@vampir.top' not in html
assert api({'action':'accounts'},csrf,401)['error']=='auth_required'
assert api({'action':'login','username':'admin','password':'incorrect'},csrf,401)['error']=='invalid_login'
assert api({'action':'accounts'},'invalid',403)['error']=='csrf'
access=(root/'var/xmail-access.txt').read_text(encoding='utf-8');password=re.search(r'^Password: (.+)$',access,re.M).group(1)
assert api({'action':'login','username':'admin','password':password},csrf)['ok']
html,csrf=page();assert 'id="accounts"' in html
accounts=api({'action':'accounts'},csrf)['accounts'];assert len(accounts)==17
assert all(set(account)=={'id','email'} for account in accounts)
def read_account(account):
    folders=api({'action':'folders','account':account['id']},csrf)['folders'];assert folders
    inbox=next((f for f in folders if f['name'].upper()=='INBOX'),folders[0])
    listing=api({'action':'messages','account':account['id'],'folder':inbox['id'],'page':0},csrf)
    assert isinstance(listing['messages'],list)
    if listing['messages']:
        m=listing['messages'][0]
        message=api({'action':'message','account':account['id'],'folder':inbox['id'],'uid':m['uid'],'validity':m['validity']},csrf)
        assert isinstance(message['text'],str) and 'attachments' in message
    return account['id']
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
    results=list(pool.map(read_account,accounts))
assert len(results)==17
assert api({'action':'logout'},csrf)['ok']
_,csrf=page();assert api({'action':'accounts'},csrf,401)['error']=='auth_required'
print('XMail: private login, CSRF, no-store/noindex, all 17 IMAP accounts/headers/message reads, logout OK; no mail contents logged')
