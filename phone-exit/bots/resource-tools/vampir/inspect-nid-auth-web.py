"""Inspect saved NID script and replay only its reviewed RSA padding helper."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path('F:/PhoneExit Resources/Vampir')
SNAPSHOT = '63254de0c08cdcf7415500b1a975d39062166272d6ce674ea25fb58ef27bb01c'
NODE_RUNNER = r'''
const fs=require('node:fs'),vm=require('node:vm');
const request=JSON.parse(fs.readFileSync(0,'utf8'));
let counter=17;
class N7{nextBytes(a){a[0]=(counter++%255)+1}}
class u7{constructor(a){this.bytes=Array.from(a,x=>x&255)}}
const context=vm.createContext({N7,u7});
const fn=vm.runInContext('('+request.function_source+')',context,{timeout:100});
const cases=request.inputs.map(text=>{const value=fn(text,128);return {text,bytes:value?value.bytes:null}});
const params={accessToken:'',clientId:'client-fixture',gameCode:'thered',buildCode:'A',playerId:'',nmDeviceKey:'nm-fixture',deviceKey:'device-fixture',deviceIp:'',clientIp:'',osType:'pc',webViewType:'sdk'};
context.oG={getState:()=>({params})};context.eK={getState:()=>({on(){},off(){}})};
context._H=vm.runInContext('('+request.url_predicate+')',context,{timeout:100});
const intercept=vm.runInContext(request.interceptor,context,{timeout:100});
const request_cases=['/signin/netmarble','/api/already','https://members.netmarble.com/auth'].map(url=>({input_url:url,params,result:intercept({url,headers:{}})}));
process.stdout.write(JSON.stringify({node_version:process.version,cases,request_cases}));
'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def build():
    folder = ROOT / 'auth-web-snapshots' / SNAPSHOT
    manifest = (folder / 'manifest.json').read_bytes()
    if digest(manifest) != SNAPSHOT:
        raise ValueError('Auth web manifest changed')
    meta = json.loads(manifest)
    payloads = {name: (folder / name).read_bytes() for name in ('auth.html', 'auth.js')}
    if any(digest(body) != meta['files'][name]['sha256'] for name, body in payloads.items()):
        raise ValueError('Auth web payload changed')
    html, script = [payloads[name].decode('utf-8') for name in ('auth.html', 'auth.js')]
    anchors = []
    for text in ('j8=t8.create({timeout:7e3})', 'j8.interceptors.request.use',
                 'e.url="/api".concat(t)', 'z7=e=>U7.encrypt(e)||""', 'tU="members_signin"',
                 'email:z7(e),password:z7(t),deviceKey:n,expectedAction:tU,reCaptchaScoreToken:r',
                 'j8.post("/signin/netmarble",i)', 'U7.setPublicKey(e)',
                 'V.getReCaptchaToken(tU)'):
        start = script.find(text)
        if start < 0 or script.find(text, start + 1) >= 0:
            raise ValueError('Auth web source anchor missing or ambiguous')
        data = text.encode('utf-8')
        anchors.append(dict(byte_offset=len(script[:start].encode('utf-8')), bytes=data.hex(), sha256=digest(data)))
    marker = 'window.__INITIAL_ZUSTAND_STATE__ = '
    start = html.index(marker) + len(marker)
    state, consumed = json.JSONDecoder().raw_decode(html[start:])
    public_pem = state['applicationConfigStore']['RSA_PUBLIC_KEY']
    start_function = script.index('n=function(e,t){if(t<e.length+11)') + 2
    end_function = script.index('}(e,t);if(null==n)', start_function) + 1
    source = script[start_function:end_function]
    if len(source) > 1024 or not source.startswith('function(e,t){') or not source.endswith('new u7(n)}'):
        raise ValueError('RSA padding helper boundary changed')
    inputs = ['', 'user@example.invalid', 'pw-fixture', 'p ä €', 'пароль', '🔒', 'a' * 117, 'a' * 118, 'é' * 60]
    predicate_start = script.index('const _H=e=>new RegExp(') + len('const _H=')
    predicate_end = script.index(',TH=e=>', predicate_start)
    predicate = script[predicate_start:predicate_end]
    interceptor_start = script.index('j8.interceptors.request.use(') + len('j8.interceptors.request.use(')
    interceptor_end = script.index('}),(e=>Promise.reject(e)))', interceptor_start) + 2
    interceptor = script[interceptor_start:interceptor_end]
    if len(predicate) > 512 or len(interceptor) > 2048:
        raise ValueError('Auth interceptor source bounds changed')
    completed = subprocess.run(['node', '-e', NODE_RUNNER], input=json.dumps(dict(function_source=source, inputs=inputs,
                               url_predicate=predicate, interceptor=interceptor)),
        capture_output=True, text=True, encoding='utf-8', timeout=15, check=True)
    replay = json.loads(completed.stdout)
    return dict(schema_version=1, snapshot_sha256=SNAPSHOT, tool_sha256=digest(Path(__file__).read_bytes()),
        sources=meta['files'], anchors=anchors,
        padding_function=dict(byte_offset=len(script[:start_function].encode('utf-8')),
                              bytes=source.encode('utf-8').hex(), sha256=digest(source.encode('utf-8'))),
        request_functions=[dict(byte_offset=len(script[:start].encode('utf-8')), bytes=text.encode('utf-8').hex(),
                                sha256=digest(text.encode('utf-8'))) for start, text in
                               ((predicate_start, predicate), (interceptor_start, interceptor))],
        public_key_pem=public_pem, public_key_sha256=digest(public_pem.encode('ascii')), replay=replay,
        method='POST', relative_path='/api/signin/netmarble', expected_action='members_signin',
        javascript_scope='Reviewed padding helper/URL predicate/request interceptor only; synthetic RNG/BigInteger/state/loaders; full app not executed',
        account_authentication_attempted=False, network_ready=False)


if __name__ == '__main__':
    report = build()
    path = ROOT / 'code-clues/nid-auth-web-evidence.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=digest(path.read_bytes()), padding_cases=len(report['replay']['cases']),
                         account_authentication_attempted=False), indent=2))
