"""Replay reviewed public web result/dispatch helpers, with explicit state shims."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('nid_result_source', HERE / 'inspect-nid-auth-web.py')
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)

RUNNER = r'''
const fs=require('node:fs'),vm=require('node:vm');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
(async()=>{
 const outputs=[];
 const credential={status:0,access_token:'access-fixture +&',easy_login_token:'easy-fixture',issue_type:'fixture',user_key:'user-fixture',refresh_token:'refresh-fixture'};
 for(const canKeep of [false,true]) for(const remember of [false,true]){
  const events=[],context=vm.createContext({URLSearchParams,i:canKeep,L:remember,
   e:{gameCode:'thered'},bie:{email:'mailUserKey'},d:()=>events.push({kind:'reset'}),
   n:(url,type)=>events.push({kind:'dispatch',url,type})});
  vm.runInContext('const _B=('+input.query+');const route=('+input.route+');const t=route;const A=('+input.result+');const W=('+input.projection+');',context,{timeout:100});
  context.credential=credential;
  await vm.runInContext('W(credential,"email",{joinedCountryCode:"UA"})',context,{timeout:100});
  outputs.push({can_keep:canKeep,remember,events});
 }
 const dispatch=[];
 for(const authType of ['signin','guestLinkIDP','gameLauncherLinkIDP','activate']) for(const allowed of [false,true]){
  const events=[],context=vm.createContext({r:authType,
   F:async()=>{events.push('profile');return allowed?{joinedCountryCode:'UA'}:null},
   U:async()=>events.push('guest-link'),z:async()=>events.push('launcher-link'),
   T:()=>events.push('activate-complete'),W:()=>events.push('result'),
   O:()=>events.push('close'),setTimeout:(_,ms)=>events.push('timer:'+ms)});
  const fn=vm.runInContext('('+input.dispatch+')',context,{timeout:100});
  await fn(credential,'email','fixture@example.invalid');
  dispatch.push({auth_type:authType,profile_allowed:allowed,events});
 }
 process.stdout.write(JSON.stringify({node_version:process.version,outputs,dispatch}));
})().catch(()=>{process.stderr.write('Reviewed result replay failed');process.exitCode=1});
'''


def build():
    folder = source.ROOT / 'auth-web-snapshots' / source.SNAPSHOT
    manifest = (folder / 'manifest.json').read_bytes()
    if source.digest(manifest) != source.SNAPSHOT:
        raise ValueError('Auth result manifest changed')
    meta = json.loads(manifest)
    raw = (folder / 'auth.js').read_bytes()
    if source.digest(raw) != meta['files']['auth.js']['sha256']:
        raise ValueError('Auth result script changed')
    script = raw.decode('utf-8')
    records = {}

    def extract(name, begin, end, skip):
        if script.count(begin) != 1:
            raise ValueError('Result helper start missing or ambiguous')
        start = script.index(begin) + skip
        finish = script.index(end, start)
        value = script[start:finish]
        if len(value) > 8192:
            raise ValueError('Result helper exceeds reviewed budget')
        data = value.encode('utf-8')
        records[name] = dict(byte_offset=len(script[:start].encode('utf-8')), bytes=data.hex(),
                             sha256=source.digest(data))
        return value

    query = extract('query', '_B=e=>{const t=Object.keys(e)', ',TB="email"', len('_B='))
    route = extract('route', 'r=({executionType:t,isConnected:r=!1,from:i,qs:a={}})=>', ';return{sendDeepLink:r', 2)
    result = extract('result', 'doneSignInDeepLink:({idpType:e,...n})=>', ',doFinishSignInDeepLink:', len('doneSignInDeepLink:'))
    projection = extract('projection', 'W=async(e,t,n)=>{const r=(null==e?void 0:e.status)', ';return{doSignInByGuest:', 2)
    dispatch = extract('dispatch', 'B=async(e,t,n="")=>{switch(r)', ',U=async({credential:', 2)
    extract('profile_gate', 'F=async(e,t,n="")=>{let r=null;', ',B=async(e,t,n="")', 2)
    extract('profile_fetch', 'Cie=()=>{const{withProcess:e}=k8();', ',Sie=()=>', len('Cie='))
    extract('profile_processing', 'N=async e=>{try{if(!e)throw new Error("credential is null")', ',M=async e=>{var t;', 2)
    completed = subprocess.run(['node', '-e', RUNNER], input=json.dumps(dict(query=query, route=route,
        result=result, projection=projection, dispatch=dispatch)), capture_output=True,
        text=True, encoding='utf-8', timeout=15, check=True)
    return dict(schema_version=1, tool_sha256=source.digest(Path(__file__).read_bytes()),
        snapshot_sha256=source.SNAPSHOT, script_sha256=source.digest(raw), functions=records,
        replay=json.loads(completed.stdout), native_execution=False, account_authentication_attempted=False,
        network_ready=False, limitations=[
            'Only reviewed query/result/route/projection/dispatch JS executes; synthetic credentials and state.',
            'Profile gate/fetch/processing recorded statically; network, policy checks and native SDK not executed.',
            'Email success result carries accessToken; this does not prove an authorization-code exchange.',
            'Active game provider/context and native result acceptance remain unproven.'])


if __name__ == '__main__':
    report = build()
    path = source.ROOT / 'code-clues/nid-auth-result-evidence.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=source.digest(path.read_bytes()),
        projection_cases=len(report['replay']['outputs']), dispatch_cases=len(report['replay']['dispatch'])), indent=2))
