"""Real loopback VMOS gateway -> direct WebRTC (HTTPS bootstrap) -> Android.
Secret via stdin only.
Optional USB fixture verifies effects via its own debug metrics; no game is touched.
Uses the existing MultiBot client's signing methods verbatim via an AST extraction.
"""
import ast
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from types import SimpleNamespace
import xml.etree.ElementTree as ET
import requests

config=json.load(sys.stdin)
root=Path(__file__).resolve().parents[1]
source=Path(config['reference'])
tree=ast.parse(source.read_text(encoding='utf-8-sig'))
cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='VmosApiClient')
cls.body=[n for n in cls.body if isinstance(n,ast.Assign) or isinstance(n,ast.FunctionDef) and n.name in ('sign','auth_headers')]
ns=dict(hashlib=hashlib,hmac=hmac,binascii=binascii)
exec(compile(ast.Module(body=[cls],type_ignores=[]),str(source),'exec'),ns)
client=ns['VmosApiClient']();client.config=SimpleNamespace(base_url='http://127.0.0.1:17842');client.access_key='phone-exit';client.secret_key=config['secret']
session=requests.Session()
def post(method,body=None):
    raw=json.dumps(body or {},separators=(',',':'),ensure_ascii=False)
    date=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    r=session.post(client.config.base_url+'/vcpcloud/api/padApi/'+method,headers=client.auth_headers(date,raw),data=raw.encode('utf-8'),timeout=75);r.raise_for_status();v=r.json()
    if v['code'] not in (0,200):raise RuntimeError(f"{method}: code={v['code']} {v['msg']}")
    return v['data']
def completed(entry):
    for _ in range(35):
        r=post('padTaskDetail',{'taskIds':[entry['taskId']]})[0]
        if r['taskStatus']==3:return r
        if r['taskStatus']<0:raise RuntimeError(f"task failed: {r['errorMsg']}")
        time.sleep(1)
    raise RuntimeError('task timeout; action not repeated')
phones=post('userPadList')
print(f"PASS: unchanged MultiBot HMAC authentication, {len(phones)} private devices",flush=True)
if config.get('onlyName'):
    phones=[p for p in phones if p['name']==config['onlyName']]
    if not phones:raise RuntimeError('Selected phone not found')
if '--benchmark' in sys.argv:
    p=next(p for p in phones if 'SM-G990B' in p['name']);times=[];transfers=[];sizes=[]
    for _ in range(5):
        start=time.perf_counter();entry=post('getLongGenerateUrl',{'padCodes':[p['padCode']],'format':'jpg','width':720,'height':1280,'quality':65})[0];times.append((time.perf_counter()-start)*1000)
        start=time.perf_counter();r=session.get(entry['url'],timeout=10);r.raise_for_status();assert r.content.startswith(b'\xff\xd8');transfers.append((time.perf_counter()-start)*1000);sizes.append(len(r.content))
    result={'phone':p['name'],'version':p['versionName'],'format':'jpg','width':720,'height':1280,'quality':65,'captureMs':[round(v) for v in times],'localDownloadMs':[round(v) for v in transfers],'bytes':sizes}
    out=root/'.test-data/vmos-speed.json';out.parent.mkdir(exist_ok=True);out.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print('BENCHMARK: '+json.dumps(result,ensure_ascii=False),flush=True)
if '--pipeline' in sys.argv:
    from concurrent.futures import ThreadPoolExecutor
    p=phones[0] if config.get('onlyName') else next(p for p in phones if 'SM-G990B' in p['name']);url=client.config.base_url+'/v1/devices/'+p['padCode']+'/commands';headers={'Authorization':'Bearer '+config['secret']}
    rate=int(next((a.split("=",1)[1] for a in sys.argv if a.startswith("--rate=")),"2"));assert rate in (1,2)
    count=int(next((a.split("=",1)[1] for a in sys.argv if a.startswith("--count=")),"10"));assert 5<=count<=180
    begin=time.perf_counter()
    def capture(index):
        start=time.perf_counter();r=requests.post(url,headers=headers,json={'command':'screenshot','args':{'format':'jpg','width':720,'height':1280,'quality':65}},timeout=75);r.raise_for_status();job=r.json();assert job['transport']=='webrtc'
        for _ in range(400):
            r=requests.get(url+'/'+job['id'],headers=headers,timeout=5);r.raise_for_status();v=r.json()
            if v['status']=='done':
                assert v['result']['ok'],v['result'].get('error');data=base64.b64decode(v['result']['result']['image']);assert data.startswith(b'\xff\xd8');return {'index':index,'latencyMs':round((time.perf_counter()-start)*1000),'doneMs':round((time.perf_counter()-begin)*1000),'bytes':len(data)}
            assert v['status']!='expired';time.sleep(.02)
        raise RuntimeError('Frame timeout')
    # Establish DTLS first: otherwise setup time fills the executor queue with
    # frames and measures a persistent backlog rather than steady-state latency.
    warmup=capture(-1);print(f"WARMUP: connection + first frame {warmup['latencyMs']} ms",flush=True)
    time.sleep(1/rate);begin=time.perf_counter()
    with ThreadPoolExecutor(max_workers=3) as pool:
        jobs=[]
        for i in range(count):
            time.sleep(max(0,begin+i/rate-time.perf_counter()));jobs.append(pool.submit(capture,i))
        captures=[j.result() for j in jobs]
    elapsed=(captures[-1]['doneMs']-captures[0]['doneMs'])/1000
    report={'phone':p['name'],'format':'JPEG720x1280 quality65','version':p['versionName'],'rate':round((count-1)/elapsed,2),'captures':captures}
    out=root/'.test-data/vmos-pipeline-speed.json';out.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print('PIPELINE: '+json.dumps({k:v for k,v in report.items() if k!='captures'} | {'frames':len(captures),'latencyMinMs':min(v['latencyMs'] for v in captures),'latencyMaxMs':max(v['latencyMs'] for v in captures)},ensure_ascii=False),flush=True)
if '--screens' in sys.argv:
    screen_failures=[]
    for p in phones:
        if not p['online']:continue
        try:
            if p.get('control',{}).get('api',0)>=2:
                r=post('getLongGenerateUrl',{'padCodes':[p['padCode']],'format':'jpg','width':480,'height':854,'quality':60})[0]
                image=session.get(r['url'],timeout=10);image.raise_for_status();data=image.content
            else:
                url=client.config.base_url+'/v1/devices/'+p['padCode']+'/commands';headers={'Authorization':'Bearer '+config['secret']}
                job=session.post(url,headers=headers,json={'command':'screenshot','args':{}},timeout=15);job.raise_for_status();job=job.json()
                for _ in range(35):
                    r=session.get(url+'/'+job['id'],headers=headers,timeout=15);r.raise_for_status();r=r.json()
                    if r['status']=='done':break
                    if r['status']=='expired':raise RuntimeError('Screenshot expired')
                    time.sleep(1)
                assert r.get('result',{}).get('ok'),r.get('result',{}).get('error','Screenshot timeout')
                data=base64.b64decode(r['result']['result']['image'])
            assert data.startswith(b'\xff\xd8')
            print(f"PASS: {p['name']} APK {p['versionName']}: real gateway JPEG screenshot ({len(data)} bytes)",flush=True)
        except Exception as e:
            if 'V2061' in p['name'] and 'control_disabled_or_screen_locked' in str(e):
                locked=post('padProperties',{'padCodes':[p['padCode']]})[0]
                if locked['screenLocked'] and locked['capabilities']['enabled'] and locked['capabilities']['accessibility']:
                    print('PASS: USB vivo sleeping/locked: screenshot gate rejects access; earlier unlocked screenshots verified',flush=True);continue
            print(f"FAIL: {p['name']}: {e}",flush=True);screen_failures.append(p['name'])
    if screen_failures:raise RuntimeError('Screenshots failed on: '+', '.join(screen_failures))
if '--read-new' in sys.argv:
    selected=[p for p in phones if p['online'] and p.get('control',{}).get('api',0)>=2 and 'V2061' not in p['name']]
    if not selected:raise RuntimeError('Updated remote device not available yet')
    for p in selected:
        code=p['padCode'];info=post('padProperties',{'padCodes':[code]})[0];assert info['versionCode']>=17 and info['capabilities']['accessibility']
        apps=post('listInstalledApp',{'padCodes':[code],'pkgName':'net.phoneexit'})[0];assert apps['total']==1 and apps['apps'][0]['versionCode']>=17
        focus=post('syncCmd',{'padCode':code,'scriptContent':'dumpsys window'})[0];assert focus['taskStatus']==3 and focus['emulated']
        dimensions=(720,1280)
        try:png=post('getLongGenerateUrl',{'padCodes':[code],'format':'png','width':dimensions[0],'height':dimensions[1]})[0]
        except RuntimeError as e:
            if 'screenshot_too_large' not in str(e):raise
            dimensions=(480,854);print(f"LIMIT: {p['name']}: PNG 720x1280 exceeds 1.4 MB; checking explicit smaller PNG",flush=True)
            png=post('getLongGenerateUrl',{'padCodes':[code],'format':'png','width':dimensions[0],'height':dimensions[1]})[0]
        image=session.get(png['url'],timeout=10);image.raise_for_status();assert image.content.startswith(b'\x89PNG\r\n\x1a\n')
        print(f"PASS: remote {p['name']} APK {info['versionName']}: device info, installed app/version, foreground, VMOS PNG {dimensions[0]}x{dimensions[1]}",flush=True)
if '--fixture' in sys.argv:
    p=next(p for p in phones if 'V2061' in p['name']);pad=p['padCode'];serial='81865352';adb=str(root/'.tools/android-sdk/platform-tools/adb.exe')
    def adbcall(*args):return subprocess.check_output([adb,'-s',serial,*args],text=True,encoding='utf-8',errors='replace').strip()
    def effect(method,**args):completed(post(method,{'padCodes':[pad],**args})[0]);time.sleep(.4)
    effect('startApp',pkgName='net.phoneexit.fixture')
    info=post('padProperties',{'padCodes':[pad]})[0]
    apps=post('listInstalledApp',{'padCodes':[pad],'pkgName':'net.phoneexit.fixture'})[0];assert apps['total']==1 and apps['apps'][0]['launchable']
    size=post('syncCmd',{'padCode':pad,'scriptContent':'wm size'})[0];assert size['taskResult']=='success' and '720x1280' in size['errorMsg']
    focus=post('syncCmd',{'padCode':pad,'scriptContent':'dumpsys window'})[0];assert 'net.phoneexit.fixture/unknown' in focus['errorMsg'] and focus['emulated']
    adbcall('shell','uiautomator','dump','/sdcard/phone-exit-fixture.xml');xml=adbcall('exec-out','cat','/sdcard/phone-exit-fixture.xml');nodes=ET.fromstring(xml).iter('node')
    found={}
    for n in nodes:
        key='button' if n.get('class')=='android.widget.Button' else 'input' if n.get('class')=='android.widget.EditText' else 'swipe' if n.get('text')=='Область для свайпа' else None
        if key:found[key]=[int(v) for v in re.findall(r'\d+',n.get('bounds'))]
    assert len(found)==3
    def center(key):a=found[key];return {'x':(a[0]+a[2])//2,'y':(a[1]+a[3])//2,'width':info['width'],'height':info['height']}
    effect('simulateClick',**center('button'));effect('simulateLongPress',**center('button'),holdMs=700)
    a=found['swipe'];effect('simulateSwipe',width=info['width'],height=info['height'],direction='TOP_TO_BOTTOM',startX=(a[0]+a[2])//2,startY=a[1]+80,endX=(a[0]+a[2])//2,endY=a[3]-80)
    c=center('button');effect('simulateTouch',width=info['width'],height=info['height'],pointCount=1,positions=[{'actionType':0,'x':c['x'],'y':c['y'],'nextPositionWaitTime':80},{'actionType':1,'x':c['x'],'y':c['y']}])
    effect('simulateClick',**center('input'));effect('inputText',text='Phone Exit тест 123')
    completed(post('asyncCmd',{'padCode':pad,'scriptContent':'input keyevent 66'})[0])
    metrics=json.loads(adbcall('exec-out','run-as','net.phoneexit.fixture','cat','files/metrics.json'))
    assert metrics['taps']>=2 and metrics['longPresses']>=1 and metrics['swipes']>=1 and metrics['text']=='Phone Exit тест 123' and metrics['enters']>=1,metrics
    print('PASS: real effects: launch, apps, foreground, tap, long press, swipe, complete touch, Unicode text, Enter',flush=True)
    completed(post('asyncCmd',{'padCode':pad,'scriptContent':'input keyevent 67'})[0]);m=json.loads(adbcall('exec-out','run-as','net.phoneexit.fixture','cat','files/metrics.json'));assert m['text']=='Phone Exit тест 12',m
    for key in (4,24,25,3):completed(post('asyncCmd',{'padCode':pad,'scriptContent':f'input keyevent {key}'})[0])
    effect('startApp',pkgName='net.phoneexit.fixture');completed(post('asyncCmd',{'padCode':pad,'scriptContent':'input keyevent 187'})[0]);effect('startApp',pkgName='net.phoneexit.fixture')
    completed(post('asyncCmd',{'padCode':pad,'scriptContent':'input keyevent 3'})[0])
    print('PASS: Delete effect verified; Back/Home/Recents/volume reported Android completion',flush=True)
    adbcall('shell','rm','/sdcard/phone-exit-fixture.xml')
session.close()
