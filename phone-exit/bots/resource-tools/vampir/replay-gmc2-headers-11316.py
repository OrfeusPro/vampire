"""Execute current GMC2 header arguments against synthetic HTTP captures only."""
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
from vampir_core.gmc2_request import plan_gmc2_get_request

START, STOP = 0x1444fbe00,0x1444fc051


def load(name,path):
    spec = importlib.util.spec_from_file_location(name,path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def replay(root=None):
    url = load('header_url_inputs',HERE/'replay-gmc2-url-11316.py')
    harness = load('header_native_harness',HERE/'native-request-harness-11316.py')
    h = harness.make_harness(url.EXPORTS,{0x1444fbbc0,0x1444c4210,0x1445320c0,*url.INITIALIZERS},root=root)
    rbp,manager,settings,cls,request,table,account_cls,account = [h.scratch+n for n in
        (0x10000,0x14000,0x15000,0x16000,0x1b000,0x1a000,0x1c000,0x1d000)]
    url_string,service,etag = [h.scratch+n for n in (0x17000,0x17100,0x17200)]
    set_url,set_header,set_method = [h.scratch+n for n in (0x3d000,0x3d010,0x3d020)]
    h.uc.mem_write(request,struct.pack('<Q',table))
    for offset,target in ((0x68,set_url),(0xb0,set_header),(0x60,set_method)):
        h.uc.mem_write(table+offset,struct.pack('<Q',target))
    h.uc.mem_write(cls+0x110,struct.pack('<Q',settings))
    h.uc.mem_write(account_cls+0x110,struct.pack('<Q',account))
    heap,values,headers,options,events = [h.scratch+0x20000],{},[],{},[]

    def put(destination,value):
        if not (h.scratch <= destination <= h.scratch+0x40000-16 or destination in url.GLOBALS):
            raise ValueError('Header string destination bound')
        data = (value+'\0').encode('utf-16le')
        if len(data)>512 or heap[0]+len(data)>=h.scratch+0x2e000:
            raise ValueError('Header string heap bound')
        pointer = heap[0] if value else 0
        if pointer:
            h.uc.mem_write(pointer,data)
            heap[0]+=(len(data)+15)&~15
        count = len(data)//2 if value else 0
        h.uc.mem_write(destination,struct.pack('<QII',pointer,count,count))

    def text(address):
        if not h.scratch <= address <= h.scratch+0x40000-16:
            raise ValueError('Header FString object bound')
        pointer,count,capacity = struct.unpack('<QII',bytes(h.uc.mem_read(address,16)))
        if not 0<=count<=capacity<=256:
            raise ValueError('Header FString count bound')
        if not count:
            return ''
        if not h.scratch <= pointer <= h.scratch+0x40000-count*2:
            raise ValueError('Header FString data bound')
        data = bytes(h.uc.mem_read(pointer,count*2))
        if data[-2:]!=bytes(2):
            raise ValueError('Header FString not terminated')
        return data[:-2].decode('utf-16le')

    def fixture(machine):
        address = machine.reg_read(h.x.UC_X86_REG_RIP)
        a,b,c = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX,h.x.UC_X86_REG_RDX,h.x.UC_X86_REG_R8)]
        result = 0
        if address in (set_url,set_header,set_method):
            if a!=request:
                raise ValueError('HTTP capture receiver differs')
            if address==set_header:
                headers.append((text(b),text(c)))
            else:
                key = 'url' if address==set_url else 'method'
                if key in values:
                    raise ValueError('Duplicate HTTP property')
                values[key] = text(b)
            events.append(dict(action='http_capture',target=hex(address)))
        elif address in (0x141426950,0x141426b30):
            width = 1 if address==0x141426950 else 2
            off = h.image.offset(b-h.image.pe.base)
            data = h.raw[off:off+512]
            end = next((i for i in range(0,512-width+1,width) if data[i:i+width]==bytes(width)),None)
            if end is None:
                raise ValueError('Header literal bound')
            value = data[:end].decode('ascii' if width==1 else 'utf-16le')
            if a in url.GLOBALS and value!=('A','B','C')[url.GLOBALS.index(a)]:
                raise ValueError('Header build initializer literal differs')
            put(a,value)
            result = a
        elif address==0x141436ed0:
            if a!=rbp-0x48 or b!=2:
                raise ValueError('Header build getter allocation bound')
            pointer = heap[0]
            heap[0]+=16
            if heap[0]>=h.scratch+0x2e000:
                raise ValueError('Header build getter heap bound')
            machine.mem_write(a,struct.pack('<Q',pointer))
            machine.mem_write(a+12,struct.pack('<I',b))
            result = a
        elif address==0x1444b1fe0:
            result = cls
        elif address in (0x1444b1430,0x1444b1550):
            result = account_cls
        elif address==0x1444ec890:
            if a!=rbp-0x38:
                raise ValueError('Device fixture destination differs')
            put(a,options['device_key'])
            result = a
        elif address==0x14452b620:
            if a!=account or b!=rbp-0x28:
                raise ValueError('Player fixture receiver/destination differs')
            put(b,options['player_id'])
            result = b
            events.append(dict(action='player_getter_fixture'))
        elif address==0x141483080:
            if not h.scratch+0x20000 <= a < h.scratch+0x2e000:
                raise ValueError('Header free fixture bound')
        elif address!=0x1487e914c:
            raise ValueError('Unreviewed header fixture')
        h.finish(result)

    fixtures = (set_url,set_header,set_method,0x141426950,0x141426b30,0x141436ed0,
                0x1444b1fe0,0x1444b1430,0x1444b1550,0x1444ec890,0x14452b620,0x141483080,0x1487e914c)
    for address in fixtures:
        h.add_fixture(address,fixture)

    def run(inputs):
        options.clear(); options.update(inputs)
        values.clear(); headers.clear(); events.clear()
        heap[0] = h.scratch+0x20000
        h.uc.mem_write(manager-16,b'\xa5'*0x320)
        if h.call(0x1444c4210,manager,budget=10000)!=manager:
            raise ValueError('Header GMC2 constructor return differs')
        if text(manager+0x190)!='netmarbles' or text(manager+0x1c8)!='netmarbles-v5':
            raise ValueError('Header GMC2 constructor constants differ')
        for address in url.INITIALIZERS:
            h.call(address,budget=1024)
        put(settings+0x38,inputs['game_code'])
        h.uc.mem_write(settings+0x48,bytes([inputs['build_code']]))
        put(account+0x78,inputs['access_token'])
        for destination,value in ((url_string,inputs['url']),(service,inputs['service_code']),(etag,inputs['etag'])):
            put(destination,value)
        stack = h.scratch+0x8000
        h.uc.mem_write(stack+0x38,struct.pack('<Q',request))
        h.uc.mem_write(stack+0x60,struct.pack('<Q',service))
        for register,value in ((h.x.UC_X86_REG_RSP,stack),(h.x.UC_X86_REG_RBP,rbp),
                               (h.x.UC_X86_REG_R14,manager),(h.x.UC_X86_REG_R12,etag),(h.x.UC_X86_REG_RDI,url_string)):
            h.uc.reg_write(register,value)
        h.uc.emu_start(START,STOP,count=10000)
        if h.uc.reg_read(h.x.UC_X86_REG_RIP)!=STOP:
            raise ValueError('Header instruction budget exhausted')
        plan = plan_gmc2_get_request(**inputs)
        if values!=dict(url=plan.url,method=plan.method) or tuple(headers)!=plan.headers:
            raise ValueError('Current header capture differs from portable request')
        if bytes(h.uc.mem_read(manager-16,16))!=b'\xa5'*16 or bytes(h.uc.mem_read(manager+0x300,16))!=b'\xa5'*16:
            raise ValueError('Header manager canaries changed')
        if len([e for e in events if e['action']=='player_getter_fixture'])!=int(bool(inputs['access_token'])):
            raise ValueError('Header player getter gate differs')
        return dict(inputs=inputs,actual=dict(**values,headers=list(headers)),events=events.copy(),canaries_unchanged=True)

    cases = [run(dict(url='https://config.invalid/request',service_code='service-fixture',game_code='game-fixture',
        build_code=code,etag=tag,access_token=token,device_key='device-fixture',player_id=player))
        for code,tag,token,player in itertools.product((0,1,2,255),('','e','etag-fixture'),('','t','token-fixture'),('','player-fixture'))]
    cases.append(run(dict(url='https://apis.netmarble.com/gc2/template-groups/netmarbles-v5/5.2.11?game=v5&country=G9&build=A&engine=unreal&market=nmp',
        service_code='netmarbles',game_code='thered',build_code=0,etag='',access_token='',device_key='',player_id='')))
    return dict(schema=1,source=str(h.source),source_sha256=h.sha,evidence=h.evidence,cases=cases,
        start=hex(START),stop=hex(STOP),copy_import=h.copy_import,fixtures=[hex(a) for a in sorted(h.fixtures)],
        dependencies={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('replay-gmc2-headers-11316.py','replay-gmc2-url-11316.py','native-request-harness-11316.py','build-native-entry-code.py','extract-native-enums.py','build-object-zero-init-code.py')},
        portable_helper_sha256=hashlib.sha256((HERE.parents[1]/'vampir-shared/vampir_core/gmc2_request.py').read_bytes()).hexdigest(),
        native_execution=True,network_ready=False,
        limits=['Actual GMC2 constructor, build initializers/getter and current HTTP argument/header slice execute.',
                'HTTP virtual methods capture synthetic arguments; FString/CDO/allocator/free/exit registration and device/player getters are fixtures.',
                'All identities are synthetic or empty; no request creation, TLS/console gates, HTTP transport, full startup or authentication.'])


if __name__=='__main__':
    report = replay()
    native = load('header_root',HERE/'build-native-entry-code.py')
    audit = load('header_snapshot',HERE/'audit-client-release.py')
    path = audit.save_snapshot(native.ROOT/'code-clues/gmc2-headers-11316',report)
    print(json.dumps(dict(report=str(path),cases=len(report['cases']))))
