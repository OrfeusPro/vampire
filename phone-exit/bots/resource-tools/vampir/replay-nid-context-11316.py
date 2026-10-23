"""Current ten NID context pairs before map construction; synthetic getters."""
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
ROOT,BEGIN,END=0x1450e3c80,0x1450e4058,0x1450e42a8
KEYS=('gameCode','buildCode','countryCode','language','os','nmDeviceKey','deviceKey','osVersion','clientId','nidV')


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def replay(root=None):
    url=load('nid_context_url_inputs',HERE/'replay-gmc2-url-11316.py')
    harness=load('nid_context_harness',HERE/'native-request-harness-11316.py')
    exports=dict(url.EXPORTS,**{'run-988ec3bf8f0a':'ac636f8488eb37a37646b4213878b4db9bb4c7567e5eddb2569195e346c0f6fd'})
    h=harness.make_harness(exports,{ROOT,0x1445320c0,*url.INITIALIZERS},root=root)
    rbp,settings,context=[h.scratch+n for n in (0x10000,0x18000,0x17000)]
    heap,options,events=[h.scratch+0x20000],{},[]
    label_at=h.image.offset(0x149738f10-h.image.pe.base)
    label=h.raw[label_at:label_at+512].split(b'\0')[0].decode('ascii')
    if 'FNetmarbleIDContent::CheckPossibleToOpen(' not in label:raise ValueError('NID caller signature differs')

    def put(destination,value):
        if not (h.scratch<=destination<=h.scratch+0x40000-16 or destination in url.GLOBALS):
            raise ValueError('NID string destination bound')
        data=(value+'\0').encode('utf-16le')
        if len(data)>512 or heap[0]+len(data)>=h.scratch+0x2e000:raise ValueError('NID string heap bound')
        pointer=heap[0] if value else 0
        if pointer:h.uc.mem_write(pointer,data);heap[0]+=(len(data)+15)&~15
        count=len(data)//2 if value else 0
        h.uc.mem_write(destination,struct.pack('<QII',pointer,count,count))

    def text(address):
        if not h.scratch<=address<=h.scratch+0x40000-16:raise ValueError('NID FString object bound')
        pointer,count,capacity=struct.unpack('<QII',bytes(h.uc.mem_read(address,16)))
        if not 0<=count<=capacity<=256:raise ValueError('NID FString counts')
        if not count:return ''
        if not h.scratch<=pointer<=h.scratch+0x40000-count*2:raise ValueError('NID FString data bound')
        data=bytes(h.uc.mem_read(pointer,count*2))
        if data[-2:]!=bytes(2):raise ValueError('NID FString termination')
        return data[:-2].decode('utf-16le')

    fixture_outputs={0x144528a00:('countryCode',0x340),0x143d1c730:('language',0x330),
        0x1444ecf50:('os',0x320),0x1444ec890:('nmDeviceKey',0x310),
        0x1445293f0:('deviceKey',0x300),0x1444ecd90:('osVersion',0x2f0)}

    def fixture(machine):
        at=machine.reg_read(h.x.UC_X86_REG_RIP)
        a,b,c=[machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX,h.x.UC_X86_REG_RDX,h.x.UC_X86_REG_R8)]
        result=0
        if at in (0x141426950,0x141426b30):
            width=1 if at==0x141426950 else 2
            off=h.image.offset(b-h.image.pe.base);data=h.raw[off:off+512]
            end=next((i for i in range(0,512-width+1,width) if data[i:i+width]==bytes(width)),None)
            if end is None:raise ValueError('NID literal bound')
            value=data[:end].decode('ascii' if width==1 else 'utf-16le')
            if a in url.GLOBALS and value!=('A','B','C')[url.GLOBALS.index(a)]:raise ValueError('NID build initializer differs')
            put(a,value);result=a
        elif at==0x141436ed0:
            if a!=rbp+0x350 or b!=2:raise ValueError('NID build getter allocation differs')
            pointer=heap[0];heap[0]+=16
            if heap[0]>=h.scratch+0x2e000:raise ValueError('NID allocation heap bound')
            machine.mem_write(a,struct.pack('<Q',pointer));machine.mem_write(a+12,struct.pack('<I',b));result=a
        elif at in fixture_outputs:
            key,offset=fixture_outputs[at];destination=b if key in ('countryCode','deviceKey') else a
            if destination!=rbp+offset:raise ValueError('NID getter destination differs')
            if key in ('countryCode','deviceKey') and a!=context:raise ValueError('NID getter receiver differs')
            if key=='deviceKey' and c&255!=1:raise ValueError('NID device getter mode differs')
            put(destination,options[key]);result=destination;events.append(dict(target=hex(at),key=key))
        elif at!=0x1487e914c:raise ValueError('Unreviewed NID context fixture')
        h.finish(result)

    for at in (0x141426950,0x141426b30,0x141436ed0,0x1487e914c,*fixture_outputs):h.add_fixture(at,fixture)
    cases=[]
    for poison,code,empty in itertools.product((0,0x55,0xaa,0xff),(0,1,2,255),(False,True)):
        events.clear();heap[0]=h.scratch+0x20000
        h.uc.mem_write(rbp-16,bytes([poison])*0x800)
        values=dict(gameCode='' if empty else 'thered',clientId='' if empty else 'client-fixture',
            countryCode='' if empty else 'UA',language='' if empty else 'en',os='' if empty else 'PC',
            nmDeviceKey='' if empty else 'nm-fixture',deviceKey='' if empty else 'device-fixture',osVersion='' if empty else 'Windows-fixture')
        options.clear();options.update(values)
        for entry in url.INITIALIZERS:h.call(entry,budget=1024)
        put(settings+0x38,values['gameCode']);put(settings+0x98,values['clientId'])
        h.uc.mem_write(settings+0x48,bytes([code]))
        for register,value in ((h.x.UC_X86_REG_RSP,h.scratch+0x38000),(h.x.UC_X86_REG_RBP,rbp),
            (h.x.UC_X86_REG_RBX,settings),(h.x.UC_X86_REG_R15,context),(h.x.UC_X86_REG_R12,0)):
            h.uc.reg_write(register,value)
        h.uc.emu_start(BEGIN,END,count=10000)
        if h.uc.reg_read(h.x.UC_X86_REG_RIP)!=END:raise ValueError('NID context instruction budget exhausted')
        pairs=[]
        for index in range(10):
            key,value=struct.unpack('<QQ',bytes(h.uc.mem_read(rbp+0x4a0+index*16,16)))
            pairs.append((text(key),text(value)))
        expected=dict(values,buildCode={0:'A',1:'B',2:'C'}.get(code,'A'),nidV='3')
        if pairs!=[(key,expected[key]) for key in KEYS]:raise ValueError('NID context pairs differ')
        if [e['key'] for e in events]!=list(KEYS[2:8]):raise ValueError('NID getter sequence differs')
        if bytes(h.uc.mem_read(rbp-16,16))!=bytes([poison])*16 or bytes(h.uc.mem_read(rbp+0x7e0,16))!=bytes([poison])*16:
            raise ValueError('NID context canaries changed')
        cases.append(dict(poison=poison,build_code=code,empty=empty,pairs=pairs,events=events.copy(),canaries_unchanged=True))
    return dict(schema=1,source=str(h.source),source_sha256=h.sha,evidence=h.evidence,cases=cases,
        caller_diagnostic=label,start=hex(BEGIN),stop=hex(END),native_execution=True,network_ready=False,
        dependencies={n:hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in
            ('replay-nid-context-11316.py','replay-gmc2-url-11316.py','native-request-harness-11316.py','build-native-entry-code.py','extract-native-enums.py','build-object-zero-init-code.py')},
        limits=['Actual current NID base-pair assembly, build getter and three initializers execute before map constructor.',
                'Six context getters, settings/context objects, FString storage/allocation, memcpy and exit registration are fixtures.',
                'Earlier URL/availability gates, actual getter identities, map construction, encoding, webV/authType extensions, browser and authentication not executed.'])


if __name__=='__main__':
    report=replay();native=load('nid_context_root',HERE/'build-native-entry-code.py');audit=load('nid_context_snapshot',HERE/'audit-client-release.py')
    path=audit.save_snapshot(native.ROOT/'code-clues/nid-context-11316',report)
    print(json.dumps(dict(report=str(path),cases=len(report['cases']))))
