"""Execute FDeviceInfo::GetPlatform with initialized synthetic TLS/console state."""
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
CALLER=0x1444ecf50


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def replay(root=None):
    platform=load('web_platform_inputs',HERE/'replay-sdk-platform-11316.py')
    harness=load('web_platform_harness',HERE/'native-request-harness-11316.py')
    exports=dict(platform.EXPORTS,**{'run-47e33521ffcf':'99158407757acb6b2b2d245e406b0b3e1c8e834048c00f442af56a5348a58cd9'})
    h=harness.make_harness(exports,{platform.INIT,platform.GETTER,CALLER},root=root)
    output,source_storage,output_storage,console,gs,tls=[h.scratch+n for n in
        (0x11000,0x12000,0x13000,0x14000,0x5000,0x6000)]
    h.uc.mem_map(h.scratch+0x101000,4096)
    h.uc.reg_write(h.x.UC_X86_REG_GS_BASE,gs)
    h.uc.mem_write(gs+0x58,struct.pack('<Q',tls))
    h.uc.mem_write(tls,struct.pack('<Q',h.scratch))
    h.uc.mem_write(h.scratch+0x101184,struct.pack('<i',0))
    h.uc.mem_write(0x14b6a4c20,struct.pack('<I',0))
    h.uc.mem_write(0x14b562660,struct.pack('<i',-1))
    h.uc.mem_write(0x14b5632e0,b'\0')
    events,options=[],{}
    label_at=h.image.offset(0x149535650-h.image.pe.base)
    label=h.raw[label_at:label_at+256].split(b'\0')[0].decode('ascii')
    if label!='class FString __cdecl Netmarble::Service::FDeviceInfo::GetPlatform(void)':
        raise ValueError('Platform caller diagnostic differs')

    def fixture(machine):
        at=machine.reg_read(h.x.UC_X86_REG_RIP)
        a,b=[machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX,h.x.UC_X86_REG_RDX)]
        value=0
        if at==0x141426b30:
            off=h.image.offset(b-h.image.pe.base)
            if a!=platform.GLOBAL or h.raw[off:off+6]!='PC\0'.encode('utf-16le'):
                raise ValueError('Web platform PC fixture differs')
            machine.mem_write(source_storage,h.raw[off:off+6])
            machine.mem_write(a,struct.pack('<QII',source_storage,3,3));value=a
        elif at==0x141436ed0:
            if a!=output or b!=3:raise ValueError('Web platform allocation differs')
            machine.mem_write(a,struct.pack('<Q',output_storage))
            machine.mem_write(a+12,struct.pack('<I',b));value=a
        elif at in (0x14148ee80,0x14148ee40):
            value=int(options['first' if at==0x14148ee80 else 'second'])
            events.append(hex(at))
        elif at!=0x1487e914c:
            raise ValueError('Unreviewed web platform fixture')
        h.finish(value)

    for at in (0x141426b30,0x141436ed0,0x1487e914c,0x14148ee80,0x14148ee40):h.add_fixture(at,fixture)
    cases=[]
    for poison in (0,0x55,0xaa,0xff):
        h.uc.mem_write(platform.GLOBAL,bytes([poison])*16)
        h.call(platform.INIT,budget=1024)
        inputs=[(None,False,False)]+[(slots,first,second) for slots,first,second in
            itertools.product(((3,2),(2,3),(255,3)),(False,True),(False,True))]
        for slots,first,second in inputs:
            events.clear();options.update(first=first,second=second)
            h.uc.mem_write(0x14b562658,struct.pack('<Q',console if slots else 0))
            if slots:h.uc.mem_write(console,struct.pack('<II',*slots))
            h.uc.mem_write(output-16,bytes([poison])*48)
            returned=h.call(CALLER,output,budget=4096)
            pointer,count,capacity=struct.unpack('<QII',bytes(h.uc.mem_read(output,16)))
            if returned!=output or not 0<=count<=capacity<=3:raise ValueError('Web platform result bounds')
            if count and pointer!=output_storage:raise ValueError('Web platform storage differs')
            actual=bytes(h.uc.mem_read(pointer,(count-1)*2)).decode('utf-16le') if count else ''
            selected=3 if slots is None else slots[0 if first or second else 1]
            expected='PC' if selected==3 else ''
            if actual!=expected:raise ValueError('Web platform override differs')
            expected_calls=[] if slots is None else ['0x14148ee80']+([] if first else ['0x14148ee40'])
            if events!=expected_calls:raise ValueError('Web platform predicate gate differs')
            if any(bytes(h.uc.mem_read(a,16))!=bytes([poison])*16 for a in (output-16,output+16)):
                raise ValueError('Web platform canaries changed')
            cases.append(dict(poison=poison,console_slots=slots,first=first,second=second,
                selected_byte=selected,actual=actual,predicate_calls=events.copy(),canaries_unchanged=True))
    return dict(schema=1,source=str(h.source),source_sha256=h.sha,evidence=h.evidence,cases=cases,
        diagnostic=label,dependencies={n:hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in
            ('replay-web-platform-11316.py','replay-sdk-platform-11316.py','native-request-harness-11316.py','build-native-entry-code.py','extract-native-enums.py','build-object-zero-init-code.py')},
        native_execution=True,network_ready=False,
        limits=['Current FDeviceInfo::GetPlatform, platform getter and PC initializer execute with initialized TLS guard.',
                'TLS/console state, two thread predicates, FString allocation/storage, memcpy and exit registration are fixtures; logging disabled.',
                'Lazy console lookup/registration not executed. NID parent/caller binding, other platform labels, auth and active game state remain unverified.'])


if __name__=='__main__':
    report=replay();native=load('web_platform_root',HERE/'build-native-entry-code.py');audit=load('web_platform_snapshot',HERE/'audit-client-release.py')
    path=audit.save_snapshot(native.ROOT/'code-clues/web-platform-11316',report)
    print(json.dumps(dict(report=str(path),cases=len(report['cases']))))
