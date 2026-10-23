"""Source-bound 1.13.16 GMC2 constructor, settings prefix and version getter.

Only saved files and synthetic memory; no process attachment or network.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parent
SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
EXPORTS={
    'run-0cdca2f717ea':'e5667cf351382f2ae5d7454010f6526cb24d0a11b49e86e87eb652c64babaf34',
    'run-d490839a48f4':'ba186c8e32fccaecc4a5a4dae04b8df9d2c667327bec1309a6d5a9ce04fa0bb1',
}
SETTINGS, SETTINGS_STOP, GMC, VERSION=0x1444b3290,0x1444b3339,0x1444c4210,0x14452ac30


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def replay(root=None):
    native=load('defaults_11316_native',HERE/'build-native-entry-code.py')
    sys.path.insert(0,str(HERE.parents[2]/'.tools/vampir-analysis'))
    import unicorn
    from unicorn import x86_const as x
    if unicorn.__version__!='2.1.4' or native.capstone.__version__!='5.0.6':
        raise ValueError('Pinned analysis runtime required')
    root=Path(root) if root else native.ROOT
    source=root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'
    raw=source.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError('SDK defaults source SHA changed')
    image=native.Image(raw);functions={};evidence=[]
    for name,expected in EXPORTS.items():
        path=root/'ghidra/request-exports'/SHA/name/'details.json';payload=path.read_bytes()
        if hashlib.sha256(payload).hexdigest()!=expected:raise ValueError('SDK defaults export changed')
        report=json.loads(payload)
        if report['new_source_sha256']!=SHA:raise ValueError('SDK defaults export source changed')
        functions.update({int(f['address'],16):f for f in report['functions']})
        evidence.append(dict(path=str(path),sha256=expected))
    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64);pages=set();instructions={}
    def page(at):
        base=at&~4095
        if base not in pages:uc.mem_map(base,4096);pages.add(base)
    for entry in (SETTINGS,GMC,VERSION):
        function=functions[entry]
        if not function['decompilation_completed']:raise ValueError('Incomplete defaults function')
        for row in function['instructions']:
            at=int(row['address'],16);data=bytes.fromhex(row['bytes']);off=image.offset(at-image.pe.base)
            if raw[off:off+len(data)]!=data:raise ValueError('SDK defaults instruction changed')
            instructions[at]=row
            page(at);page(at+len(data)-1);uc.mem_write(at,data)
    if SETTINGS_STOP not in instructions:raise ValueError('Settings prefix end is not an instruction boundary')
    scratch=0x24000000;uc.mem_map(scratch,0x20000)
    obj,heap,stack,stop=scratch+0x1000,[scratch+0x4000],scratch+0x18000,scratch+0x1f000
    uc.mem_write(stop,b'\xc3')
    fixtures=(0x1417cba90,0x141426b30,0x141426950)
    for at in fixtures:page(at);uc.mem_write(at,b'\xc3')
    page(0x14b5632e0);uc.mem_write(0x14b5632e0,b'\0')
    captured,base_calls={},[]
    def finish(value):
        sp=uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX,value)
        uc.reg_write(x.UC_X86_REG_RIP,int.from_bytes(uc.mem_read(sp,8),'little'))
        uc.reg_write(x.UC_X86_REG_RSP,sp+8)
    def hook(machine,at,size,user):
        if at==stop:machine.emu_stop();return
        if at not in fixtures:
            if at not in instructions:raise ValueError('Unreviewed native target '+hex(at))
            return
        dest,ptr=[machine.reg_read(reg) for reg in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
        if at==0x1417cba90:
            if dest!=obj:raise ValueError('Settings base fixture receiver differs')
            base_calls.append(at);finish(dest);return
        if not obj<=dest<=obj+0x300-16 or dest in captured:raise ValueError('String fixture destination out of bounds or duplicate')
        width=2 if at==0x141426b30 else 1
        off=image.offset(ptr-image.pe.base);data=raw[off:off+512]
        end=next((i for i in range(0,len(data)-width+1,width) if data[i:i+width]==bytes(width)),None)
        if end is None:raise ValueError('String literal exceeds bound')
        text=data[:end].decode('utf-16le' if width==2 else 'ascii')
        payload=text.encode('utf-16le')+b'\0\0';storage=heap[0];heap[0]+=(len(payload)+15)&~15
        if heap[0]>=scratch+0x14000:raise ValueError('String fixture heap exceeded')
        machine.mem_write(storage,payload);machine.mem_write(dest,struct.pack('<QII',storage,len(payload)//2,len(payload)//2))
        captured[dest]=dict(source=hex(ptr),source_bytes=data[:end+width].hex(),text=text)
        finish(dest)
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    cases=[]
    def run(entry,poison,prefix=False):
        captured.clear();base_calls.clear();heap[0]=scratch+0x4000
        uc.mem_write(obj-16,bytes([poison])*0x340)
        uc.reg_write(x.UC_X86_REG_RCX,obj);uc.reg_write(x.UC_X86_REG_RSP,stack)
        uc.mem_write(stack,struct.pack('<Q',stop))
        uc.emu_start(entry,SETTINGS_STOP if prefix else 0,count=20000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=(SETTINGS_STOP if prefix else stop):raise ValueError('Native instruction budget exhausted')
        return {hex(at-obj):value['text'] for at,value in captured.items()}
    for poison in (0,0x55,0xaa,0xff):
        fields=run(SETTINGS,poison,True)
        if base_calls!=[0x1417cba90] or len(fields)!=7:raise ValueError('Settings prefix fixture sequence differs')
        values=dict(market=fields['0x28'],game_code=fields['0x38'],sdk_type=fields['0x50'],
            client_ids=[fields[hex(at)] for at in (0x68,0x78,0x88,0x98)],
            build_code=uc.mem_read(obj+0x48,1)[0],sdk_zone=uc.mem_read(obj+0x49,1)[0])
        cases.append(dict(kind='settings_prefix',poison=poison,values=values,literals=list(captured.values())))
        fields=run(GMC,poison)
        if uc.reg_read(x.UC_X86_REG_RAX)!=obj:raise ValueError('GMC constructor return differs')
        if bytes(uc.mem_read(obj-16,16))!=bytes([poison])*16 or bytes(uc.mem_read(obj+0x260,16))!=bytes([poison])*16:
            raise ValueError('GMC constructor crossed object bounds')
        cases.append(dict(kind='gmc_constructor',poison=poison,values={hex(at):fields[hex(at)] for at in (0x150,0x160,0x170,0x180,0x190,0x1c8)},literals=list(captured.values())))
    fields=run(VERSION,0xa5)
    if uc.reg_read(x.UC_X86_REG_RAX)!=obj:raise ValueError('SDK version return differs')
    cases.append(dict(kind='sdk_version',values=fields,literals=list(captured.values())))
    return dict(schema=1,source=str(source),source_sha256=SHA,evidence=evidence,cases=cases,
        dependencies={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('replay-sdk-defaults-11316.py','build-native-entry-code.py','extract-native-enums.py')},
        fixtures=['Settings base constructor returns receiver without writes.',
                  'ASCII/UTF16 FString constructors read exact source literals and allocate bounded synthetic storage.'],
        limits=['Settings only to explicit prefix boundary; other settings fields not covered.',
                'GMC constructor and SDK version execute to return; logging disabled.',
                'No game overrides, active settings, actual allocator/FString implementation, GMC2 URL/headers, network or live auth.'])


if __name__=='__main__':
    report=replay();audit=load('defaults_snapshot',HERE/'audit-client-release.py')
    target=audit.save_snapshot(load('defaults_native_root',HERE/'build-native-entry-code.py').ROOT/'code-clues/sdk-defaults-11316',report)
    print(json.dumps(dict(report=str(target),cases=len(report['cases']),source_sha256=SHA)))
