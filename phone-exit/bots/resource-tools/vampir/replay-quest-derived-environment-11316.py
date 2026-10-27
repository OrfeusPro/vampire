"""Source-derived environment factory and virtual A8/B8/C8 with explicit table/string fixtures."""
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    h=load('native-request-harness-11316').make_harness(
        {'run-430fed1bb906':'6e162d6a5056ba52dbfe8bf50bec54e02b66ab2271c8c4d489e5c2f54a68bd06',
         'run-ca617b011bc3':'6d544a194b99d1597156d3e4b8280ecb9d3979090789b5a450c0b884911f902c'},
        {0x1456001d0,0x145d9c7c0,0x145db0150,0x145da1d40,0x145db5480},
        leaves={0x141488490:'488b4108c3',0x1418af880:'8b4140c3'})
    index=load('knowledge-index')
    if h.sha!=SHA or any(not f.get('block_coverage_complete') or index.missing_conditional_fallthroughs(f['instructions'])
        or f.get('direct_flow_coverage_complete') is not True for f in h.fragments):
        raise ValueError('Derived environment source/coverage differs')
    uc,x,b=h.uc,h.x,h.scratch
    environment,record_table,output=b+0x1000,b+0x2000,b+0x3000
    current={};calls=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,n,size=8):uc.mem_write(at,int(n).to_bytes(size,'little'))
    def get(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def source_u64(at):return struct.unpack_from('<Q',h.raw,h.image.offset(at-h.image.pe.base))[0]
    off=h.image.offset(0x141403ab0-h.image.pe.base)
    if source_u64(0x149909370+0xa8)!=0x141403ab0 or h.raw[off:off+3]!=bytes.fromhex('32c0c3'):
        raise ValueError('Base environment A8 false leaf differs')
    if source_u64(0x149909370+0xb8)!=0x1418af880:
        raise ValueError('Base environment B8 getter differs')
    slots={slot:source_u64(0x149a3dac0+slot) for slot in (0xa8,0xb0,0xb8,0xc8)}
    if slots!={0xa8:0x145db0150,0xb0:0x1418af880,0xb8:0x145da1d40,0xc8:0x145db5480}:
        raise ValueError('Derived environment virtual slots differ')
    def allocate(machine):
        if reg('RCX')!=0x1b0:raise ValueError('Derived environment allocation size differs')
        calls.append('allocate');h.finish(environment if current['allocate'] else 0)
    def registration(machine):
        if reg('RCX')!=environment+0x28:raise ValueError('Base registry receiver differs')
        calls.append('register');h.finish(reg('RCX'))
    def lookup(machine):
        key=reg('RDX')&0xffffffff;record=current['records'].get(key,0)
        out=reg('RCX');uc.mem_write(out,bytes(16));put(out+8,record)
        current['lookups'].append(key);h.finish(out)
    def record_text(machine):
        record=reg('RCX')
        if record not in current['records'].values():raise ValueError('Record string receiver differs')
        calls.append('record-text');h.finish(record+0x20)
    def copy_string(machine):
        source=reg('RDX');target=reg('RCX')
        if source not in [r+0x20 for r in current['records'].values()]:raise ValueError('Record string source differs')
        uc.mem_write(target,bytes(uc.mem_read(source,16)));calls.append('copy-string');h.finish(target)
    def read_text(pointer):
        out=[]
        for i in range(64):
            c=get(pointer+2*i,2)
            if not c:return ''.join(out)
            if not 32<=c<=126:raise ValueError('Only bounded ASCII compare fixture is reviewed')
            out.append(chr(c))
        raise ValueError('Derived name comparison bound')
    def compare(machine):
        a,z=read_text(reg('RCX')),read_text(reg('RDX'))
        calls.append('compare');h.finish(int(a.lower()!=z.lower()))
    def free(machine):
        if reg('RCX') not in current['buffers']:raise ValueError('Unexpected derived string cleanup')
        calls.append('free');h.finish()
    callbacks={0x146908950:allocate,0x144286f50:registration,0x145c79950:lookup,
        b+0x4000:record_text,0x1414266a0:copy_string,0x14145f1e0:compare,0x141483080:free}
    for at,fn in callbacks.items():h.add_fixture(at,fn)
    put(record_table+0x20,b+0x4000)
    def setup(allocated=True):
        current.clear();current.update(allocate=allocated,records={},buffers=[],lookups=[]);calls.clear()
        uc.mem_write(environment,b'\xa5'*0x1b0)
        result=h.call(0x145d9c7c0)
        if result!=(environment if allocated else 0):raise ValueError('Environment factory result differs')
        if calls!=(['allocate','register'] if allocated else ['allocate']):raise ValueError('Factory/base registration order differs')
        if allocated:
            if get(environment)!=0x149a3dac0 or get(0x14b5e5ea8)!=environment:
                raise ValueError('Factory global/derived vptr differs')
            if get(environment+8)!=0x149a3db98 or get(environment+0x28)!=0x149a3dba0:
                raise ValueError('Factory secondary vptr differs')
            if get(environment+0xf0,2)!=0x6420:raise ValueError('Factory private word differs')
    def record(key,text,kind):
        at=b+0x5000+len(current['records'])*0x100;uc.mem_write(at,bytes(0x100));put(at,record_table);put(at+0xc,kind,4)
        if text is not None:
            pointer=b+0x9000+len(current['records'])*0x100;encoded=(text+'\0').encode('utf-16le')
            uc.mem_write(pointer,encoded);put(at+0x20,pointer);put(at+0x28,len(text)+1,4);put(at+0x2c,len(text)+1,4)
            current['buffers'].append(pointer)
        current['records'][key]=at
    setup(False)
    names=[]
    for old_name,new_name in ((None,None),('',''),(None,''),('',None),('MapA','MapA'),
                              ('MapA','mapa'),('MapA','MapB'),('MapA',''),('', 'MapB'),(None,'MapB')):
        setup();record(10012,old_name,7);record(10020,new_name,9)
        put(environment+0x40,10012,4);put(environment+0x44,10020,4);calls.clear()
        before=bytes(uc.mem_read(environment,0x1b0))
        actual=h.call(slots[0xa8],environment)&255
        expected=int((old_name or '').lower()!=(new_name or '').lower())
        if actual!=expected or current['lookups']!=[10012,10020]:raise ValueError('Derived A8 name lookup/comparison differs')
        if bytes(uc.mem_read(environment,0x1b0))!=before:raise ValueError('Derived A8 changed environment')
        names.append(dict(old=old_name,new=new_name,result=bool(actual),lookups=current['lookups'].copy(),calls=calls.copy()))
    kinds=[]
    for present in (False,True):
     for kind in (0,1,7,0xffffffff):
        setup()
        if present:record(10012,'MapA',kind)
        put(environment+0x40,10012,4);put(environment+0x44,10020,4)
        actual=h.call(slots[0xb8],environment)&0xffffffff
        default_off=h.image.offset(0x1496706e0-h.image.pe.base)
        default=int.from_bytes(h.raw[default_off:default_off+4],'little')
        if actual!=(kind if present else default) or current['lookups']!=[10012]:
            raise ValueError('Derived B8 record field differs')
        if present and actual==10012:raise ValueError('Record field confused with world ID')
        kinds.append(dict(record_present=present,record_field_0c=kind,result=actual,world_id=10012))
    audit=load('audit-client-release')
    report=dict(source_sha256=SHA,tool_sha256=audit.sha256(Path(__file__)),exports=h.evidence,
        derived_vtable='0x149a3dac0',slots={hex(k):hex(v) for k,v in slots.items()},
        allocation_failure_checked=True,names=names,kinds=kinds,native_execution=True,
        network_used=False,action_admitted=False,
        limits=['Whole factory/base constructor and derived A8/B8/C8 execute. Registry/allocation, record lookup, record name getter, FString copy/free and ASCII case-insensitive comparison are fixtures.',
            'A8 compares names resolved for committed+40 and pending+44; B8 returns resolved record+0C, not the world ID itself.',
            'Record values and names are synthetic; actual world table provenance, factory lifecycle/phase initialization, derived phase completion and active task/actor remain unknown.',
            'Only source11316 is covered; no installed11318 portability or runtime activation.'])
    path=audit.save_snapshot(h.root/'code-clues/quest-derived-environment-11316',report)
    return path,report


if __name__=='__main__':
    path,result=run();print(json.dumps(dict(artifact=str(path),names=len(result['names']),kinds=len(result['kinds']))))
