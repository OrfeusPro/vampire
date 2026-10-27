"""Native singleton/handle/hash lookup and derived initialization; records remain synthetic."""
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
LOOKUP='8b41204c8bc9448bd23b414c74654c8b4158488d41508b49604d85c04c0f44c0ffc94923ca418b048883f8ff7445498b51180f1f400066660f1f84000000000048984869c85801000044391411740f8b84115001000083f8ff75e533c0c3488bc233d24803c1488d4008480f44c24885c0750233c0c3'
INIT='488b0561200604488941388b055f2006048941408b05562006048941448b054d20060489414833c0488981c8000000488981d0000000c641300766c7415a010166c741780001c3'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    h=load('native-request-harness-11316').make_harness({
        'run-430fed1bb906':'6e162d6a5056ba52dbfe8bf50bec54e02b66ab2271c8c4d489e5c2f54a68bd06',
        'run-ca617b011bc3':'6d544a194b99d1597156d3e4b8280ecb9d3979090789b5a450c0b884911f902c',
        'run-9c3aa7f1a5cd':'2d5b59ea71478e48a63a172ef313f20c379e5d7ace470b041c5fa3ce9a0eb78e',
        'run-eadbefe5996b':'5716c3cce601b7a762f2c9332f4e5aa41bfb3ef5621d7bb24add49b0a0699b05'},
        {0x1456001d0,0x145d9c7c0,0x145da3540,0x145da1d40,0x145c79950,0x145c545b0},
        leaves={0x145c53e30:LOOKUP,0x14560e670:INIT,0x141488490:'488b4108c3',0x1418af880:'8b4140c3'})
    index=load('knowledge-index');native=load('build-native-entry-code')
    if h.sha!=SHA or any(not f.get('block_coverage_complete') or f.get('direct_flow_coverage_complete') is not True
        or index.missing_conditional_fallthroughs(f['instructions']) for f in h.fragments):
        raise ValueError('World record source/coverage differs')
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    rows=list(decoder.disasm(bytes.fromhex(LOOKUP),0x145c53e30));addresses={r.address for r in rows}
    if sum(r.size for r in rows)!=len(bytes.fromhex(LOOKUP)) or rows[-1].mnemonic!='ret':
        raise ValueError('Explicit lookup leaf boundary differs')
    for r in rows:
        if r.group(native.capstone.CS_GRP_CALL):raise ValueError('Lookup leaf unexpectedly calls outside')
        if r.group(native.capstone.CS_GRP_JUMP) and (not r.operands or r.operands[0].type!=native.X86_OP_IMM
            or r.operands[0].imm not in addresses):raise ValueError('Lookup leaf branch leaves explicit code')
    uc,x,b=h.uc,h.x,h.scratch;environment=b+0x1000;entries=b+0x8000;buckets=b+0x6000;handle=b+0x7000
    singleton=0x14b1c8cf0;selected=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,n,size=8):uc.mem_write(at,int(n).to_bytes(size,'little'))
    def get(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def allocate(machine):
        if reg('RCX')!=0x1b0:raise ValueError('World environment allocation differs')
        h.finish(environment)
    def register(machine):
        if reg('RCX')!=environment+0x28:raise ValueError('World base registration differs')
        h.finish(reg('RCX'))
    def select_pending(machine):
        if reg('RCX')&0xffffffff!=0:raise ValueError('Derived initialization selection differs')
        selected.append(0);h.finish()
    for at,fn in {0x146908950:allocate,0x144286f50:register,0x145e0f840:select_pending}.items():h.add_fixture(at,fn)
    tls=0x30000000;uc.mem_map(tls,0x110000);uc.reg_write(x.UC_X86_REG_GS_BASE,tls)
    put(tls+0x58,tls+0x100);put(tls+0x100,tls+0x200)
    put(0x14b6a4c20,0,4);put(0x14b5f0b68,0,4)
    initialized=[];cases=[];values={0:11,1:0,10012:7,10020:9,0xffffffff:0xdeadbeef}
    for external in (False,True):
     for empty in (False,True):
        selected.clear();uc.mem_write(environment,b'\xa5'*0x1b0)
        if h.call(0x145d9c7c0)!=environment:raise ValueError('World factory result differs')
        put(environment+0x108,0xfeedbeef,4);put(environment+0x158,0xfeedbeef,4)
        h.call(0x145da3540,environment)
        if get(environment)!=0x149a3dac0 or get(environment+0x40,4)!=0 or get(environment+0x44,4)!=0:
            raise ValueError('Derived initialization world fields differ')
        if get(environment+0x30,1)!=7 or get(environment+0x108,4)!=0 or get(environment+0x158,4)!=0 or selected!=[0]:
            raise ValueError('Derived initialization phase/fields/selection differ')
        initialized.append(dict(external_buckets=external,empty_counts=empty,phase=7,selected=selected.copy()))
        # Source singleton/header remain intact. Only the bounded synthetic map fields change.
        put(singleton+0x18,entries);put(singleton+0x20,len(values),4)
        put(singleton+0x4c,len(values) if empty else 0,4)
        count=8 if external else 2;bucket_base=buckets if external else singleton+0x50
        put(singleton+0x58,buckets if external else 0);put(singleton+0x60,count,4)
        uc.mem_write(bucket_base,b'\xff'*(count*4));uc.mem_write(entries,bytes(len(values)*0x158))
        expected={}
        for i,(key,value) in enumerate(values.items()):
            row=entries+i*0x158;bucket=bucket_base+(key&(count-1))*4
            put(row,key,4);put(row+0x150,get(bucket,4),4);put(bucket,i,4)
            put(row+8+0xc,value,4);expected[key]=row+8
        immutable=[(a,bytes(uc.mem_read(a,n))) for a,n in
            ((singleton,0x68),(entries,len(values)*0x158),(bucket_base,count*4))]
        for key in (0,1,10012,10020,0xffffffff,2,10028):
            uc.mem_write(handle,b'\xa5'*16);uc.reg_write(x.UC_X86_REG_RDX,key)
            returned=h.call(0x145c79950,handle)
            pointer=expected.get(key,0) if not empty else 0
            if returned!=handle or get(handle,4)!=key or get(handle+8)!=pointer:
                raise ValueError('Native world handle/key/hash lookup differs')
            put(environment+0x40,key,4);put(environment+0x44,0xabcdef,4)
            result=h.call(0x145da1d40,environment)&0xffffffff
            if result!=(values[key] if pointer else 0):raise ValueError('Derived B8/native hash composition differs')
            if any(bytes(uc.mem_read(a,len(v)))!=v for a,v in immutable):raise ValueError('Native lookup mutated map input')
            cases.append(dict(external_buckets=external,empty_counts=empty,key=key,found=bool(pointer),field_0c=result))
    audit=load('audit-client-release')
    report=dict(source_sha256=SHA,tool_sha256=audit.sha256(Path(__file__)),exports=h.evidence,
        singleton=hex(singleton),lookup_leaf=LOOKUP,lookup_stride=0x158,lookup_value_offset=8,
        initialized=initialized,cases=cases,native_execution=True,network_used=False,action_admitted=False,
        limits=['Native provider in initialized TLS mode, handle wrapper, complete bounded hash leaf, derived B8 and derived/base initialization execute.',
            'Allocator, registry and initialization selection callback are fixtures; table rows/buckets/record+0C are synthetic.',
            'No CSV row loader/record field naming proof, no real manager population, no phase transition after ID204 or live quest action.',
            'Only source11316; no installed11318 admission or automatic reconnect.'])
    path=audit.save_snapshot(h.root/'code-clues/quest-world-record-11316',report)
    return path,report


if __name__=='__main__':
    path,result=run();print(json.dumps(dict(artifact=str(path),cases=len(result['cases']))))
