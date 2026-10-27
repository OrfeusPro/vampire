"""Registered1811 result gate -> progress projection -> model virtual application."""
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def run():
    audit=load('audit-client-release');path=HERE/'knowledge/native-contexts/quest-result-application-11316.json'
    c=json.loads(path.read_text('utf-8'));h=load('native-request-harness-11316').make_harness(c['exports'],{int(a,16) for a in c['functions']},leaves={int(a,16):v for a,v in c['leaves'].items()})
    if h.sha!=c['source_sha256'] or any(not f.get('block_coverage_complete') or load('knowledge-index').missing_conditional_fallthroughs(f['instructions']) for f in h.fragments):raise ValueError('Result application coverage/source changed')
    # Explicit local registration window; no fabricated whole-root export.
    native=load('build-native-entry-code');decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
    start,end=0x1467ba0b0,0x1467ba0e9;offset=h.image.offset(start-h.image.pe.base);raw=h.raw[offset:offset+end-start]
    rows=list(decoder.disasm(raw,start))
    expected={0x1467ba0b0:'488d05c1ef6003',0x1467ba0b7:'488907',0x1467ba0bf:'b948000000',0x1467ba0d1:'e87aea06ff',0x1467ba0db:'4c8bc7',0x1467ba0de:'488bd0',0x1467ba0e1:'488bce',0x1467ba0e4:'e8d7150100'}
    by_address={i.address:bytes(i.bytes).hex() for i in rows}
    if sum(i.size for i in rows)!=len(raw) or any(by_address.get(a)!=b for a,b in expected.items()):raise ValueError('1811 registration window changed')
    table=0x149dc9078;slots=struct.unpack_from('<3Q',h.raw,h.image.offset(table-h.image.pe.base))
    if slots!=(0x1414096c0,0x14153b9d0,0x1467b27a0):raise ValueError('Registered handler table changed')
    uc,x,base=h.uc,h.x,h.scratch;packet,model,model_table,record,setting,wrapper=[base+n for n in (0x1000,0x2000,0x3000,0x4000,0x5000,0x6000)]
    calls=[];current={};applied=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,n,size=8):uc.mem_write(at,(int(n)%(1<<(8*size))).to_bytes(size,'little'))
    def get(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def projection(machine):
        if reg('RDX')!=current['key'] or reg('R8')!=packet+0x28:raise ValueError('1811 progress projection arguments changed')
        result=bytearray(32);struct.pack_into('<QBBII',result,0,current['task_id'],6,current['index'],0,0)
        # Projection's counters live at +C/+10; padding +A/+B and +14..17 stay explicit zeros here.
        struct.pack_into('<II',result,12,current['first']&0xffffffff,current['second']&0xffffffff)
        uc.mem_write(reg('RCX'),bytes(result));current['projected']=bytes(result);calls.append('project');h.finish(reg('RCX'))
    def lookup(machine):
        if reg('RCX')!=model or reg('RDX')!=current['key']:raise ValueError('1811 lookup key changed')
        calls.append('lookup');h.finish(record if current['existing'] else 0)
    def make_record(machine):
        if reg('RDX')!=current['key']:raise ValueError('1811 new record key changed')
        put(reg('RCX'),current['key']);calls.append('new-record');h.finish(reg('RCX'))
    def application(kind):
        def callback(machine):
            if reg('RCX')!=model or reg('R8')&255!=current['state'] or get(reg('RSP')+0x28,1)!=1:raise ValueError('1811 model state/flag changed')
            if bytes(uc.mem_read(reg('R9'),32))!=current['projected']:raise ValueError('1811 projected progress changed')
            if kind=='existing' and reg('RDX')!=record:raise ValueError('1811 existing receiver changed')
            if kind=='new' and get(reg('RDX'))!=current['key']:raise ValueError('1811 new wrapper changed')
            calls.append('apply:'+kind);applied.append(dict(kind=kind,key=current['key'],state=current['state'],index=current['index'],flag=1));h.finish()
        return callback
    def error(machine):
        if reg('RCX')&0xffffffff!=current['result'] or reg('RDX')&0xffffffff!=0:raise ValueError('1811 error presentation arguments changed')
        calls.append('error');h.finish()
    def free(machine):raise ValueError('Unexpected nonempty allocation in1811 gate')
    callbacks={0x145594db0:lambda machine:h.finish(setting),0x145fd3ee0:error,0x145de4610:projection,
        0x1455bbcb0:lookup,0x145de3790:make_record,0x141483080:free,base+0x7000:application('new'),base+0x7010:application('existing')}
    for a,callback in callbacks.items():h.add_fixture(a,callback)
    page=0x149965000
    if not any(start<=page and end>=page+4095 for start,end,_ in uc.mem_regions()):
        uc.mem_map(page,4096);offset=h.image.offset(page-h.image.pe.base);uc.mem_write(page,h.raw[offset:offset+4096])
    put(model_table+0x48,base+0x7000);put(model_table+0x50,base+0x7010);put(0x14b5e4d60,model)
    cases=[]
    for code,special,existing,key,state,index in itertools.product((0,10,0xffffffff,0x1197),(False,True),(False,True),(110120,0xffffffffffffffff),(0,2,6),(0,5)):
        current.clear();current.update(result=code,existing=existing,key=key,state=state,index=index,task_id=110120005 if index==0 else 110120070,first=0x1234567800000001,second=0x8765432100000002)
        calls.clear();applied.clear();uc.mem_write(packet-16,b'A'*16+bytes(0x48)+b'B'*16);put(packet,0x149965728);put(packet+0x10,code,4);put(packet+0x18,key);put(packet+0x20,state,1);put(packet+0x28,0x149948b40);put(packet+0x30,index,1);put(packet+0x38,current['first']);put(packet+0x40,current['second'])
        uc.mem_write(model,bytes(0x100));put(model,model_table);uc.mem_write(record,bytes(0x60));uc.mem_write(setting,bytes(16));put(setting+8,int(special),1)
        immutable=[(at,bytes(uc.mem_read(at,n))) for at,n in ((packet-16,0x68),(model,0x100),(record,0x60),(setting,16))]
        uc.reg_write(x.UC_X86_REG_RDX,0);uc.reg_write(x.UC_X86_REG_R8,packet);h.call(0x1467b27a0,wrapper,budget=100000)
        accepted=code==0 or code==0x1197 and not special
        expected_calls=(['error'] if not special and code!=0 else [])+(['project','lookup']+([] if existing else ['new-record'])+['apply:existing' if existing else 'apply:new'] if accepted else [])
        if calls!=expected_calls or bool(applied)!=accepted:raise ValueError('1811 gate/application branch changed '+repr((code,special,calls,expected_calls)))
        if any(bytes(uc.mem_read(at,len(v)))!=v for at,v in immutable):raise ValueError('1811 handler mutated packet/model fixture inputs')
        cases.append(dict(result=code,special_gate=special,existing=existing,key=key,state=state,index=index,applied=applied.copy(),calls=calls.copy()))
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),exports=h.evidence,
        registration=dict(start=hex(start),end=hex(end),bytes=raw.hex(),handler_table=hex(table),handler_slots=[hex(v) for v in slots]),
        cases=cases,native_execution=True,network_used=False,action_confirmation_admitted=False,limits=c['limits'])
    target=audit.save_snapshot(h.root/'code-clues/quest-result-application-11316',report);return target,report


if __name__=='__main__':
    target,result=run();print(json.dumps(dict(artifact=str(target),cases=len(result['cases'])),ensure_ascii=False))
