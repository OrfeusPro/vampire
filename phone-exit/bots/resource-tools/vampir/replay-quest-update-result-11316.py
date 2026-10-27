"""Whole ID1811 outer/nested readers/writers; bounded primitive archive fixtures."""
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
    audit=load('audit-client-release');path=HERE/'knowledge/native-contexts/quest-update-result-11316.json'
    c=json.loads(path.read_text('utf-8'))
    h=load('native-request-harness-11316').make_harness(c['exports'],{int(a,16) for a in c['functions']},
        leaves={int(a,16):b for a,b in c['leaves'].items()})
    index=load('knowledge-index')
    if h.sha!=c['source_sha256'] or any(not f.get('block_coverage_complete') or index.missing_conditional_fallthroughs(f['instructions']) for f in h.fragments):
        raise ValueError('Quest result source/coverage changed')
    for table,slots in ((0x149965728,{0x10:0x1458370b0,0x20:0x14582bce0,0x28:0x1458344b0}),
            (0x149948b40,{0x10:0x1457ab0a0,0x20:0x1457a6750})):
        for slot,target in slots.items():
            if struct.unpack_from('<Q',h.raw,h.image.offset(table+slot-h.image.pe.base))[0]!=target:raise ValueError('Reply virtual binding changed')
    uc,x,base=h.uc,h.x,h.scratch;packet,archive,table=base+0x1000,base+0x2000,base+0x3000
    state={};reads=[];writes=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,n,size=8):uc.mem_write(at,int(n).to_bytes(size,'little'))
    def get(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def read(size):
        def operation(machine):
            if reg('RCX')!=archive:raise ValueError('Reply reader archive changed')
            at=state['at'];reads.append(size)
            if state.get('fail')==len(reads) or len(state['raw'])-at<size:h.finish(0);return
            uc.mem_write(reg('RDX'),state['raw'][at:at+size]);state['at']+=size;h.finish(1)
        return operation
    def write(size):
        def operation(machine):
            if reg('RCX')!=archive:raise ValueError('Reply writer archive changed')
            writes.append(size)
            if state.get('fail')==len(writes):h.finish(0);return
            state['out']+=(reg('RDX')% (1<<(size*8))).to_bytes(size,'little');h.finish(1)
        return operation
    for i,(slot,size) in enumerate(((0x58,4),(0x50,8),(0x78,1),(0x80,1))):
        callback=base+0x4000+i*16;put(table+slot,callback);h.add_fixture(callback,read(size))
    for i,(slot,size) in enumerate(((0xc0,4),(0x48,8),(0xe0,1),(0xe8,1),(0xb8,8))):
        callback=base+0x5000+i*16;put(table+slot,callback);h.add_fixture(callback,write(size))
    put(archive,table)
    def construct():
        uc.mem_write(packet-16,b'A'*16+b'\xcc'*0x48+b'B'*16);h.call(0x145828b50,packet)
        if (get(packet),get(packet+0x10,4),get(packet+0x18),get(packet+0x20,1),get(packet+0x28),get(packet+0x30,1),get(packet+0x38),get(packet+0x40))!=(0x149965728,0,0,0,0x149948b40,0,0,0):
            raise ValueError('Reply constructor defaults changed')
    def guards():
        if bytes(uc.mem_read(packet-16,16))!=b'A'*16 or bytes(uc.mem_read(packet+0x48,16))!=b'B'*16:raise ValueError('Reply object guards changed')
    cases=[]
    for result,key,outer,inner,a,b in itertools.product((0,10,0xffffffff),(0,110120,0xffffffffffffffff),(0,2,6,7,255),(0,5,31,32,255),(0,0xffffffffffffffff),(0,123)):
        raw=struct.pack('<IQBBQQ',result,key,outer,inner,a,b);construct();state.clear();state.update(raw=raw,at=0,fail=None);reads.clear()
        uc.reg_write(x.UC_X86_REG_RDX,archive)
        if h.call(0x14582bce0,packet)&255!=1 or state['at']!=30 or reads!=[4,8,1,1,8,8]:raise ValueError('Reply read sequence changed')
        expected=(result,key,min(outer,6),inner,a,b)
        actual=(get(packet+0x10,4),get(packet+0x18),get(packet+0x20,1),get(packet+0x30,1),get(packet+0x38),get(packet+0x40))
        if actual!=expected:raise ValueError('Reply fields/clamps changed '+repr((actual,expected)))
        state.update(out=b'',fail=None);writes.clear();uc.reg_write(x.UC_X86_REG_RDX,archive)
        if h.call(0x1458370b0,packet)&255!=1 or state['out']!=struct.pack('<IQBBQQ',*expected) or writes!=[4,8,1,1,8,8]:raise ValueError('Reply write sequence changed')
        guards();cases.append(dict(input=[result,key,outer,inner,a,b],decoded=list(actual)))
    raw=struct.pack('<IQBBQQ',0,110120,2,0,0,0);short=[]
    for n in range(30):
        construct();state.clear();state.update(raw=raw[:n],at=0,fail=None);reads.clear();uc.reg_write(x.UC_X86_REG_RDX,archive)
        if h.call(0x14582bce0,packet)&255:raise ValueError('Reply truncated input accepted')
        guards();short.append(dict(bytes=n,consumed=state['at'],attempted=reads.copy()))
    failures=[]
    for mode in ('read','write'):
      for failure in range(1,7):
        construct();state.clear();state.update(raw=raw,at=0,out=b'',fail=failure);reads.clear();writes.clear();uc.reg_write(x.UC_X86_REG_RDX,archive)
        if h.call(0x14582bce0 if mode=='read' else 0x1458370b0,packet)&255:raise ValueError('Reply primitive failure ignored')
        if len(reads if mode=='read' else writes)!=failure:raise ValueError('Reply continued after primitive failure')
        guards();failures.append(dict(mode=mode,failed_primitive=failure))
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),exports=h.evidence,
        packet_id=1811,wire_bytes=30,wire_format='<IQBBQQ',cases=cases,truncated=short,failures=failures,
        native_execution=True,network_used=False,action_confirmation_admitted=False,limits=c['limits'])
    target=audit.save_snapshot(h.root/'code-clues/quest-update-result-11316',report);return target,report


if __name__=='__main__':
    target,result=run();print(json.dumps(dict(artifact=str(target),cases=len(result['cases']),short=len(result['truncated']),failures=len(result['failures'])),ensure_ascii=False))
