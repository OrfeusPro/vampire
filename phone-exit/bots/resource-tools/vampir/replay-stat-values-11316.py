"""Current stat record reader and application; explicit archive/setter fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
ROOT=Path('F:/PhoneExit Resources/Vampir')
SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
READER,APPLY,SET=0x1457a8030,0x145d8b830,0x1455f10f0


def verify():
    exports=json.loads((HERE/'knowledge/native-contexts/stat-values-exports-11316.json').read_text('utf-8'))
    spec=importlib.util.spec_from_file_location('stat_harness',HERE/'native-request-harness-11316.py')
    harness=importlib.util.module_from_spec(spec);spec.loader.exec_module(harness)
    h=harness.make_harness(exports,{READER,APPLY})
    uc,x=h.uc,h.x
    record,archive,table,array,items,model=[h.scratch+n for n in (0x1000,0x2000,0x3000,0x4000,0x5000,0x8000)]
    state={};writes=[];cases=[]
    def scalar(machine,size):
        target=machine.reg_read(x.UC_X86_REG_RDX)
        if not record<=target<=record+32-size:raise ValueError('Stat fixture write bounds')
        at=state['cursor'];end=at+size
        if end>len(state['body']):h.finish(0);return
        uc.mem_write(target,state['body'][at:end]);state['cursor']=end;h.finish(1)
    for slot,size in ((0x58,4),(0x50,8)):
        target=h.scratch+0x10000+slot
        h.add_fixture(target,lambda machine,size=size:scalar(machine,size))
        uc.mem_write(table+slot,struct.pack('<Q',target))
    uc.mem_write(archive,struct.pack('<Q',table))
    def capture(machine):
        if machine.reg_read(x.UC_X86_REG_RCX)!=model:raise ValueError('Wrong model receiver')
        stat=machine.reg_read(x.UC_X86_REG_RDX)&0xffffffff
        bits=machine.reg_read(x.UC_X86_REG_R8)
        signed=bits if bits<2**63 else bits-2**64
        writes.append((stat,signed));h.finish()
    h.add_fixture(SET,capture)
    samples=[(3,999,12),(4,0,0),(5,-999,1500),(9,2**63-1,42),(10,-2**63,2**63-1),(4,99,-1)]
    for sample in samples:
        body=struct.pack('<iqq',*sample)
        for size in range(21):
            uc.mem_write(record,b'\xaa'*32)
            state.update(body=body[:size],cursor=0)
            uc.reg_write(x.UC_X86_REG_RDX,archive)
            accepted=bool(h.call(READER,record)&255)
            if accepted!=(size==20):raise ValueError('Native stat record boundary differs')
            if accepted:
                actual=(struct.unpack('<i',bytes(uc.mem_read(record+8,4)))[0],
                    struct.unpack('<q',bytes(uc.mem_read(record+0x10,8)))[0],
                    struct.unpack('<q',bytes(uc.mem_read(record+0x18,8)))[0])
                if actual!=sample:raise ValueError('Native stat record fields differ')
            cases.append(dict(kind='reader',sample=list(sample),size=size,accepted=accepted))
    for values in ([],samples[:1],samples,samples+[samples[0]]):
        uc.mem_write(array,struct.pack('<Qii',items,len(values),len(values)))
        for index,(stat,first,second) in enumerate(values):
            uc.mem_write(items+32*index,struct.pack('<Qi4xqq',0,stat,first,second))
        writes.clear();uc.reg_write(x.UC_X86_REG_RDX,array)
        h.call(APPLY,model)
        expected=[(stat,second) for stat,first,second in values]
        if writes!=expected:raise ValueError('Native stat apply does not use second value in order')
        cases.append(dict(kind='apply',records=len(values),writes=list(writes)))
    report=dict(source_sha256=SHA,exports=h.evidence,cases=cases,network_used=False,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        limits=['Actual current stat record reader and array application instructions execute.',
            'Archive scalar IO, target model setter and storage are explicit fixtures.',
            'Outer ID322 array framing, registration, entity lookup and UI/display units are not replayed.',
            'Type134 special scaling is outside this fixture set. No runtime profile or HP/MP integration enabled.'])
    spec=importlib.util.spec_from_file_location('stat_audit',HERE/'audit-client-release.py')
    audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
    path=audit.save_snapshot(ROOT/'code-clues/stat-values-11316',report)
    return dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(cases))


if __name__=='__main__':print(json.dumps(verify()))
