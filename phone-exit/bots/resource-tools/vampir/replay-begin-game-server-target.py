"""Native BeginGameImpl server ID/lookup and transport target setters; no connection."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('server_dispatch',HERE/'replay-sdk-result-dispatch.py')
dispatch=importlib.util.module_from_spec(spec);spec.loader.exec_module(dispatch)
native,x=dispatch.native,dispatch.x
BEGIN=0x146425730
STOPS={0x146425a7d:'target_setters_completed',0x14642589c:'server_missing',
       0x146425b28:'already_busy',0x146425b30:'zero_id_selection_branch'}
SPANS={0x145d39440:0xaa,0x144aab510:11,0x144aab500:16,0x144aab520:12,0x144aab4f0:12}


class Replay(dispatch.Replay):
    def __init__(self,raw,image,fragments,spans,fixture):
        super().__init__(raw,image,fragments,dict(bound=False,refcounted=False,execute_ok=False))
        self.fixture=fixture
        rows=[r for f in fragments if f['root_begin_rva']==0x6425730 for r in f['instructions']]
        rows += [r for span in spans for r in span['instructions']]
        self.allowed={r['address'] for r in rows}
        self.targets={0x14142d840,0x141424430,0x14147d580,0x145d37270,0x14563d980,0x145636eb0,
                      0x144aa8880,0x145d44eb0,0x145d45030,0x145d37220,0x144aaa9d0,0x14143c260,0x300000e0}
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in self.targets)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.master,self.busy,self.wrapper,self.transport,self.generic,self.title=(self.allocate(n) for n in (0x400,0x100,0x40,0x300,0x100,0x1000))
        self.uc.mem_write(self.master+0x308,struct.pack('<I',fixture['last_id']))
        entries=self.allocate(max(128,len(fixture['records'])*128));buckets=self.allocate(16)
        count=len(fixture['records'])
        self.uc.mem_write(self.master+0x88,struct.pack('<Q',entries))
        self.uc.mem_write(self.master+0x90,struct.pack('<I',count))
        self.uc.mem_write(self.master+0xbc,struct.pack('<I',fixture.get('free_count',0)))
        self.uc.mem_write(self.master+0xc8,struct.pack('<Q',buckets))
        self.uc.mem_write(self.master+0xd0,struct.pack('<I',1))
        self.uc.mem_write(buckets,struct.pack('<i',0 if count else -1))
        for n,record in enumerate(fixture['records']):
            entry=entries+n*128;value=entry+8
            self.uc.mem_write(entry,struct.pack('<I',record['id']))
            self.string(value+0x20,record['text'])
            self.uc.mem_write(value+0x30,struct.pack('<HH',record['word_30'],record['word_32']))
            self.uc.mem_write(entry+0x78,struct.pack('<i',n+1 if n+1<count else -1))
        self.uc.mem_write(self.busy+0x38,bytes([fixture['busy']]))
        self.uc.mem_write(self.wrapper+0x10,struct.pack('<Q',self.transport))
        self.uc.mem_write(self.transport+0x270,struct.pack('<I',777))
        self.string(self.transport+0x278,'old-target-fixture')
        self.uc.mem_write(self.transport+0x288,struct.pack('<HH',111,222))
        self.uc.mem_write(self.generic,struct.pack('<Q',self.generic+0x40))
        self.uc.mem_write(self.generic+0x40+0x30,struct.pack('<Q',0x300000e0))
        self.uc.mem_write(0x14961a380,struct.pack('<I',fixture['invalid_id']))
        self.uc.mem_write(0x14b125534,struct.pack('<I',fixture['fallback_id']))
        self.uc.mem_write(0x14b520cc3,b'\0')
        self.events=[]

    def string(self,descriptor,value):
        data=(value+'\0').encode('utf-16le');ptr=self.allocate(len(data))
        self.uc.mem_write(ptr,data);self.uc.mem_write(descriptor,struct.pack('<QII',ptr,len(data)//2,len(data)//2))

    def text(self,descriptor):
        ptr,count,cap=struct.unpack('<QII',bytes(self.uc.mem_read(descriptor,16)))
        if not count:return ''
        if not 1<=count<=cap<=256:raise ValueError('Server string fixture bound')
        return bytes(self.uc.mem_read(ptr,count*2)).decode('utf-16le')[:-1]

    def hook(self,uc,address,size,user):
        if address in STOPS:uc.emu_stop();return
        if address in self.allowed:return
        a,b=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
        result=0
        if address==0x14142d840:uc.mem_write(a,b'\0'*16);result=a
        elif address in (0x141424430,0x14147d580):pass
        elif address==0x145d37270:result=self.master
        elif address in (0x14563d980,0x144aa8880):result=self.generic
        elif address==0x145636eb0:pass
        elif address in (0x145d44eb0,0x145d45030,0x300000e0):
            self.events.append(dict(action='zero_id_action_capture',target=address))
        elif address==0x145d37220:result=self.busy
        elif address==0x144aaa9d0:result=self.wrapper
        elif address==0x14143c260:
            self.string(a,self.text(b));result=a
            self.events.append(dict(action='target_string_assignment_fixture',value=self.text(b)))
        else:raise ValueError('Unexpected server target execution '+hex(address))
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture(self):
        self.uc.mem_write(self.stack,struct.pack('<Q',self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP,self.stack);self.uc.reg_write(x.UC_X86_REG_RCX,self.title)
        self.uc.emu_start(BEGIN,self.stop,count=4096)
        rip=self.uc.reg_read(x.UC_X86_REG_RIP)
        if rip not in STOPS:raise ValueError('BeginGame target budget '+hex(rip))
        return dict(fixture=self.fixture,stop=STOPS[rip],selected_id=self.uc.reg_read(x.UC_X86_REG_RSI)&0xffffffff,
                    busy_after=int.from_bytes(self.uc.mem_read(self.busy+0x38,1),'little'),
                    target_id=int.from_bytes(self.uc.mem_read(self.transport+0x270,4),'little'),
                    target_text=self.text(self.transport+0x278),
                    target_words=list(struct.unpack('<HH',bytes(self.uc.mem_read(self.transport+0x288,4)))),events=self.events)


def build():
    path=native.ROOT/'code-clues/entry-code.json'
    prior=json.loads(path.read_text('utf-8'));raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Server target source changed')
    image=native.Image(raw)
    fragments=native.decode_ranges(image,{image.roots[image.containing(a)] for a in (BEGIN,dispatch.DISPATCH)})
    cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
    spans=[]
    for address,size in SPANS.items():
        off=image.offset(address-image.pe.base);content=raw[off:off+size];rows=[]
        for i in cs.disasm(content,address):
            refs=[i.address+i.size+op.mem.disp for op in i.operands if op.type==native.capstone.x86_const.X86_OP_MEM and op.mem.base==native.capstone.x86_const.X86_REG_RIP]
            rows.append(dict(address=i.address,bytes=bytes(i.bytes).hex(),mnemonic=i.mnemonic,operands=i.op_str,rip_references=refs))
        if sum(len(bytes.fromhex(r['bytes'])) for r in rows)!=size:raise ValueError('Server leaf decode changed')
        spans.append(dict(address=address,file_offset=off,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest(),instructions=rows))
    literals=[]
    for f in fragments:
        for row in f['instructions']:
            for ref in row['rip_references']:
                if lit:=dispatch.completion.gates.fields.lifecycle.guid.source.config.read_literal(raw,image,ref):literals.append(dict(instruction=row['address'],**lit))
    record=dict(id=42,text='server-fixture.invalid',word_30=10001,word_32=20002)
    base=dict(last_id=42,invalid_id=0xffffffff,fallback_id=42,busy=False,records=[record])
    profiles=[dict(base,name='direct'),dict(base,name='fallback',last_id=0xffffffff),
              dict(base,name='missing-id',last_id=99),dict(base,name='empty-map',records=[]),
              dict(base,name='busy',busy=True),dict(base,name='zero-empty',last_id=0,records=[]),
              dict(base,name='zero-selection',last_id=0),
              dict(base,name='collision-second',records=[dict(record,id=1),record]),
              dict(base,name='collision-miss',last_id=3,records=[dict(record,id=1),record]),
              dict(base,name='word-boundaries',records=[dict(record,word_30=0,word_32=65535)]),
              dict(base,name='empty-text',records=[dict(record,text='')])]
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),entry_report_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                fragments=fragments,spans=spans,literals=literals,cases=[Replay(raw,image,fragments,spans,f).capture() for f in profiles],
                native_execution=True,network_ready=False,limitations=[
                    'Native BeginGameImpl selection/lookup/collision walk/busy gate and four target setters execute.',
                    'Map/server records/last ID/invalid sentinel/fallback globals are fixtures, not actual live configuration.',
                    'Source lookup returns map value entry+8; string assignment is bounded FString fixture.',
                    'Stops before connection/UI tail, missing-server dialog and zero-ID effects are captures.',
                    'Raw 16-bit fields retain offset names; actual endpoint/protocol roles not proven here.',
                    'No game launch/process memory/profile/credentials/HTTP or socket connect used.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/begin-game-server-target-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
