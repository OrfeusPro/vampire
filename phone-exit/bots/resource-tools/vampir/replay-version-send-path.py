"""Native Version wrapper/send-B/writer/frame/queue path with bounded fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,HERE/filename)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
send=module('version_send_b','build-headless-send-b.py')
writer=module('version_writer_source','replay-version-packet-writer.py')
native,x=send.native,send.x
WRAPPER,THUNK,LOWER=0x1467aaa10,0x144aab2f0,0x144aaccf0
DISABLE,FILTER=0x14b520cb4,0x14b520db0


class Emulator(send.SendBEmulator):
    alloc=writer.Emulator.alloc

    def __init__(self):
        super().__init__()
        w=writer.Emulator()
        self.extra=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in (WRAPPER,0x1456e3a10)})
        self.ranges.extend(w.ranges)
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.extra)
        self.leaves_extra=[]
        for address,length in ((THUNK,9),(0x141448600,6)):
            off=self.image.offset(address-self.image.pe.base);content=self.raw[off:off+length]
            self.leaves_extra.append(dict(address=address,file_offset=off,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest()))
            self.ranges.append((address,address+length))
        if self.leaves_extra[0]['bytes']!='488b4910e9f7190000':raise ValueError('Version lower-send thunk changed')
        self.fixture_hooks={0x1414311c0,0x1468e4100,0x14147d580,0x14142c480,0x148796040}
        self.path_hooks={0x141420f70,0x14597e370,0x141493d10,0x14420a250,0x141489380,
            0x141489340,0x14142d840,0x141424430,0x144aad0a0,0x144aa6320}
        fragments=self.extra+w.writer_fragments+self.send_fragments
        refs=[a for f in fragments for r in f['instructions'] for a in r['rip_references']]
        pages={p for begin,end in self.ranges for p in range(begin&~4095,(end+4095)&~4095,4096)}
        pages.update(a&~4095 for a in (*refs,*self.path_hooks,*self.fixture_hooks,DISABLE,FILTER,0x1498d6990))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])
        self.writer_fragments=w.writer_fragments;self.encoder_leaf=w.encoder_leaf
        self.events=[]

    def hook(self,uc,address,size,user):
        if address in (WRAPPER,THUNK,LOWER,writer.WRITER):
            self.events.append(dict(action='native_entry',address=address))
        if address in self.fixture_hooks or address==writer.ping.MEMCPY:
            return writer.Emulator.hook(self,uc,address,size,user)
        if address in self.path_hooks:
            a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
            result=0
            if address==0x141420f70:
                data=bytearray()
                for n in range(64):
                    value=bytes(uc.mem_read(b+n,1))
                    if value==b'\0':break
                    data.extend(value)
                else:raise ValueError('Packet name fixture bound')
                if data!=b'PktVersion':raise ValueError('Version send name changed')
                text=data.decode('ascii');payload=text.encode('utf-16le')+b'\0\0';p=self.alloc(len(payload))
                uc.mem_write(p,payload);uc.mem_write(a,struct.pack('<QII',p,len(text)+1,len(text)+1));result=a
                self.events.append(dict(action='packet_name_constructor_fixture',name=text))
            elif address==0x14597e370:
                uc.mem_write(a,b'\0'*16)
                self.events.append(dict(action='packet_metadata_lookup_capture'))
            elif address==0x141493d10:
                result=self.metadata if self.fixture['metadata_present'] else 0
            elif address==0x14420a250:result=self.fixture['raw_mode']
            elif address==0x141489380:result=1
            elif address==0x141489340:raise ValueError('Unexpected secondary predicate fixture')
            elif address==0x14142d840:uc.mem_write(a,b'\0'*16)
            elif address==0x141424430:pass
            elif address==0x144aad0a0:
                if a!=self.scratch+0x4000 or b:raise ValueError('Send failure helper args changed')
                self.events.append(dict(action='send_failure_helper_capture'))
            elif address==0x144aa6320:self.events.append(dict(action='archive_cleanup_capture'))
            uc.reg_write(x.UC_X86_REG_RAX,result)
            rsp=uc.reg_read(x.UC_X86_REG_RSP);ret=int.from_bytes(uc.mem_read(rsp,8),'little')
            uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,ret);return
        super().hook(uc,address,size,user)
        if address in (0x144aace88,0x144aacee8):
            rbp=uc.reg_read(x.UC_X86_REG_RBP);archive=rbp-9 if address==0x144aace88 else rbp-0x49
            buffer=self.scratch+(0x8000 if address==0x144aace88 else 0x9000)
            uc.mem_write(archive+0x18,struct.pack('<QQQ',buffer,buffer,buffer+4096))
            uc.mem_write(archive+0x30,struct.pack('<III',4096,0,0))

    def execute(self,packet_fields,fixture):
        self.fixture=fixture;self.events=[];self.heap=self.scratch+0x10000
        self.copy_sizes=[];self.io_entries=[];self.queue_calls=self.wake_calls=0
        b=self.scratch;packet,wrapper,peer,queue=b+0x1000,b+0x3000,b+0x4000,b+0xa000
        self.uc.mem_write(packet,b'\0'*0xd0);self.uc.mem_write(packet,struct.pack('<Q',0x1498d6990))
        for offset,text in zip(writer.STRING_OFFSETS,packet_fields['strings']):
            data=text.encode('utf-16le')+b'\0\0';p=self.alloc(len(data));self.uc.mem_write(p,data)
            self.uc.mem_write(packet+offset,struct.pack('<QII',p,len(data)//2,len(data)//2))
        for offset,value in zip((0x20,0x98,0xc0),packet_fields['integers']):self.uc.mem_write(packet+offset,struct.pack('<I',value))
        self.uc.mem_write(wrapper+0x10,struct.pack('<Q',peer));self.uc.mem_write(peer,b'\0'*0x400)
        self.uc.mem_write(peer+0x108,struct.pack('<I',1));self.uc.mem_write(peer+0xc0,struct.pack('<I',int(not fixture['wake'])))
        self.uc.mem_write(peer+0x50,struct.pack('<Q',b+0x6000));self.uc.mem_write(b+0x6020,struct.pack('<Q',self.wake_address))
        self.uc.mem_write(peer+0x240,struct.pack('<H',fixture['sequence']));self.uc.mem_write(peer+0x248,struct.pack('<Q',fixture['key']))
        self.uc.mem_write(peer+0x2a5,bytes([fixture['special']]));self.uc.mem_write(peer+0x300,bytes([fixture['already_flag']]))
        self.uc.mem_write(DISABLE,bytes([fixture['disabled']]))
        self.uc.mem_write(FILTER,struct.pack('<Q',b+0xe000));self.uc.mem_write(b+0xe000,b'\0'*8)
        self.metadata=b+0xf000;self.uc.mem_write(self.metadata+0x18,bytes([fixture['metadata_byte']]))
        self.uc.mem_write(peer+0x178,struct.pack('<QQQ',queue,queue+1,queue+4096));self.uc.mem_write(queue,b'\0')
        stack=b+0x30000;stop=b+0x3f000;self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,wrapper),(x.UC_X86_REG_RDX,packet)):self.uc.reg_write(reg,value)
        self.uc.emu_start(WRAPPER,stop,count=200000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('Version full send budget')
        end=int.from_bytes(self.uc.mem_read(peer+0x180,8),'little')
        if not queue+1<=end<=queue+4096:raise ValueError('Version queue bounds')
        frame=bytes(self.uc.mem_read(queue,end-queue-1))
        self.uc.mem_write(b+0x9000,b'\xcc'*4096)
        if frame!=bytes(self.uc.mem_read(queue,len(frame))):raise ValueError('Version queue borrowed archive')
        return dict(fixture=fixture,packet_fields=packet_fields,frame_hex=frame.hex(),
            returned=self.uc.reg_read(x.UC_X86_REG_AL),sequence_after=int.from_bytes(self.uc.mem_read(peer+0x240,2),'little'),
            packet_byte_a=int.from_bytes(self.uc.mem_read(packet+0xa,1),'little'),queue_calls=self.queue_calls,
            wake_calls=self.wake_calls,events=self.events,queue_owns_bytes=True)


def build():
    path=native.ROOT/'code-clues/version-packet-writer-replay.json';prior=json.loads(path.read_text('utf-8'))
    em=Emulator()
    if prior['sha256']!=em.bindings['sha256']:raise ValueError('Version send source mismatch')
    base=dict(sequence=0,key=0,wake=False,metadata_present=False,metadata_byte=7,disabled=False,raw_mode=0,special=False,already_flag=False)
    cases=[]
    for index,fields in enumerate(prior['cases']):
        f=dict(base,name=fields['name'],sequence=65535 if index%2 else 0,key=0x1020304050607080 if index%3 else 0,wake=bool(index%2),metadata_present=bool(index%2))
        cases.append(em.execute(fields,f))
    fields=prior['cases'][0]
    for f in (dict(base,name='disabled',disabled=True),dict(base,name='mode-two',raw_mode=2),
        dict(base,name='mode-two-already',raw_mode=2,already_flag=True),dict(base,name='special',special=True)):
        cases.append(em.execute(fields,f))
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        fragments=em.extra+em.send_fragments,writer_fragments=em.writer_fragments,leaves=em.leaves_extra,
        encoder_leaf=em.encoder_leaf,frame_leaves=em.send_leaves,
        cases=cases,native_execution=True,network_ready=False,
        limitations=['Actual Version wrapper/thunk/send-B gates/writer/frame/queue append execute together.',
            'Metadata lookup/predicates/name constructor/diagnostics/cleanup and allocators are bounded fixtures.',
            'Filter block explicitly zero, no packet-filter membership path; field semantics not inferred.',
            'Archives/queue capacity4096, no growth/failure; queue wake captured, no scheduler/drain/socket.',
            'Fields and keys synthetic snapshots; full connected callback not part of this replay.',
            'No server response/negotiation/Login, game launch/profile/process memory/credentials/network/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/version-send-path-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
