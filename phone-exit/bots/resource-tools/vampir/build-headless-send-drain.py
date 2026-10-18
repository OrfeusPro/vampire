"""Native queue drain/partial-send/error branches with verified ordinal import."""
import hashlib,importlib.util,json,os,struct
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('drain_listener',HERE/'build-headless-listener-loop.py')
listener=importlib.util.module_from_spec(spec);spec.loader.exec_module(listener)
native=listener.native;x=listener.x
DRAIN=0x1445e8b70


def ordinal_import(raw,image,target):
    pe=struct.unpack_from('<I',raw,60)[0]
    rva,size=struct.unpack_from('<II',raw,pe+24+112+8)
    start=image.offset(rva)
    for off in range(start,start+size-19,20):
        original,_,_,dll,first=struct.unpack_from('<IIIII',raw,off)
        if not dll:break
        index=(target-image.pe.base-first)//8
        if index<0 or index>65535 or target!=image.pe.base+first+index*8:continue
        for i in range(index+1):
            pos=image.offset((original or first)+i*8);value=struct.unpack_from('<Q',raw,pos)[0]
            if value==0:break
        else:
            if not value>>63:continue
            dp=image.offset(dll);end=raw.index(b'\0',dp)
            return dict(dll=raw[dp:end].decode('ascii'),ordinal=value&0xffff,
                        descriptor_offset=off,descriptor_bytes=raw[off:off+20].hex(),
                        thunk_offset=pos,thunk_bytes=raw[pos:pos+8].hex(),iat_address=target)
    raise ValueError('Ordinal import not found')


def verify_local_export(info):
    path=Path(os.environ['SystemRoot'])/'System32'/info['dll']
    raw=path.read_bytes();image=native.Image(raw)
    pe=struct.unpack_from('<I',raw,60)[0]
    rva,size=struct.unpack_from('<II',raw,pe+24+112)
    off=image.offset(rva)
    base,count,names,functions,name_table,ordinals=struct.unpack_from('<IIIIII',raw,off+16)
    index=info['ordinal']-base
    if not 0<=index<count:raise ValueError('Ordinal outside export table')
    for i in range(names):
        ordinal_index=struct.unpack_from('<H',raw,image.offset(ordinals)+i*2)[0]
        if ordinal_index!=index:continue
        nrva=struct.unpack_from('<I',raw,image.offset(name_table)+i*4)[0]
        np=image.offset(nrva);end=raw.index(b'\0',np)
        name=raw[np:end].decode('ascii')
        if name!='send':raise ValueError('Unexpected socket export')
        return dict(path=str(path),sha256=hashlib.sha256(raw).hexdigest(),name=name,
                    export_directory_offset=off,export_directory_bytes=raw[off:off+40].hex(),
                    ordinal_index_offset=image.offset(ordinals)+i*2,
                    ordinal_index_bytes=raw[image.offset(ordinals)+i*2:image.offset(ordinals)+i*2+2].hex(),
                    name_offset=np,name_bytes=raw[np:end+1].hex())
    raise ValueError('Export has no verified name')


class DrainEmulator(listener.ListenerEmulator):
    def __init__(self):
        super().__init__()
        self.drain_fragments=native.decode_ranges(self.image,
            {self.image.roots[self.image.containing(a)] for a in [DRAIN,0x1445e5ef0,0x1445e2af0]})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva'])
                           for f in self.drain_fragments)
        rows={i['address']:i for f in self.drain_fragments for i in f['instructions']}
        self.iat=rows[0x1445e8c0d]['rip_references'][0]
        self.import_proof=ordinal_import(self.raw,self.image,self.iat)
        if self.import_proof['dll'].lower()!='ws2_32.dll':raise ValueError('Unexpected socket DLL')
        self.export_proof=verify_local_export(self.import_proof)
        self.error_global=rows[0x1445e8c21]['rip_references'][0]
        table=rows[0x1445e2b7f]['rip_references'][0]
        off=self.image.offset(table-self.image.pe.base);data=self.raw[off:off+0x28]
        if struct.unpack_from('<Q',data,0x20)[0]!=DRAIN:raise ValueError('Wakeup vtable changed')
        self.wake_table=dict(address=table,file_offset=off,bytes=data.hex())
        pages={p for begin,end in self.ranges for p in range(begin&~4095,(end+4095)&~4095,4096)}
        pages.update(a&~4095 for a in [self.iat,self.error_global,0x1445de8b0,0x1445e5a50])
        regions=list(self.uc.mem_regions())
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in regions):continue
            self.uc.mem_map(page,4096)
            if page==(self.error_global&~4095):continue
            off=self.image.offset(page-self.image.pe.base);self.uc.mem_write(page,self.raw[off:off+4096])
        self.uc.mem_write(self.iat,struct.pack('<Q',self.scratch+0x3a000))
        self.uc.mem_write(self.error_global,struct.pack('<Q',self.scratch+0x5000))

    def hook(self,uc,address,size,user):
        b=self.scratch
        if address in [b+0x3a000,b+0x3b000,0x1445de8b0,0x1445e5a50]:
            rcx=uc.reg_read(x.UC_X86_REG_RCX)
            if address==b+0x3a000:
                pointer=uc.reg_read(x.UC_X86_REG_RDX);count=uc.reg_read(x.UC_X86_REG_R8)
                if rcx!=7 or pointer!=b+0xa000 or count!=len(self.payload) or uc.reg_read(x.UC_X86_REG_R9)!=0:
                    raise ValueError('send arguments changed')
                self.send_calls.append(bytes(uc.mem_read(pointer,count)).hex())
                uc.reg_write(x.UC_X86_REG_RAX,self.send_result&0xffffffff)
            elif address==b+0x3b000:
                if rcx!=b+0x5000:raise ValueError('Error query owner changed')
                uc.reg_write(x.UC_X86_REG_RAX,self.error_code)
            elif address==0x1445de8b0:
                if rcx!=self.owner:raise ValueError('Diagnostic owner changed')
                self.diagnostics+=1
            else:
                if rcx!=self.owner:raise ValueError('Close owner changed')
                self.close_requested=True
            self.ret(uc);return
        super().hook(uc,address,size,user)

    def execute_drain(self,payload,result,error=22,socket_present=True):
        if len(payload)>2048 or result < -1 or result>len(payload):raise ValueError('Fixture bounds')
        self.payload=payload;self.send_result=result;self.error_code=error
        self.send_calls=[];self.close_requested=False;self.diagnostics=0
        self.copy_sizes=[];self.io_entries=[];self.snapshot_count=self.cleanup_count=self.free_count=self.expired_count=0
        self.listener_count=0;self.owner=self.scratch+0x4000
        b=self.scratch;uc=self.uc;peer=self.owner;queue=b+0xa000
        uc.mem_write(peer,bytes(0x300))
        uc.mem_write(peer+0x148,struct.pack('<I',7 if socket_present else 0))
        uc.mem_write(peer+0x178,struct.pack('<QQQ',queue,queue+len(payload)+(1 if payload else 0),queue+4096))
        uc.mem_write(queue,payload+b'\0')
        uc.mem_write(b+0x5000,struct.pack('<Q',b+0x5100))
        uc.mem_write(b+0x5168,struct.pack('<Q',b+0x3b000))
        self.call(DRAIN,peer+0x50,peer+0x110)
        end=struct.unpack('<Q',bytes(uc.mem_read(peer+0x180,8)))[0]
        count=end-queue-(1 if payload else 0)
        if not 0<=count<=len(payload):raise ValueError('Remaining queue outside bounds')
        return dict(payload_hex=payload.hex(),send_result=result,error_code=error,socket_present=socket_present,
                    send_calls=self.send_calls.copy(),remaining_hex=bytes(uc.mem_read(queue,count)).hex(),
                    close_requested=self.close_requested,diagnostics=self.diagnostics)


def main():
    emulator=DrainEmulator();cases=[]
    for size in [1,8,27,46,127,256]:
        payload=bytes(i&255 for i in range(size))
        for result in sorted({0,1,size-1,size}):
            case=emulator.execute_drain(payload,result)
            if case['remaining_hex']!=payload[result:].hex() or case['send_calls']!=[payload.hex()]:raise ValueError('Partial send differs')
            cases.append(case)
        for error in [22,23,37,0,1,38]:
            case=emulator.execute_drain(payload,-1,error)
            if case['remaining_hex']!=payload.hex() or case['close_requested']!=(error not in [22,23,37]):raise ValueError('Error policy differs')
            cases.append(case)
    for payload,socket_present in [(b'',True),(b'',False),(b'abc',False)]:
        case=emulator.execute_drain(payload,0,socket_present=socket_present)
        if case['send_calls'] or case['remaining_hex']!=payload.hex():raise ValueError('Empty/no socket behavior differs')
        cases.append(case)
    report=dict(schema_version=1,source=emulator.bindings['source'],sha256=emulator.bindings['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),fragments=emulator.drain_fragments,
                socket_import=emulator.import_proof,local_export=emulator.export_proof,wake_table=emulator.wake_table,
                cases=cases,statistics=dict(native_drain_cases=len(cases)),network_ready=False,
                limitations=['Native drain/partial-compaction and actual wake vtable linkage executed/verified.',
                'Winsock send and error-query results simulated; no system socket called by native emulator.',
                'No listeners: snapshot fixtures inherited; fatal diagnostic/close captured without executing whole shutdown.',
                'Error integers22/23/37 observed, engine enum names not established; zero send leaves queue unchanged.',
                'Connection startup, scheduling, reconnect and live game transport unresolved.'])
    path=native.ROOT/'code-clues/headless-send-drain.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(dict(output=str(path),**report['statistics'],socket_export=emulator.export_proof['name'],network_ready=False)))


if __name__=='__main__':main()
