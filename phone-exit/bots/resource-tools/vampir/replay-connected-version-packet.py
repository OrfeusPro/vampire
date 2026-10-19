"""Native connected callback constructs PktVersion and reaches its send target."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('version_delegate',HERE/'replay-transport-connected-delegate.py')
delegate=importlib.util.module_from_spec(spec);spec.loader.exec_module(delegate)
native,x=delegate.native,delegate.x
GAME=delegate.GAME_RECIPIENT
CTOR,TABLE,SEND=0x1456d53b0,0x1498d6990,0x1467aaa10
VERSION_GLOBAL,ENUM_GLOBAL=0x14b14ae28,0x14b125530
TEXT_GLOBAL=0x14b520d10


class Replay(delegate.Replay):
    def __init__(self,*args,body_fragments,fixture):
        super().__init__(*args,fixture)
        rows=[r for f in body_fragments if f['root_begin_rva']+self.image_base in (GAME,CTOR) for r in f['instructions']]
        self.body_allowed={r['address'] for r in rows};self.allowed.update(self.body_allowed)
        self.body_hooks={0x144aaaac0,0x1445c77a0,0x1445bdfe0,0x1416d7af0,0x1415c3960,
            0x1414476a0,0x141420f70,0x141426250,0x141426180,0x1414313d0,
            0x1487a2e19,0x1445c63a0,0x14143c260,0x141421150,0x1413fe190,
            0x1456d5c30,SEND,0x14147d580}
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in (*self.body_hooks,TABLE,VERSION_GLOBAL,ENUM_GLOBAL,TEXT_GLOBAL))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=args[1].offset(page-self.image_base)
            except ValueError:continue
            self.uc.mem_write(page,args[0][off:off+4096])
        v=self.allocate(len(fixture['version_ascii'])+1)
        self.uc.mem_write(v,fixture['version_ascii'].encode('ascii')+b'\0')
        self.uc.mem_write(VERSION_GLOBAL,struct.pack('<Q',v))
        self.uc.mem_write(ENUM_GLOBAL,struct.pack('<I',fixture['raw_enum']))
        self.fwrite(TEXT_GLOBAL,fixture['global_text'])
        self.uc.mem_write(self.wrapper+0x160,struct.pack('<Q',123456))
        self.packet_capture=None

    image_base=0x140000000

    def fwrite(self,desc,text):
        data=text.encode('utf-16le')+b'\0\0' if text else b''
        ptr=self.allocate(len(data)) if data else 0
        if data:self.uc.mem_write(ptr,data)
        self.uc.mem_write(desc,struct.pack('<QII',ptr,len(data)//2,len(data)//2))

    def fread(self,desc):
        ptr,count,cap=struct.unpack('<QII',bytes(self.uc.mem_read(desc,16)))
        if not 0<=count<=cap<=512 or (count and not ptr):raise ValueError('Version FString fixture bounds')
        if not count:return ''
        data=bytes(self.uc.mem_read(ptr,count*2))
        if not data.endswith(b'\0\0'):raise ValueError('Version FString missing terminator')
        return data[:-2].decode('utf-16le')

    def hook(self,uc,address,size,user):
        if address==GAME:self.events.append(dict(action='native_game_connected_callback'))
        if address in self.body_allowed:return
        if address not in self.body_hooks:return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0
        if address==0x1445c77a0:result=self.fixture['context_selector']
        elif address==0x1445bdfe0:result=0  # Explicit absent context store branch.
        elif address==0x1416d7af0:raise ValueError('Unexpected present context store branch')
        elif address==0x1415c3960:self.fwrite(a,'context-fixture')
        elif address==0x1414476a0:self.fwrite(a,self.fixture['first_text'])
        elif address==0x141420f70:
            # Bounded ASCII constructor input; source prefix/global pointers
            # are inspected as data only. General conversion not implemented.
            data=bytearray()
            for offset in range(256):
                value=bytes(uc.mem_read(b+offset,1))
                if value==b'\0':break
                data.extend(value)
            else:raise ValueError('Version ASCII constructor bounds')
            text=data.decode('ascii');self.fwrite(a,text);result=a
            self.events.append(dict(action='ascii_fstring_constructor_fixture',text=text))
        elif address==0x141426250:self.fwrite(a,'combine-a-fixture');result=a
        elif address==0x141426180:self.fwrite(a,self.fixture['combined_text']);result=a
        elif address==0x1414313d0:
            if not 0<=b<=512:raise ValueError('Version string resize bound')
            count=int.from_bytes(uc.mem_read(a+8,4),'little')
            uc.mem_write(a,struct.pack('<QII',self.allocate(max(2,b*2)),count,b))
        elif address==0x1487a2e19:
            if not 0<=c<=1024:raise ValueError('Version memcpy bound')
            uc.mem_write(a,bytes(uc.mem_read(b,c)));result=a
        elif address==0x1445c63a0:self.fwrite(a,self.fixture['provider_text']);result=a
        elif address==0x14143c260:self.fwrite(a,self.fread(b));result=a
        elif address==0x141421150:self.fwrite(a,'')
        elif address in (0x144aaaac0,0x1413fe190,0x1456d5c30,0x14147d580):pass
        elif address==SEND:
            if a!=self.wrapper:raise ValueError('Version send wrapper changed')
            table=int.from_bytes(uc.mem_read(b,8),'little')
            if table!=TABLE:raise ValueError('Connected packet vtable changed')
            self.packet_capture=dict(vtable=table,
                strings={hex(o):self.fread(b+o) for o in (0x10,0x28,0x38,0x48,0x58,0x68,0x78,0x88,0xa0,0xb0)},
                raw_20=int.from_bytes(uc.mem_read(b+0x20,4),'little'),
                raw_98=int.from_bytes(uc.mem_read(b+0x98,4),'little'),
                raw_c0=int.from_bytes(uc.mem_read(b+0xc0,4),'little'))
            self.events.append(dict(action='version_send_capture',returned=self.fixture['send_return']))
            result=int(self.fixture['send_return'])
        else:raise ValueError('Unexpected version body fixture')
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=int.from_bytes(uc.mem_read(rsp,8),'little')
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture(self):
        result=super().capture()
        result.update(packet=self.packet_capture,wrapper_160_after=int.from_bytes(self.uc.mem_read(self.wrapper+0x160,8),'little'))
        return result


def build():
    path=native.ROOT/'code-clues/transport-connected-delegate-replay.json'
    prior=json.loads(path.read_text('utf-8'))
    notify=json.loads((native.ROOT/'code-clues/socket-ready-notification-replay.json').read_text('utf-8'))
    ready=json.loads((native.ROOT/'code-clues/socket-readiness-job-replay.json').read_text('utf-8'))
    opt=json.loads((native.ROOT/'code-clues/socket-error-option-replay.json').read_text('utf-8'))
    raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Version packet source changed')
    image=native.Image(raw)
    fragments=native.decode_ranges(image,{image.roots[image.containing(a)] for a in (GAME,CTOR,0x1456e3a10)})
    rows={r['address']:r for f in fragments for r in f['instructions']}
    if rows[0x1456d53b6]['rip_references']!=[TABLE] or rows[0x1456d53c0]['operands']!='qword ptr [rcx], rax':raise ValueError('Version ctor table binding changed')
    if rows[0x1467a9ddc]['operands']!=hex(CTOR):raise ValueError('Version caller constructor changed')
    if rows[0x1467a9fc4]['operands']!='qword ptr [rax + 0x38]':raise ValueError('Version caller send slot changed')
    # Confirm globals at instruction boundaries, not from offset similarity.
    for address,target in ((0x1456d542c,VERSION_GLOBAL),(0x1456d5438,ENUM_GLOBAL),(0x1467a9de8,TEXT_GLOBAL)):
        if rows[address]['rip_references']!=[target]:raise ValueError('Version input global binding changed')
    off=image.offset(TABLE-image.pe.base);table=raw[off:off+0x40]
    id_target=struct.unpack_from('<Q',table,0x28)[0];name_target=struct.unpack_from('<Q',table,0x38)[0]
    if (id_target,name_target)!=(0x141448600,0x1456e3a10):raise ValueError('Version name/id slots changed')
    io=image.offset(id_target-image.pe.base);id_bytes=raw[io:io+6]
    if id_bytes.hex()!='b801000000c3':raise ValueError('Version ID getter changed')
    name_address=rows[0x1456e3a19]['rip_references'][0];no=image.offset(name_address-image.pe.base)
    name_bytes=raw[no:raw.index(b'\0',no)+1]
    if name_bytes!=b'PktVersion\0':raise ValueError('Version packet name changed')
    wo=image.offset(delegate.GAME_TABLE-image.pe.base);wrapper_table=raw[wo:wo+0x50]
    if struct.unpack_from('<Q',wrapper_table,0x38)[0]!=SEND:raise ValueError('Version send table binding changed')
    base=dict(prior['cases'][0]['fixture'],version_ascii='0.0-fixture',raw_enum=2,global_text='global-fixture',
        first_text='first-fixture',combined_text='combined-fixture',provider_text='provider-fixture',context_selector=7,send_return=True)
    fixtures=[dict(base,name='version-default'),dict(base,name='empty-fields',global_text='',first_text='',combined_text='',provider_text='',version_ascii=''),
        dict(base,name='unicode-fields',global_text='Тест',first_text='Проверка',provider_text='Украина'),
        dict(base,name='send-false',send_return=False),dict(base,name='raw-enum-max',raw_enum=0xffffffff),
        dict(base,name='delegate-disabled',owner_count=0)]
    args=(raw,image,ready['fragments'],ready['completion_leaf'],ready['handle_leaf'],opt['option_body'],notify['fragments'],notify['leaves'],prior['fragments'],prior['leaves'])
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        fragments=fragments,packet_table=dict(address=TABLE,file_offset=off,bytes=table.hex(),sha256=hashlib.sha256(table).hexdigest()),
        packet_id=dict(address=id_target,file_offset=io,bytes=id_bytes.hex(),value=1),
        packet_name=dict(address=name_address,file_offset=no,bytes=name_bytes.hex(),name='PktVersion'),
        wrapper_table=dict(address=delegate.GAME_TABLE,file_offset=wo,bytes=wrapper_table.hex()),
        cases=[Replay(*args,body_fragments=fragments,fixture=f).capture() for f in fixtures],native_execution=True,network_ready=False,
        limitations=['Actual game callback and PktVersion constructor execute after native connection delegate.',
            'Version is identified by source ctor/vtable/name/ID; not PktLogin or a live negotiation.',
            'Context store absent branch only; text getters/combiners/copy/resize are bounded fixtures.',
            'Raw globals explicitly fixture-assigned; semantic names of packet fields not established.',
            'Actual send target captured; writer/frame/socket and server VersionResult not executed.',
            'Inherited syscall/scheduler/endpoint/lifetime boundaries retained; no game launch/profile/process memory/credentials/network/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/connected-version-packet-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
