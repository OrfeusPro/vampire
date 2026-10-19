"""Game success optional Google PGS route; actual Windows provider returns unsupported."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('pgs_silent',HERE/'replay-silent-game-dispatch.py')
silent=importlib.util.module_from_spec(spec);spec.loader.exec_module(silent)
native,x=silent.native,silent.x
PROVIDER,GETTER,TABLE=0x1450c35e0,0x1450b11b0,0x1496de728
CLONE,RELEASE=0x300000b0,0x300000c0


class Replay(silent.Replay):
    def __init__(self,raw,image,fragments,leaves,fixture):
        super().__init__(raw,image,fragments,leaves,dict(bound=True,owner=True,weak=True,strong=4,
            field_4=fixture['field_4'],field_c=7 if fixture['field_4'] else 0,status=200,
            refcounted=True,heap_storage=True))
        self.pgs_fixture=fixture
        rows=[r for f in fragments if f['root_begin_rva']==PROVIDER-image.pe.base for r in f['instructions']]
        self.allowed.update(r['address'] for r in rows)
        self.pgs_targets={0x1450b11b0,0x1417ee5d0,0x1468e4100,0x141421150,0x144510320,0x1445342d0,0x14141c170,0x14141c190,CLONE,RELEASE}
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in self.pgs_targets)
        pages.add(TABLE & ~4095)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.game_instance=self.allocate(32);self.provider=self.allocate(128)
        self.uc.mem_write(self.provider,struct.pack('<Q',TABLE))
        self.callback_vtable=self.allocate(32)
        self.uc.mem_write(self.callback_vtable,struct.pack('<Q',CLONE))
        self.uc.mem_write(self.callback_vtable+0x10,struct.pack('<Q',RELEASE))
        self.events=[]

    def hook(self,uc,address,size,user):
        if address==PROVIDER:
            a,b=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
            if a!=self.provider or int.from_bytes(uc.mem_read(b+0x28,8),'little')!=0x1455f7bd0:
                raise ValueError('Game PGS virtual target or callback changed')
            self.events.append(dict(action='native_pgs_signin_entry',callback=0x1455f7bd0))
        if address in self.allowed:return super().hook(uc,address,size,user)
        if not hasattr(self,'pgs_targets'):return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0
        if address==0x1454894b0:
            result=self.game_instance if self.pgs_fixture['game_instance'] else 0
            self.events.append(dict(action='game_instance_fixture',present=bool(result)))
        elif address==0x1450b11b0:
            result=self.provider if self.pgs_fixture['provider'] else 0
            self.events.append(dict(action='pgs_get_or_create_capture',present=bool(result)))
        elif address==0x1417ee5d0:
            if b!=self.game_instance:raise ValueError('PGS game instance changed')
            uc.mem_write(a,struct.pack('<Q',b))
            result=a
        elif address==0x1468e4100:
            if a not in (64,24):raise ValueError('PGS allocation size changed')
            result=self.allocate(a)
        elif address==0x141421150:
            data=bytearray()
            for n in range(128):
                pair=bytes(uc.mem_read(b+n*2,2))
                if pair==b'\0\0':break
                data.extend(pair)
            else:raise ValueError('PGS literal bound')
            value=data.decode('utf-16le')
            pointer=self.allocate(len(data)+2);uc.mem_write(pointer,bytes(data)+b'\0\0')
            uc.mem_write(a,struct.pack('<QII',pointer,len(data)//2+1,len(data)//2+1));result=a
            self.events.append(dict(action='pgs_text_fixture',value=value))
        elif address==0x144510320:
            desc=int.from_bytes(uc.mem_read(uc.reg_read(x.UC_X86_REG_RSP)+0x28,8),'little')
            pointer,count,cap=struct.unpack('<QII',bytes(uc.mem_read(desc,16)))
            value=bytes(uc.mem_read(pointer,count*2)).decode('utf-16le')[:-1]
            self.events.append(dict(action='pgs_result_constructor_capture',arg_edx=b,arg_r8d=c,arg_r9d=d,message=value))
            uc.mem_write(a+4,struct.pack('<I',d));uc.mem_write(a+12,struct.pack('<I',c))
            uc.mem_write(a+0x28,struct.pack('<Q',b));result=a
        elif address in (CLONE,0x14141c170):
            storage=self.allocate(32);uc.mem_write(storage,bytes(uc.mem_read(a,32)))
            uc.mem_write(storage,struct.pack('<Q',self.callback_vtable))
            uc.mem_write(b,struct.pack('<Q',storage));result=storage
            self.events.append(dict(action='pgs_function_clone_fixture'))
        elif address in (RELEASE,0x14141c190):self.events.append(dict(action='pgs_function_release_capture'))
        elif address==0x1445342d0:
            obj,ref=struct.unpack('<QQ',bytes(uc.mem_read(b,16)))
            marker=int.from_bytes(uc.mem_read(a,8),'little')
            storage=int.from_bytes(uc.mem_read(a+0x10,8),'little') or a+0x20
            logging_target=int.from_bytes(uc.mem_read(storage+8,8),'little')
            self.events.append(dict(action='pgs_result_delivery_capture',callback=marker,logging_target=logging_target,
                field_4=int.from_bytes(uc.mem_read(obj+4,4),'little'),
                field_c=int.from_bytes(uc.mem_read(obj+12,4),'little'),
                status=int.from_bytes(uc.mem_read(obj+0x28,8),'little')))
        elif address in self.pgs_targets:raise ValueError('Unhandled PGS capture '+hex(address))
        else:return super().hook(uc,address,size,user)
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture(self):
        result=super().capture();result['fixture']=self.pgs_fixture
        result['original_response_field_4']=int.from_bytes(self.uc.mem_read(self.response+4,4),'little')
        return result


def build():
    path=native.ROOT/'code-clues/silent-game-dispatch-replay.json'
    prior=json.loads(path.read_text('utf-8'));raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('PGS source changed')
    image=native.Image(raw)
    addresses=(GETTER,PROVIDER,0x1450b7c50)
    fragments=prior['fragments']+native.decode_ranges(image,{image.roots[image.containing(a)] for a in addresses})
    literals=[]
    for f in fragments:
        if f['root_begin_rva']+image.pe.base not in addresses:continue
        for row in f['instructions']:
            for ref in row['rip_references']:
                if lit:=silent.dispatch.completion.gates.fields.lifecycle.guid.source.config.read_literal(raw,image,ref):
                    literals.append(dict(instruction=row['address'],**lit))
    offset=image.offset(TABLE-image.pe.base);content=raw[offset:offset+40]
    if struct.unpack_from('<Q',content,0x10)[0]!=PROVIDER:raise ValueError('PGS vtable slot changed')
    storage_address=0x14898d548;storage_offset=image.offset(storage_address-image.pe.base)
    storage_bytes=raw[storage_offset:storage_offset+24]
    if struct.unpack('<QQQ',storage_bytes)[::2]!=(0x14141c170,0x14141c190):
        raise ValueError('PGS callback storage targets changed')
    profiles=[dict(name='no-game-instance',game_instance=False,provider=False,field_4=0),
              dict(name='no-provider',game_instance=True,provider=False,field_4=0),
              dict(name='provider',game_instance=True,provider=True,field_4=0),
              dict(name='original-error',game_instance=True,provider=True,field_4=1)]
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),fragments=fragments,leaves=prior['leaves'],literals=literals,
                callback_storage_vtable=dict(address=storage_address,file_offset=storage_offset,bytes=storage_bytes.hex(),sha256=hashlib.sha256(storage_bytes).hexdigest()),
                provider_vtable=dict(address=TABLE,file_offset=offset,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest()),
                cases=[Replay(raw,image,fragments,prior['leaves'],f).capture() for f in profiles],native_execution=True,network_ready=False,
                limitations=[
                    'Native game callback, real provider vtable dispatch and Windows PGS SignIn body execute.',
                    'Game instance/weak conversion and GetOrCreate returns are fixtures; GetOrCreate/module initialization source static only.',
                    'PGS error constructor is a capture with raw arguments; fixture result field layout is not constructor execution.',
                    'PGS result delivery/TFunction storage/lifetime remain captures; logging callback not drained.',
                    'Original game result and optional PGS error are separate fixture objects; no network session proof.',
                    'Android PGS implementation and live provider availability are not established by Windows code.',
                    'No game launch/process memory/profile/credentials/HTTP used.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/game-pgs-branch-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
