"""Whole current NPC create reader with native nested readers and bounded storage."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import math
import sys

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def verify(context):
    sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.npc_create_event import decode_npc_create_notify
    f={k:int(v,16) for k,v in context['functions'].items()}
    h=load('update-native-harness').make_harness(context,context['exports'],set(f.values()),
        leaves={int(k,16):v for k,v in context['leaves'].items()})
    uc,x=h.uc,h.x
    packet,archive,buffer=h.scratch+0x30000,h.scratch+0x2000,h.scratch+0x5000
    npc=packet+0x20;create=packet+0x18
    state=dict(packet=packet)
    def require(ok,message):
        if not ok:raise ValueError(message)
    def reg(key):return uc.reg_read(getattr(x,'UC_X86_REG_'+key))
    def number(at,size):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,fmt,*values):uc.mem_write(at,struct.pack('<'+fmt,*values))
    def allocate(size):
        require(0<size<=8192 and state['heap']+size+64<h.scratch+0x30000,'NPC allocation bound')
        pointer=state['heap']+16;state['heap']+=(size+63)&~15
        uc.mem_write(pointer-16,b'\xa5'*16+b'\x5a'*size+b'\xa6'*16)
        state['allocations'][pointer]=size;return pointer
    load('login-result-string-fixtures').install(load,h,context['string_storage'],state,packet,(0x110,0x208))
    load('character-list-storage-fixtures').install(h,context,state,allocate)
    # Native UCRT imports, source-bound by their import descriptors; no Python math substitute.
    kernel=ctypes.WinDLL('kernel32',use_last_error=True);directory=ctypes.create_unicode_buffer(32768)
    require(kernel.GetSystemDirectoryW(directory,len(directory))>0,'System runtime directory unavailable')
    dll_path=Path(directory.value)/'ucrtbase.dll';crt=ctypes.CDLL(str(dll_path));crt_sha=hashlib.sha256(dll_path.read_bytes()).hexdigest()
    imports=load('build-object-zero-init-code')
    for row in context['crt_imports']:
        at=int(row['address'],16);off=h.image.offset(at-h.image.pe.base)
        require(h.raw[off:off+2]==b'\xff\x25','Math thunk differs')
        slot=at+6+struct.unpack_from('<i',h.raw,off+2)[0]
        actual=imports.import_at(h.raw,h.image,slot)
        require(actual=={k:v for k,v in row.items() if k!='address'} and actual['dll']=='api-ms-win-crt-math-l1-1-0.dll'
                and actual['name'] in ('atan2','fmod'),'Math import identity differs')
        fn=getattr(crt,actual['name']);fn.argtypes=[ctypes.c_double,ctypes.c_double];fn.restype=ctypes.c_double
        def math_call(machine,fn=fn):
            a,b=[struct.unpack('<d',(reg('XMM'+str(i))&((1<<64)-1)).to_bytes(8,'little'))[0] for i in (0,1)]
            uc.reg_write(x.UC_X86_REG_XMM0,int.from_bytes(struct.pack('<d',fn(a,b)),'little'));h.finish()
        h.add_fixture(at,math_call)
    # Select the source's SSE2 sincos branch; AVX dispatch and exceptional huge arguments are outside this replay.
    isa=0x14b271750
    require(h.raw[h.image.offset(0x1487e9660-h.image.pe.base):h.image.offset(0x1487e9660-h.image.pe.base)+2]==b'\x83\x3d','Sincos ISA dispatch differs')
    dispatch=0x1487e9660+7+struct.unpack_from('<i',h.raw,h.image.offset(0x1487e9660-h.image.pe.base)+2)[0]
    require(dispatch==isa,'Sincos ISA variable differs');put(isa,'I',0)
    def clear(machine):
        require(reg('RDX')==0,'Only empty previous NPC arrays are supported');h.finish()
    for at in (0x1456bcc10,0x1456b5990,0x1456b59c0):h.add_fixture(at,clear)
    def resize(machine,target,stride):
        require(reg('RDX')==target and reg('R8')<=8,'NPC vector reserve receiver/count differs')
        count=reg('R8');put(target,'QII',allocate(count*stride) if count else 0,0,count);h.finish()
    for at,target,stride in [(0x14578b170,npc+0x80,0x70),(0x1456ba3a0,npc+0x178,0x18)]:
        h.add_fixture(at,lambda machine,target=target,stride=stride:resize(machine,target,stride))
    def appearance_allocate(machine):
        require(reg('RCX')==npc+0x108 and reg('RDX')<=8,'NPC appearance allocation differs')
        count=reg('RDX');put(npc+0x108,'Q',allocate(count*16) if count else 0);put(npc+0x114,'I',count);h.finish()
    def move_allocate(machine):
        require(reg('RCX')==create+0x1b0 and reg('RDX')<=8,'NPC move allocation differs')
        count=reg('RDX');put(create+0x1b0,'Q',allocate(count*16) if count else 0);put(create+0x1bc,'I',count);h.finish()
    # Shared resize 1456ba460 calls this allocation for both XY and appearance arrays.
    def shared_allocate(machine):
        if reg('RCX')==npc+0x108:appearance_allocate(machine)
        else:move_allocate(machine)
    h.add_fixture(0x14141ccf0,shared_allocate)
    def no_growth(machine):raise ValueError('NPC reserved array grew unexpectedly')
    for at in (0x14163d5c0,0x141437ee0,0x141539b80):h.add_fixture(at,no_growth)
    # Tables and descriptors are checked against source, not inferred from type names.
    for table,offset,expected in [(0x149921f88,0x20,(f['reader'],0x1456cf0d0)),
        (0x149921f40,0x20,(f['create_reader'],)),(0x149921ec8,0x20,(f['npc_reader'],)),
        (0x149948d28,0,(0x141b0aa50,0x14578b170,f['effect_callback'])),
        (0x14993f988,0,(0x141b0aa50,0x1456ba3a0,f['stat_callback']))]:
        off=h.image.offset(table+offset-h.image.pe.base)
        require(struct.unpack_from('<'+'Q'*len(expected),h.raw,off)==expected,'NPC table/descriptor differs')
    require(h.call(0x1456cf0d0)==324,'NPC create ID differs')
    def text(at):
        pointer,count,cap=struct.unpack('<QII',bytes(uc.mem_read(at,16)))
        require(0<=count==cap<=2048 and (not count or pointer in state['allocations']),'NPC string ownership differs')
        return bytes(uc.mem_read(pointer,count*2))[:-2].decode('utf-16le') if count else ''
    def vector(at,stride,fields):
        pointer,count,cap=struct.unpack('<QII',bytes(uc.mem_read(at,16)))
        require(0<=count<=cap<=8 and (not count or pointer in state['allocations']),'NPC vector ownership differs')
        return [[number(pointer+stride*i+offset,width) for offset,width in fields] for i in range(count)]
    def capture():
        appearance=npc+0xd8;owner=create+0x1d8
        result=dict(flag=bool(number(packet+0x10,1)),key=number(npc+8,8),id=number(npc+0x10,4),
            xyz=list(struct.unpack('<ddd',bytes(uc.mem_read(npc+0x18,24)))),yaw=number(npc+0x38,1),
            u64=[number(npc+off,8) for off in (0x58,0x60,0x68,0x78,0x188,0x190)],
            flag70=bool(number(npc+0x70,1)),u32=number(npc+0x74,4),enum90=number(npc+0x90,1),
            param=None,appearance=None,optional=None,
            effects=vector(npc+0x80,0x70,[(8,8),(0x10,4),(0x14,4),(0x18,2),(0x1a,2),(0x1c,2),
                (0x20,8),(0x28,8),(0x30,8),(0x38,4),(0x48,1),(0x58,4),(0x5c,4),(0x60,4),(0x68,1)]),
            stats=vector(npc+0x178,0x18,[(8,4),(0x10,8)]),
            create_u32=number(create+0x1a0,4),move=vector(create+0x1b0,16,[(8,4),(12,4)]),
            create_u64=number(create+0x1c0,8),owner=None,quest=None,
            enum230=number(create+0x230,1),float234=number(create+0x234,4),u32_238=number(create+0x238,4))
        if number(npc+0xa0,1):result['param']=[number(npc+0xb0,1),number(npc+0xb8,8),number(npc+0xc0,8)]
        if number(npc+0xd0,1):result['appearance']=dict(enum=number(appearance+8,1),bytes=list(uc.mem_read(appearance+9,9)),
            text=text(appearance+0x18),flag=bool(number(appearance+0x28,1)),byte=number(appearance+0x29,1),
            items=vector(appearance+0x30,16,[(8,4),(12,1),(14,2)]))
        if number(npc+0x120,1):
            pointer,count=number(npc+0x128,8),number(npc+0x130,4)
            require(count<=8 and pointer in state['allocations'],'NPC map ownership differs')
            result['optional']=sorted([[number(pointer+i*0x38+offset,width) for offset,width in
                [(0,1),(0x10,1),(0x14,4),(0x18,4),(0x1c,4),(0x28,8)]] for i in range(count)])
        if number(create+0x1d0,1):result['owner']=[number(owner+8,1),number(owner+0x10,8),text(owner+0x18),number(owner+0x28,8)]
        if number(create+0x210,1):result['quest']=[number(create+0x220,8),number(create+0x228,8)]
        return result
    def run(body):
        state.clear();state.update(packet=packet,record=npc+8,body=body,heap=h.scratch+0x10000,
            allocations={},generation=1,map_storage={},insertions=[],rehashes=[])
        uc.mem_write(packet-16,b'\xa1'*16+bytes(0x260)+b'\xa2'*16)
        uc.mem_write(archive-16,b'\xa3'*16+bytes(0x40)+b'\xa4'*16)
        uc.mem_write(buffer-16,b'\xa7'*16+body+b'\xa8'*16)
        h.call(f['packet_constructor'],packet)
        require(number(packet,8)==0x149921f88 and number(create,8)==0x149921f40,'NPC constructor differs')
        uc.reg_write(x.UC_X86_REG_RDX,buffer);uc.reg_write(x.UC_X86_REG_R8,len(body));uc.reg_write(x.UC_X86_REG_R9,1)
        uc.mem_write(h.scratch+0x38028,bytes(8));h.call(f['input_constructor'],archive)
        uc.reg_write(x.UC_X86_REG_RDX,archive)
        accepted=bool(h.call(f['reader'],packet,budget=500000)&255)
        consumed=number(archive+0x30,8)-buffer
        require(0<=consumed<=len(body),'NPC input cursor outside body')
        for at,size,before,after in [(packet,0x260,b'\xa1',b'\xa2'),(archive,0x40,b'\xa3',b'\xa4')]:
            require(bytes(uc.mem_read(at-16,16))==before*16 and bytes(uc.mem_read(at+size,16))==after*16,'NPC object/archive guards changed')
        require(bytes(uc.mem_read(buffer-16,len(body)+32))==b'\xa7'*16+body+b'\xa8'*16,'NPC input modified')
        for at,size in state['allocations'].items():
            require(bytes(uc.mem_read(at-16,16))==b'\xa5'*16 and bytes(uc.mem_read(at+size,16))==b'\xa6'*16,'NPC storage guard changed')
        return dict(accepted=accepted,consumed=consumed,value=capture() if accepted else None)
    def body_for(style=0,yaw=0,mask=31,count=2):
        maximum=(1<<64)-1;key=maximum if style else 42
        def string(value):
            raw=value.encode('utf-8');return struct.pack('<H',len(raw))+raw
        label='Тест日本😀' if style else 'NPC'
        effects=[];effect_values=[]
        for i in range(count):
            present=i%2;bits=[0x80000000,0x3f800000,0x7fc12345] if present else [0,0,0]
            scalars=[i+1,0xffffffff,3,4,5,0xffff,7,8,9,10]
            effects.append(struct.pack('<QIIHHHQQQIB',*scalars,present)+(struct.pack('<III',*bits) if present else b'')+b'\xff')
            effect_values.append(scalars+[present]+bits+[1])
        items=[[1,45,0xffff],[0xffffffff,2,0x8000]][:count]
        appearance=(bytes([255])+bytes(range(1,10))+string(label)+b'\xff\xfe'+struct.pack('<H',len(items))
                    +b''.join(struct.pack('<IBH',*item) for item in items))
        entries=[[1,255,2,3,4,5],[17,1,6,7,8,9],[1,2,10,11,12,13]] if count else []
        optional=struct.pack('<H',len(entries))+b''.join(struct.pack('<BBIIIQ',*item) for item in entries)
        stat_values=[[4,maximum],[5,100]][:count]
        moves=[[0x80000000,0x3f800000],[0x7fc12345,0xff800000]][:count]
        body=(b'\xff'+struct.pack('<QIIIIBQQQBIQH',key,123,0x80000000,0x3f800000,0xc2f68000,yaw,4,5,6,255,7,8,count)
              +b''.join(effects)+b'\xff'+(b'\xff\xff'+struct.pack('<QQ',21,22) if mask&1 else b'\0')
              +(b'\xff'+appearance if mask&2 else b'\0')+(b'\xff'+optional if mask&4 else b'\0')
              +struct.pack('<H',len(stat_values))+b''.join(struct.pack('<IQ',*item) for item in stat_values)
              +struct.pack('<QQIH',9,10,11,len(moves))+b''.join(struct.pack('<II',*item) for item in moves)
              +struct.pack('<Q',12)+(b'\xff\xff'+struct.pack('<Q',maximum)+string(label)+struct.pack('<Q',14) if mask&8 else b'\0')
              +(b'\xff'+struct.pack('<QQ',15,16) if mask&16 else b'\0')+b'\xff'+struct.pack('<II',0x80000000,13))
        expected=dict(flag=True,key=key,id=123,xyz=[-0.,1.,-123.25],u64=[4,5,6,8,9,10],flag70=True,u32=7,enum90=22,
            param=[1,21,22] if mask&1 else None,
            appearance=dict(enum=2,bytes=list(range(1,10)),text=label,flag=True,byte=254,items=items) if mask&2 else None,
            optional=([[1,2,10,11,12,13],[17,1,6,7,8,9]] if count else []) if mask&4 else None,
            effects=effect_values,stats=stat_values,create_u32=11,move=moves,create_u64=12,
            owner=[9,maximum,label,14] if mask&8 else None,quest=[15,16] if mask&16 else None,
            enum230=22,float234=0x80000000,u32_238=13)
        return body,expected
    cases=[]
    def portable(body):
        decoded=decode_npc_create_notify(body,source_sha256=h.sha)
        d,n=decoded.data,decoded.npc
        def rows(items,offsets):return [[int(item.at(off)) for off in offsets] for item in items]
        a,p,o,q=n.at(0xc8),n.at(0x98),d.at(0x1c8),d.at(0x208)
        return dict(flag=decoded.flag,key=n.at(8),id=n.at(0x10),xyz=list(n.at(0x18).finite_values()),
            u64=[n.at(off) for off in (0x58,0x60,0x68,0x78,0x188,0x190)],flag70=n.at(0x70),u32=n.at(0x74),enum90=n.at(0x90),
            param=[int(p.at(8)),p.at(0x10),p.at(0x18)] if p else None,
            appearance=dict(enum=a.at(8),bytes=[a.at(i) for i in range(9,18)],text=a.at(0x18),flag=a.at(0x28),byte=a.at(0x29),
                items=rows(a.at(0x30),(8,12,14))) if a else None,
            optional=[[key]+[v.at(off) for off in (8,12,16,20,0x20)] for key,v in n.at(0x118)] if n.at(0x118) is not None else None,
            effects=rows(n.at(0x80),(8,0x10,0x14,0x18,0x1a,0x1c,0x20,0x28,0x30,0x38,0x48,0x58,0x5c,0x60,0x68)),
            stats=rows(n.at(0x178),(8,0x10)),create_u32=d.at(0x1a0),move=[list(pair.bits) for pair in d.at(0x1a8)],
            create_u64=d.at(0x1c0),owner=[o.at(off) for off in (8,0x10,0x18,0x28)] if o else None,
            quest=[q.at(8),q.at(0x10)] if q else None,enum230=d.at(0x230),float234=d.at(0x234),u32_238=d.at(0x238))
    def complete(style=0,yaw=0,mask=31,count=2):
        body,expected=body_for(style,yaw,mask,count);result=run(body)
        require(result['accepted'] and result['consumed']==len(body),'NPC whole body rejected or partially consumed')
        actual=result['value'];canonical_yaw=actual.pop('yaw')
        require(actual==expected,'NPC complete fields differ: '+str([(k,actual.get(k),v) for k,v in expected.items() if actual.get(k)!=v]))
        require(portable(body)==expected,'NPC portable fields differ')
        require(decode_npc_create_notify(body,source_sha256=h.sha).npc.at(0x30).raw_byte==yaw,'NPC portable raw heading differs')
        require(math.copysign(1,actual['xyz'][0])==-1,'NPC widened signed zero differs')
        cases.append(dict(style=style,yaw=yaw,canonical_yaw=canonical_yaw,mask=mask,count=count,size=len(body)))
        return body
    for mask in range(32):
        for count in (0,2):complete(mask%2,(mask*17)&255,mask,count)
    for yaw in range(256):complete(1,yaw)
    complete(1,128,count=8)
    minimal=run(bytes(112));require(minimal['accepted'] and minimal['consumed']==112,'NPC zero/minimum body differs')
    minimal['value'].pop('yaw');require(minimal['value']==portable(bytes(112)),'NPC zero portable projection differs')
    cases.append(dict(style='all_zero',size=112))
    body=complete(1,255)
    truncated=[]
    for size in range(len(body)):
        result=run(body[:size]);require(not result['accepted'],'NPC truncated body accepted');truncated.append(dict(size=size,consumed=result['consumed']))
        try:decode_npc_create_notify(body[:size],source_sha256=h.sha)
        except ValueError:pass
        else:raise ValueError('NPC portable truncated body accepted')
    extra=run(body+b'\xff');require(extra['accepted'] and extra['consumed']==len(body),'NPC native trailing policy differs')
    try:decode_npc_create_notify(body+b'\xff',source_sha256=h.sha)
    except ValueError:pass
    else:raise ValueError('NPC portable exact-size policy differs')
    require(hashlib.sha256(dll_path.read_bytes()).hexdigest()==crt_sha,'System runtime changed during replay')
    return dict(cases=cases,truncated=truncated,extra=extra,runtime=dict(path=str(dll_path),sha256=crt_sha),exports=h.evidence,
        source_sha256=h.sha,network_used=False,limits=['Empty previous storage, bounded arrays/map/strings; native allocation and object reuse are not proved.',
            'Native SSE2 sincos branch selected; AVX dispatch and huge/nonfinite math inputs not exercised.',
            'Current system UCRT executes source-checked atan2/fmod imports; no Python math substitute.',
            'No NPC handler, actor visibility, world association or live packet proved.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--context',type=Path,required=True)
    args=parser.parse_args();result=verify(json.loads(args.context.read_text('utf-8')))
    result.update(context_sha256=hashlib.sha256(args.context.read_bytes()).hexdigest(),tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    path=load('audit-client-release').save_snapshot(Path('F:/PhoneExit Resources/Vampir/code-clues/npc-create-11316'),result)
    print(json.dumps(dict(report=str(path),cases=len(result['cases']),truncated=len(result['truncated']))))
