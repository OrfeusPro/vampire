"""Whole CharacterOther with native appearance/stats/effects/actions/Guild/Party/map."""
import ctypes
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def verify(*,lifecycle=None):
    context_path=HERE/'knowledge/native-contexts'/('sight-character-other-lifecycle-11316.json' if lifecycle else 'sight-character-other-11316.json')
    context=json.loads(context_path.read_text('utf-8'));f={k:int(v,16) for k,v in context['functions'].items()}
    h=load('update-native-harness').make_harness(context,context['exports'],set(f.values()),
        leaves={int(k,16):v for k,v in context['leaves'].items()})
    uc,x=h.uc,h.x
    def require(ok,message):
        if not ok:raise ValueError(message)
    def reg(key):return uc.reg_read(getattr(x,'UC_X86_REG_'+key))
    def number(at,width):return int.from_bytes(uc.mem_read(at,width),'little')
    # Execute the same source's SSE2 yaw path and the actual local UCRT math imports.
    kernel=ctypes.WinDLL('kernel32',use_last_error=True);directory=ctypes.create_unicode_buffer(32768)
    require(kernel.GetSystemDirectoryW(directory,len(directory))>0,'System runtime directory unavailable')
    dll_path=Path(directory.value)/'ucrtbase.dll';crt=ctypes.CDLL(str(dll_path))
    imports=load('build-object-zero-init-code')
    for row in context['crt_imports']:
        at=int(row['address'],16);off=h.image.offset(at-h.image.pe.base)
        require(h.raw[off:off+2]==b'\xff\x25','Sight math thunk differs')
        slot=at+6+struct.unpack_from('<i',h.raw,off+2)[0];actual=imports.import_at(h.raw,h.image,slot)
        require(actual=={k:v for k,v in row.items() if k!='address'} and actual['dll']=='api-ms-win-crt-math-l1-1-0.dll'
            and actual['name'] in ('atan2','fmod'),'Sight math import differs')
        fn=getattr(crt,actual['name']);fn.argtypes=[ctypes.c_double,ctypes.c_double];fn.restype=ctypes.c_double
        def math_call(machine,fn=fn):
            a,b=[struct.unpack('<d',(reg('XMM'+str(i))&((1<<64)-1)).to_bytes(8,'little'))[0] for i in (0,1)]
            uc.reg_write(x.UC_X86_REG_XMM0,int.from_bytes(struct.pack('<d',fn(a,b)),'little'));h.finish()
        h.add_fixture(at,math_call)
    dispatch=0x1487e9660
    require(h.raw[h.image.offset(dispatch-h.image.pe.base):h.image.offset(dispatch-h.image.pe.base)+2]==b'\x83\x3d','Sight ISA shape differs')
    isa=dispatch+7+struct.unpack_from('<i',h.raw,h.image.offset(dispatch-h.image.pe.base)+2)[0]
    require(isa==0x14b271750,'Sight ISA variable differs');uc.mem_write(isa,bytes(4))
    sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.sight_character_other import decode_character_other
    from vampir_core.character_select_result import SelectionRecord,WireVector3,WireHeading
    packet,archive,buffer=[h.scratch+n for n in (0x30000,0x2000,0x5000)]
    state=dict(packet=packet)
    def put(at,fmt,*values):uc.mem_write(at,struct.pack('<'+fmt,*values))
    def allocate(size):
        require(0<size<=8192 and state['heap']+size+64<h.scratch+0x30000,'CharacterOther storage bound')
        pointer=state['heap']+16;state['heap']+=(size+63)&~15
        uc.mem_write(pointer-16,b'\xa5'*16+b'\x5a'*size+b'\xa6'*16);state['allocations'][pointer]=size;return pointer
    load('login-result-string-fixtures').install(load,h,context['string_storage'],state,packet,(0x20,0x58,0x118,0x188,0x1a8))
    load('character-list-storage-fixtures').install(h,context,state,allocate)
    def clear(machine):
        require(reg('RDX')==0,'Only empty previous CharacterOther arrays supported');h.finish()
    for at in (0x1456bcc10,0x1456b5990,0x1456b59c0,0x1456bc920):
        if at not in f.values():h.add_fixture(at,clear)
    def reserve(machine,target,stride):
        require(reg('RDX')==target and reg('R8')<=8,'CharacterOther reserve receiver/count differs')
        count=reg('R8');put(target,'QII',allocate(count*stride) if count else 0,0,count);h.finish()
    for at,target,stride in [(0x14578b170,packet+0xe0,0x70),(0x1456ba3a0,packet+0xc8,0x18)]:
        h.add_fixture(at,lambda machine,target=target,stride=stride:reserve(machine,target,stride))
    def appearance_allocate(machine):
        require(reg('RCX')==packet+0x70 and reg('RDX')<=8,'CharacterOther appearance allocation differs')
        count=reg('RDX');put(packet+0x70,'Q',allocate(count*16) if count else 0);put(packet+0x7c,'I',count);h.finish()
    def action_allocate(machine):
        require(reg('RCX')==packet+0xf8 and reg('RDX')<=8,'CharacterOther action allocation differs')
        count=reg('RDX');put(packet+0xf8,'QII',allocate(count*0x78) if count else 0,0,count);h.finish()
    h.add_fixture(0x14141ccf0,appearance_allocate);h.add_fixture(0x141685280,action_allocate)
    def no_growth(machine):raise ValueError('CharacterOther reserved storage exceeded')
    for at in (0x14163d5c0,0x141437ee0,0x141539b80,0x141684cd0):h.add_fixture(at,no_growth)
    for table,reader in [(0x149921ca8,f['reader']),(0x149921ad8,f['action_reader']),(0x149921a70,f['position_reader'])]:
        require(struct.unpack_from('<Q',h.raw,h.image.offset(table+0x20-h.image.pe.base))[0]==reader,'CharacterOther virtual reader differs')
    for table,expected in [(0x149948d70,(0x141b0aa50,f['action_resize'],f['action_callback'])),
        (0x149948d28,(0x141b0aa50,0x14578b170,f['effect_callback']))]:
        require(struct.unpack_from('<3Q',h.raw,h.image.offset(table-h.image.pe.base))==expected,'CharacterOther descriptor differs')
    def text(at):
        ptr,count,cap=struct.unpack('<QII',bytes(uc.mem_read(at,16)))
        require(0<=count==cap<=2048 and (not count or ptr in state['allocations']),'CharacterOther string owner differs')
        if not count:return ''
        data=bytes(uc.mem_read(ptr,count*2));require(data[-2:]==b'\0\0','CharacterOther string terminator differs')
        return data[:-2].decode('utf-16le')
    shapes={
        'root':{8:8,0x10:8,0x18:4,0x30:4,0x34:4,0x38:1,0x3c:4,0x80:2,0xd8:8,0xf0:1,0x228:1,0x229:1,0x22a:1,0x22b:1},
        'appearance':{8:1,**{i:1 for i in range(9,18)},0x28:1,0x29:1},'item':{8:4,12:1,14:2},'stat':{8:4,0x10:8},
        'effect':{8:8,0x10:4,0x14:4,0x18:2,0x1a:2,0x1c:2,0x20:8,0x28:8,0x30:8,0x38:4,0x48:1,0x58:4,0x5c:4,0x60:4,0x68:1},
        'action':{8:1,0xc:4,0x10:8,0x18:8},'guild':{8:8,0x20:4,0x38:8,0x40:1,0x50:8,0x58:1},
        'emblem':{8:2,10:2,12:2,14:2},'party':{8:8,0x48:1,0x49:1,0x4c:4},'options':{8:1,9:1,10:1,0x20:1,0x21:1}}
    arrays={('root',0xc8):(0x18,'stat'),('root',0xe0):(0x70,'effect'),('root',0xf8):(0x78,'action'),('appearance',0x30):(16,'item')}
    nested={('root',0x40):'appearance',('root',0x108):'guild',('guild',0x28):'emblem',('party',0x20):'options'}
    optionals={('root',0x168):'party',('action',0x20):'position'}
    strings={('root',0x20),('appearance',0x18),('guild',0x10),('party',0x10),('options',0x10)}
    def compare(value,at,kind):
        for offset,item in value.fields:
            key=(kind,offset)
            if key in strings:require(text(at+offset)==item,'CharacterOther text differs')
            elif key in arrays:
                stride,child=arrays[key];pointer,count,cap=struct.unpack('<QII',bytes(uc.mem_read(at+offset,16)))
                require(count==len(item) and 0<=count<=cap<=8 and (not count or pointer in state['allocations']),'CharacterOther vector owner/count differs')
                for i,row in enumerate(item):compare(row,pointer+i*stride,child)
            elif key in optionals:
                require(bool(number(at+offset+8,1))==(item is not None),'CharacterOther optional presence differs')
                if item is not None:compare(item,at+offset+0x10,optionals[key])
            elif key in nested:compare(item,at+offset,nested[key])
            elif key==('root',0x1c8):
                require(bool(number(at+offset+8,1))==(item is not None),'CharacterOther map presence differs')
                if item is not None:
                    base=at+offset+0x10;pointer,count=number(base,8),number(base+8,4)
                    require(count==len(item) and (pointer in state['allocations'] or (count==0 and pointer==0)),'CharacterOther map owner/count differs')
                    actual=sorted((number(pointer+i*0x38,1),tuple(number(pointer+i*0x38+8+k,width) for k,width in [(8,1),(12,4),(16,4),(20,4),(0x20,8)])) for i in range(count))
                    require(actual==[(k,tuple(v.at(n) for n in (8,12,16,20,0x20))) for k,v in item],'CharacterOther map entries differ')
            elif isinstance(item,WireVector3):
                expected=struct.unpack('<fff',struct.pack('<III',*item.bits));actual=struct.unpack('<ddd',bytes(uc.mem_read(at+offset,24)))
                for a,b in zip(actual,expected):require(math.isnan(a) if math.isnan(b) else struct.pack('<d',a)==struct.pack('<d',b),'CharacterOther XYZ differs')
            elif not isinstance(item,WireHeading):require(number(at+offset,shapes[kind][offset])==item,'CharacterOther scalar differs')
    operation=lifecycle.install(h,context,packet,state,compare) if lifecycle else None
    def attempt(body):
        state.clear();state.update(packet=packet,record=packet+0xb8,body=body,heap=h.scratch+0x10000,allocations={},generation=1,map_storage={},insertions=[],rehashes=[])
        uc.mem_write(packet-16,b'\xa1'*16+bytes(0x230)+b'\xa2'*16)
        uc.mem_write(archive-16,b'\xa3'*16+bytes(0x40)+b'\xa4'*16)
        uc.mem_write(buffer-16,b'\xa7'*16+body+b'\xa8'*16)
        h.call(f['constructor'],packet);require(number(packet,8)==0x149921ca8,'CharacterOther constructor differs')
        uc.reg_write(x.UC_X86_REG_RDX,buffer);uc.reg_write(x.UC_X86_REG_R8,len(body));uc.reg_write(x.UC_X86_REG_R9,1)
        uc.mem_write(h.scratch+0x38028,bytes(8));h.call(f['input_constructor'],archive)
        uc.reg_write(x.UC_X86_REG_RDX,archive)
        try:accepted=bool(h.call(f['reader'],packet,budget=3000000)&255)
        except Exception as exc:
            raise ValueError('CharacterOther execution failed: size='+str(len(body))+' rip='+hex(reg('RIP'))+' rcx='+hex(reg('RCX'))+' rdx='+hex(reg('RDX'))) from exc
        consumed=number(archive+0x30,8)-buffer;require(0<=consumed<=len(body),'CharacterOther cursor exceeded input')
        for at,size,a,b in [(packet,0x230,b'\xa1',b'\xa2'),(archive,0x40,b'\xa3',b'\xa4')]:
            require(bytes(uc.mem_read(at-16,16))==a*16 and bytes(uc.mem_read(at+size,16))==b*16,'CharacterOther frame guard differs')
        require(bytes(uc.mem_read(buffer-16,len(body)+32))==b'\xa7'*16+body+b'\xa8'*16,'CharacterOther input changed')
        for at,size in state['allocations'].items():require(bytes(uc.mem_read(at-16,16))==b'\xa5'*16 and bytes(uc.mem_read(at+size,16))==b'\xa6'*16,'CharacterOther heap guard differs')
        if accepted:compare(decode_character_other(body[:consumed],source_sha256=h.sha),packet,'root')
        if operation:operation(accepted,body[:consumed])
        return accepted,consumed
    def encoded(label):
        data=label.encode('utf-8');return struct.pack('<H',len(data))+data
    def body_for(style=0,yaw=0,mask=3,count=2):
        key=(0,2**63,2**64-1)[style];other=key^0xffffffffffffffff;label=('','Игрок 🦇','x'*31)[style];flag=(0,1,255)[style]
        bits=((0,0x80000000,0x3f800000),(0x7fc12345,0x7f800000,0xff800000),(0xc2f68000,0x3f000000,0x7f7fffff))[style]
        appearance=b'\xff'+bytes(range(1,10))+encoded(label)+bytes([flag,254])+struct.pack('<H',count)+b''.join(struct.pack('<IBH',i+1,255,65535-i) for i in range(count))
        stats=struct.pack('<H',count)+b''.join(struct.pack('<IQ',4+i,key^i) for i in range(count))
        effects=[];actions=[]
        for i in range(count):
            present=i%2;effect=struct.pack('<QIIHHHQQQIB',i+1,2,3,4,5,6,7,8,9,10,present)
            effects.append(effect+(struct.pack('<III',*bits) if present else b'')+b'\xff')
            actions.append(struct.pack('<BIQQB',255,i+1,key,other,present)+(struct.pack('<IIIB',*bits,(yaw+i+45)%256) if present else b''))
        guild=struct.pack('<Q',other)+encoded(label)+struct.pack('<I4HQBQB',17,0,32767,32768,65535,key,255,other,flag)
        party=struct.pack('<Q',key)+encoded(label)+b'\xff\xff\xff'+encoded(label)+b'\xff\0\xff\xff'+struct.pack('<I',27)
        entries=[(1,255,2,3,4,5),(17,1,6,7,8,9),(1,2,10,11,12,13)] if count else []
        small_map=struct.pack('<H',len(entries))+b''.join(struct.pack('<BBIIIQ',*row) for row in entries)
        body=(struct.pack('<QQI',key,other,12)+encoded(label)+struct.pack('<IIBI',13,14,255,15)+appearance+struct.pack('<HIIIB',65535,*bits,yaw)+stats+struct.pack('<QH',other,count)
            +b''.join(effects)+bytes([flag])+struct.pack('<H',count)+b''.join(actions)+guild
            +(b'\xff'+party if mask&1 else b'\0')+(b'\xff'+small_map if mask&2 else b'\0')+bytes([flag,255,1 if not flag else 0,255]))
        require(decode_character_other(body,source_sha256=h.sha).at(0xa0).raw_byte==yaw,'CharacterOther raw yaw differs')
        return body
    cases=[]
    bodies=[body_for(style,yaw,mask,count) for style,yaw in [(0,0),(1,127),(2,255)] for mask in range(4) for count in (0,2)]
    bodies.extend(body_for(0,yaw,3,1) for yaw in range(256))
    for index,body in enumerate(bodies):
        sizes=range(len(body)+1) if index in (7,15,23) else [len(body)]
        for size in sizes:
            accepted,consumed=attempt(body[:size]);require(accepted==(size==len(body)),'CharacterOther native prefix differs')
            try:decode_character_other(body[:size],source_sha256=h.sha);portable=True
            except ValueError:portable=False
            require(portable==accepted,'CharacterOther portable prefix differs')
            cases.append(dict(index=index,size=size,accepted=accepted,consumed=consumed))
        accepted,consumed=attempt(body+b'\xff');require(accepted and consumed==len(body),'CharacterOther trailing cursor differs')
    report=dict(source_sha256=h.sha,exports=h.evidence,context_sha256=hashlib.sha256(context_path.read_bytes()).hexdigest(),
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),cases=cases,network_used=False,
        crt_sha256=hashlib.sha256(dll_path.read_bytes()).hexdigest(),
        limits=['Whole CharacterOther including nonempty appearance/stats/effects/ActorAction/Guild/Party/map and actual input/UTF8/XYZ/yaw.',
            'Fresh owners with bounded allocation/storage fixtures, at most 8 array/map entries; reuse/growth/allocator/engine effects not proved.',
            'CharacterOther+f8 uses ActorAction/optional PositionData, not SightEnter GroundEffectData. No outer SightEnter/actor/world/live claim.'])
    if lifecycle:
        report['lifecycle_tool_sha256']=hashlib.sha256(Path(lifecycle.__file__).read_bytes()).hexdigest()
        report['limits']=lifecycle.LIMITS
        report['lifecycle_summary']=operation.summary
    path=load('audit-client-release').save_snapshot(h.root/'code-clues'/('sight-character-other-lifecycle-11316' if lifecycle else 'sight-character-other-11316'),report)
    return dict(report=str(path),cases=len(cases))


if __name__=='__main__':print(json.dumps(verify()))
