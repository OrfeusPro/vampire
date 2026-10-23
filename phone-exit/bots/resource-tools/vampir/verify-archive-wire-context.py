"""Bounded current archive IO and whole Version/Login writers; no sockets or auth."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from importlib.util import spec_from_file_location, module_from_spec

HERE = Path(__file__).resolve().parent


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(context, root):
    archive = {k:int(v,16) for k,v in context['archive'].items()}
    bindings = {k:int(v,16) for k,v in context['bindings'].items()}
    functions = set(bindings.values())-{bindings['encoder']}
    functions.update(v for k,v in archive.items() if k not in ('table','growth'))
    functions.update(int(p['writer'],16) for p in context['packets'].values())
    leaves = dict(context['archive_leaves'])
    leaves[hex(bindings['encoder'])] = context['encoder_leaf']
    for item in leaves.values():
        raw = bytes.fromhex(item['bytes'])
        if len(raw) != item['size'] or len(raw)>512 or hashlib.sha256(raw).hexdigest()!=item['sha256']:
            raise ValueError('Archive leaf size or SHA differs')
    h = load('update-native-harness').make_harness(context, context['exports'], functions,
        leaves={int(k,16):v['bytes'] for k,v in leaves.items()}, root=root)
    native = load('build-native-entry-code')
    rows = load('update-bindings').rows
    table_offset = h.image.offset(archive['table']-h.image.pe.base)
    table_bytes = h.raw[table_offset:table_offset+0xf8]
    if hashlib.sha256(table_bytes).hexdigest()!=context['archive_table_sha256']:
        raise ValueError('Archive table SHA differs')
    slots = {'string':0x28,'u16':0x60,'raw':0x88,'u64':0xb8,'u32':0xc8,'u8':0xe0,'bool':0xf0}
    for name,slot in slots.items():
        if struct.unpack_from('<Q',table_bytes,slot)[0]!=archive[name]:
            raise ValueError('Archive table slot differs')
    ctor_rows = rows(native,h.image,archive['constructor'])
    if not any(r['mnemonic']=='lea' and r['rip_references']==[archive['table']] for r in ctor_rows):
        raise ValueError('Archive constructor table link differs')
    if [r['direct_target'] for r in ctor_rows if r['call']] != [archive['base-constructor']]:
        raise ValueError('Archive constructor callee differs')
    # All archive calls must remain in the reviewed slot/direct set. Overflow growth is rejected at execution.
    allowed_calls = {'base-constructor':[0x144aad1b0], 'raw':[archive['growth'],int(context['helpers']['memcpy'],16),0x1445f11f0]}
    for name in ('base-constructor','raw','string','u8','u16','u32','u64','bool'):
        calls = [r for r in rows(native,h.image,archive[name]) if r['call']]
        if [r['direct_target'] for r in calls if r['direct_target'] is not None] != allowed_calls.get(name,[]):
            raise ValueError('Archive direct call set differs')
        indirect = [r['operands'] for r in calls if r['direct_target'] is None]
        expected = [] if name in allowed_calls else (
            ['qword ptr [rax + 0x60]','qword ptr [rax + 0x88]'] if name=='string' else ['qword ptr [rax + 0x88]'])
        if indirect!=expected:
            raise ValueError('Archive indirect call set differs')
    for packet in context['packets'].values():
        off = h.image.offset(int(packet['table'],16)-h.image.pe.base)
        if struct.unpack_from('<Q',h.raw,off+0x10)[0]!=int(packet['writer'],16):
            raise ValueError('Packet table writer link differs')
    # Runtime hook rejects all non-exported/non-leaf instructions. Verify leaf control closure too.
    cs = native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
    cs.detail = True
    for address,item in leaves.items():
        instructions = list(cs.disasm(bytes.fromhex(item['bytes']),int(address,16)))
        locations = {i.address for i in instructions}
        if not instructions or instructions[-1].mnemonic!='ret':
            raise ValueError('Archive leaf return differs')
        for ins in instructions:
            if ins.group(native.capstone.CS_GRP_CALL):
                raise ValueError('Unreviewed leaf call')
            if ins.group(native.capstone.CS_GRP_JUMP) and (len(ins.operands)!=1 or
                    ins.operands[0].type!=native.X86_OP_IMM or ins.operands[0].imm not in locations):
                raise ValueError('Unreviewed leaf branch')
    obj, descriptor, source, packet, text, buffer = [h.scratch+n for n in (0x1000,0x1800,0x2000,0x4000,0x5000,0x10000)]
    capacity = 16384
    fixture = {k:int(v,16) for k,v in context['fixtures'].items() if k!='archive_slot'}
    state = {}

    def reg(name):
        return h.uc.reg_read(getattr(h.x,'UC_X86_REG_'+name))

    def allocate(size,kind):
        if not 1<=size<=8192 or state['heap']+size+32>h.scratch+0x30000:
            raise ValueError('Wire allocation fixture bound')
        pointer = state['heap']+16
        state['heap'] += (size+63)&~15
        h.uc.mem_write(pointer-16,b'\xa5'*16+b'\x5a'*size+b'\xa6'*16)
        state['allocations'][pointer]=(size,kind)
        return pointer

    def allocate_utf8(machine):
        if reg('RDX')!=0 or reg('R9')!=1:
            raise ValueError('UTF-8 allocation arguments differ')
        h.uc.mem_write(reg('RCX'),struct.pack('<Q',allocate(reg('R8'),'utf8')))
        h.finish()

    def free(machine,kind):
        pointer = reg('RCX')
        if pointer not in state['allocations'] or pointer in state['freed']:
            raise ValueError('Unowned wire free')
        size,expected = state['allocations'][pointer]
        if kind!=expected or (kind=='cpp' and reg('RDX')!=size):
            raise ValueError('Wire free size or kind differs')
        if bytes(h.uc.mem_read(pointer-16,16))!=b'\xa5'*16 or bytes(h.uc.mem_read(pointer+size,16))!=b'\xa6'*16:
            raise ValueError('Wire allocation canary changed')
        state['freed'].add(pointer)
        h.finish()

    def security(machine):
        off=h.image.offset(0x14b271780-h.image.pe.base)
        if reg('RCX')!=int.from_bytes(h.raw[off:off+8],'little'):
            raise ValueError('Wire security cookie differs')
        h.finish(reg('RAX'))

    def reject_growth(machine):
        raise ValueError('Archive growth is outside preallocated fixtures')

    h.add_fixture(fixture['utf8_allocate'],allocate_utf8)
    h.add_fixture(fixture['cpp_allocate'],lambda machine:h.finish(allocate(reg('RCX'),'cpp')))
    h.add_fixture(fixture['utf8_free'],lambda machine:free(machine,'utf8'))
    h.add_fixture(fixture['cpp_free'],lambda machine:free(machine,'cpp'))
    h.add_fixture(fixture['security_check'],security)
    h.add_fixture(archive['growth'],reject_growth)
    nonvolatile = {name:0xfedcba9876543210+i for i,name in enumerate(('RBX','RSI','RDI','RBP','R12','R14','R15'))}

    def call(address,receiver=obj,b=0,c=0):
        for name,value in nonvolatile.items():
            h.uc.reg_write(getattr(h.x,'UC_X86_REG_'+name),value)
        h.uc.reg_write(h.x.UC_X86_REG_RDX,b)
        h.uc.reg_write(h.x.UC_X86_REG_R8,c)
        result = h.call(address,receiver,budget=3000000)
        if any(reg(name)!=value for name,value in nonvolatile.items()) or reg('RSP')!=h.scratch+0x38008:
            raise ValueError('Wire native ABI differs')
        return result

    def reset():
        state.update(heap=h.scratch+0x18000,allocations={},freed=set())
        h.uc.mem_write(obj-16,b'\xa5'*16+b'\xcc'*64+b'\xa6'*16)
        if call(archive['constructor'],b=1)!=obj:
            raise ValueError('Archive constructor return differs')
        if int.from_bytes(h.uc.mem_read(obj,8),'little')!=archive['table']:
            raise ValueError('Archive constructor vptr differs')
        h.uc.mem_write(obj+0x18,struct.pack('<QQQ',buffer,buffer,buffer+capacity))
        h.uc.mem_write(obj+0x30,struct.pack('<III',capacity,0,0))
        h.uc.mem_write(buffer-16,b'\xa5'*16+b'\x5a'*capacity+b'\xa6'*16)

    def check(expected):
        size,total = struct.unpack('<II',h.uc.mem_read(obj+0x34,8))
        if (size,total)!=(len(expected),len(expected)):
            raise ValueError('Archive output counters differ')
        if bytes(h.uc.mem_read(buffer-16,capacity+32))!=b'\xa5'*16+expected+b'\x5a'*(capacity-len(expected))+b'\xa6'*16:
            raise ValueError('Archive payload or canaries differ')
        if bytes(h.uc.mem_read(obj-16,16))!=b'\xa5'*16 or bytes(h.uc.mem_read(obj+64,16))!=b'\xa6'*16:
            raise ValueError('Archive object canaries differ')
        if set(state['allocations'])!=state['freed']:
            raise ValueError('Wire temporary allocation leaked')

    cases=[]
    for name,width in (('u8',1),('bool',1),('u16',2),('u32',4),('u64',8)):
        for value in sorted({0,1,0x7f,0x80,(1<<(width*8-1)),(1<<(width*8))-1}):
            reset()
            expected=value.to_bytes(width,'little')
            if call(archive[name],b=value)&255!=1:
                raise ValueError('Archive scalar return differs')
            check(expected)
            cases.append(dict(kind=name,value=value,output_hex=expected.hex()))
    for size in (0,1,15,16,127,128,1024,4095):
        reset();data=bytes((i*17+3)&255 for i in range(size))
        h.uc.mem_write(source-16,b'\xa5'*16+data+b'\xa6'*16)
        if call(archive['raw'],b=source,c=size)&255!=1:
            raise ValueError('Archive raw return differs')
        check(data)
        if bytes(h.uc.mem_read(source-16,size+32))!=b'\xa5'*16+data+b'\xa6'*16:
            raise ValueError('Archive raw source changed')
        cases.append(dict(kind='raw',size=size,payload_sha256=hashlib.sha256(data).hexdigest()))
    for data in (b'',b'abc',b'a'*15,b'b'*16,'Ж🙂'.encode(),b'x\0y',b'a'*127,b'a'*128,b'a'*4095):
        reset();h.uc.mem_write(source,data+b'\0')
        value=(data+b'\0').ljust(16,b'\0') if len(data)<=15 else struct.pack('<Q',source)+bytes(8)
        value+=struct.pack('<QQ',len(data),max(15,len(data)))
        h.uc.mem_write(descriptor,value)
        if call(archive['string'],b=descriptor)&255!=1:
            raise ValueError('Archive string return differs')
        check(struct.pack('<H',len(data))+data)
        if bytes(h.uc.mem_read(descriptor,32))!=value:
            raise ValueError('Archive string descriptor changed')
        cases.append(dict(kind='string',size=len(data),payload_sha256=hashlib.sha256(data).hexdigest()))
    wire_cases=[]
    for name,spec in context['packets'].items():
        for poison in (0,0x55,0xaa,0xff):
            for text_value in ('','a','Ж界🙂','a'*15,'b'*16,'c'*127,'d'*128,'é'*80):
                reset();contents=bytearray([poison]*spec['object_size']);expected=b'';text_cursor=text
                for number,(kind,offset) in enumerate(spec['fields']):
                    if kind=='string':
                        value=(text_value+str(number)) if text_value else ''
                        data=value.encode('utf-16le')+b'\0\0';h.uc.mem_write(text_cursor,data)
                        struct.pack_into('<QII',contents,offset,text_cursor,len(data)//2,len(data)//2)
                        text_cursor+=(len(data)+31)&~15
                        utf8=value.encode('utf-8');expected+=struct.pack('<H',len(utf8))+utf8
                    else:
                        width={'u32':4,'u64':8,'u8':1,'bool':1}[kind]
                        value=((0xfedcba9876543210+number) if width==8 else
                               (0x89abcdef+number) if width==4 else (poison+number)&255)
                        data=value.to_bytes(width,'little');contents[offset:offset+width]=data;expected+=data
                struct.pack_into('<Q',contents,0,int(spec['table'],16))
                guarded=b'\xa5'*16+contents+b'\xa6'*16;h.uc.mem_write(packet-16,bytes(guarded))
                if call(int(spec['writer'],16),packet,obj)&255!=1:
                    raise ValueError('Packet wire writer failed')
                check(expected)
                if bytes(h.uc.mem_read(packet-16,len(guarded)))!=guarded:
                    raise ValueError('Packet object changed')
                wire_cases.append(dict(packet=name,poison=poison,text_utf8_bytes=len(text_value.encode()),
                                       payload_hex=expected.hex(),guards=True))
    return dict(schema=1,source_sha256=context['source_sha256'],method='bounded_native',
        archive=context['archive'],cases=cases,wire_cases=wire_cases,evidence=h.evidence,
        network_used=False,profile_activated=False,runtime=load('update-native-harness').runtime_inputs(),
        limits=['Native archive constructors/scalars/raw/string and whole packet/string/UTF-8 writers executed.',
                'Preallocated 16384-byte archive; growth rejected. Allocator/free/memcpy/security are bounded fixtures.',
                'No allocation failure, framing, preparation, response reader, auth, socket or world-session proof.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context',type=Path,required=True)
    parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    args=parser.parse_args()
    report=verify(json.loads(args.context.read_text('utf-8')),args.root)
    report['context_sha256']=hashlib.sha256(args.context.read_bytes()).hexdigest()
    report['tool_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    target=load('research-workflow').snapshot(args.root,'native-archive-wire-checks',report)
    print(json.dumps(dict(report=str(target),cases=len(report['cases']),wire_cases=len(report['wire_cases']))))
