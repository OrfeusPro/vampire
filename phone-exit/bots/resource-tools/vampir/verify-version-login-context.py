"""Explicit source-context constructor/tag checks, not full Version/Login IO."""
import hashlib
import importlib.util
from pathlib import Path
import re
import struct

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def verify(context, root):
    native=load('build-native-entry-code')
    sha=context['source_sha256']
    if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha):raise ValueError('Full context SHA required')
    expected_source=root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
    if Path(context['source']).resolve()!=expected_source.resolve():raise ValueError('Context source outside snapshot library')
    spec=context['contract']['tag_check']
    bindings=context['bindings']['bindings']
    ctor,prepare=[int(bindings[k],16) for k in ('constructor','prepare')]
    exports={}
    for item in context['exports']:
        if item.get('address') in (hex(ctor),hex(prepare)):
            for artifact in item['artifacts']:
                path=Path(artifact['path'])
                if not path.resolve().is_relative_to((root/'ghidra/request-exports'/context['source_sha256']).resolve()):
                    raise ValueError('Context export outside source-specific request library')
                exports[path.parent.name]=artifact['sha256']
    raw=Path(context['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=context['source_sha256']:raise ValueError('Context source changed')
    image=native.Image(raw)
    binding=load('update-bindings')
    ctor_rows=binding.rows(native,image,ctor)
    prep_rows=binding.rows(native,image,prepare)
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    def ins(row):return next(decoder.disasm(bytes.fromhex(row['bytes']),row['address']))
    ascii_calls=[r['direct_target'] for r in ctor_rows if r['call']]
    if len(ascii_calls)!=1:raise ValueError('Constructor has unreviewed calls')
    ascii_ctor=ascii_calls[0]
    ptr_loads=[r for r in ctor_rows if r['mnemonic']=='mov' and r['operands'].startswith('rdx, qword ptr [rip')]
    if len(ptr_loads)!=1:raise ValueError('Constructor tag pointer binding differs')
    pointer=ptr_loads[0]['rip_references'][0]
    po=image.offset(pointer-image.pe.base);literal=struct.unpack_from('<Q',raw,po)[0]
    lo=image.offset(literal-image.pe.base);tag=raw[lo:lo+33]
    if not re.fullmatch(b'[0-9A-F]{32}\0',tag):raise ValueError('Compiled tag literal differs')
    table_loads=[r for r in ctor_rows if r['mnemonic']=='lea' and r['operands'].startswith('rax, [rip')]
    if len(table_loads)!=1:raise ValueError('Constructor table load differs')
    table=table_loads[0]['rip_references'][0];to=image.offset(table-image.pe.base)
    reviewed=context['contract'].get('data_dependencies',{}).get(sha,{})
    actual={'tag-pointer':hex(pointer),'tag-literal':hex(literal),'packet-table':hex(table)}
    kinds={'tag-pointer':'pointer','tag-literal':'ascii','packet-table':'vtable'}
    if set(reviewed)-set(actual):raise ValueError('Unreviewed data dependency')
    if any(actual[k]!=v['address'] or v.get('kind')!=kinds[k] for k,v in reviewed.items()):
        raise ValueError('Reviewed data binding differs')
    getter,name_getter=[struct.unpack_from('<Q',raw,to+slot)[0] for slot in (0x28,0x38)]
    go=image.offset(getter-image.pe.base);getter_bytes=raw[go:go+6]
    if getter_bytes!=b'\xb8'+struct.pack('<I',spec['packet_id'])+b'\xc3':
        raise ValueError('Packet ID getter differs')
    name_rows=binding.rows(native,image,name_getter)
    name_refs=[r['rip_references'][0] for r in name_rows if r['mnemonic']=='lea' and r['operands'].startswith('rdx, [rip')]
    if len(name_refs)!=1:raise ValueError('Packet name binding differs')
    no=image.offset(name_refs[0]-image.pe.base);expected_name=(spec['packet_name']+'\0').encode('ascii')
    if raw[no:no+len(expected_name)]!=expected_name:raise ValueError('Packet name literal differs')
    start,stop=prepare+spec['start_offset'],prepare+spec['stop_offset']
    sliced=[r for r in prep_rows if start<=r['address']<stop]
    if not sliced or sliced[0]['rip_references']!=[pointer] or sliced[0]['mnemonic']!='mov':
        raise ValueError('Prepare tag source differs from constructor')
    calls=[r['direct_target'] for r in sliced if r['call']]
    if len(calls)!=3 or calls[0]!=ascii_ctor:raise ValueError('Prepare tag fixture call set differs')
    links={}
    if spec['packet_id']==3:
        sites=[n for n,r in enumerate(prep_rows) if r['call'] and r['direct_target']==ctor]
        if len(sites)!=1:raise ValueError('Login preparation constructor link differs')
        argument=ins(prep_rows[sites[0]-1])
        if argument.mnemonic!='lea' or argument.operands[1].mem.base!=native.capstone.x86.X86_REG_RSP:
            raise ValueError('Login stack packet binding differs')
        packet_offset=argument.operands[1].mem.disp
        rbp_lea=next(ins(r) for r in prep_rows if r['mnemonic']=='lea' and r['operands'].startswith('rbp, [rsp'))
        stack_sub=next(ins(r) for r in prep_rows if r['mnemonic']=='sub' and r['operands'].startswith('rsp,'))
        frame_delta=rbp_lea.operands[1].mem.disp+stack_sub.operands[1].imm
        if frame_delta+spec['destination_offset']-packet_offset!=spec['tag_field']:
            raise ValueError('Login tag destination is not the constructor field')
        links['login_constructor_call']=hex(prep_rows[sites[0]]['address'])
        links['login_tag_field']=spec['tag_field']
    if 'wrapper-constructor' in bindings:
        owner=int(bindings['wrapper-constructor'],16)
        owner_rows=binding.rows(native,image,owner);found=[]
        for n,r in enumerate(owner_rows[:-1]):
            if r['mnemonic']!='lea' or not r['operands'].startswith('rax, [rip'):continue
            if owner_rows[n+1]['operands']!='qword ptr [rbx], rax':continue
            table_address=r['rip_references'][0];off=image.offset(table_address-image.pe.base)
            if struct.unpack_from('<Q',raw,off+0x48)[0]==prepare:found.append(table_address)
        if len(found)!=1:raise ValueError('Wrapper constructor/table/Version slot differs')
        links['wrapper_table']=hex(found[0]);links['version_slot']=0x48
    allocator,copy=calls[1:]
    harness_context=dict(context,helpers=dict(memcpy=hex(copy)))
    h=load('update-native-harness').make_harness(harness_context,exports,{ctor,prepare},
        leaves={getter:getter_bytes.hex()},root=root)
    obj,temp,storage,rbp,stack=[h.scratch+n for n in (0x1000,0x18000,0x19000,0x10000,0x8000)]
    expected=tag[:-1].decode('ascii').encode('utf-16le')+b'\0\0'
    mode={'name':'constructor'};events=[]
    def construct(machine):
        a,b=[machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX,h.x.UC_X86_REG_RDX)]
        destination=obj+spec['tag_field'] if mode['name']=='constructor' else stack+spec['temporary_offset']
        if (a,b)!=(destination,literal):raise ValueError('ASCII fixture source/destination differs')
        machine.mem_write(temp,expected);machine.mem_write(a,struct.pack('<QII',temp,33,33))
        events.append('ascii');h.finish(a)
    def allocate(machine):
        a,b=[machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX,h.x.UC_X86_REG_RDX)]
        if (a,b)!=(rbp+spec['destination_offset'],33):raise ValueError('Allocation fixture differs')
        machine.mem_write(a,struct.pack('<Q',storage));machine.mem_write(a+12,struct.pack('<I',33))
        events.append('allocate');h.finish(a)
    h.add_fixture(ascii_ctor,construct);h.add_fixture(allocator,allocate)
    def copy_fixture(machine):
        a,b,count=[machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX,h.x.UC_X86_REG_RDX,h.x.UC_X86_REG_R8)]
        if (a,b,count)!=(storage,temp,66):raise ValueError('Memcpy fixture differs')
        machine.mem_write(a,bytes(machine.mem_read(b,count)));events.append('copy');h.finish(a)
    h.add_fixture(copy,copy_fixture)
    cases=[]
    for poison in (0,0x55,0xaa,0xff):
        events.clear();mode['name']='constructor'
        h.uc.mem_write(obj-16,b'\xa5'*16+bytes([poison])*spec['object_size']+b'\xa5'*16)
        h.call(ctor,obj)
        if struct.unpack('<Q',bytes(h.uc.mem_read(obj,8)))[0]!=table:raise ValueError('Native constructor vptr differs')
        if bytes(h.uc.mem_read(obj+spec['tag_field'],16))!=struct.pack('<QII',temp,33,33):
            raise ValueError('Native constructor tag field differs')
        if h.call(getter,obj)!=spec['packet_id']:raise ValueError('Native getter ID differs')
        if any(bytes(h.uc.mem_read(a,16))!=b'\xa5'*16 for a in (obj-16,obj+spec['object_size'])):
            raise ValueError('Constructor crossed object guard')
        mode['name']='prepare';events.clear()
        destination=rbp+spec['destination_offset']
        h.uc.mem_write(destination-16,bytes([poison])*48);h.uc.mem_write(storage-16,b'\xa5'*98)
        for register,value in ((h.x.UC_X86_REG_RBP,rbp),(h.x.UC_X86_REG_RSP,stack),(h.x.UC_X86_REG_R14,0)):
            h.uc.reg_write(register,value)
        h.uc.emu_start(start,stop,count=2048)
        if h.uc.reg_read(h.x.UC_X86_REG_RIP)!=stop:raise ValueError('Tag slice instruction budget exceeded')
        if bytes(h.uc.mem_read(destination,16))!=struct.pack('<QII',storage,33,33) or bytes(h.uc.mem_read(storage,66))!=expected:
            raise ValueError('Native prepare output differs')
        for address,value in ((destination-16,bytes([poison])*16),(destination+16,bytes([poison])*16),
                              (storage-16,b'\xa5'*16),(storage+66,b'\xa5'*16)):
            if bytes(h.uc.mem_read(address,16))!=value:raise ValueError('Prepare slice crossed guard')
        cases.append(dict(poison=poison,packet_id=spec['packet_id'],events=events[:],guards=True))
    return dict(schema=1,source_sha256=context['source_sha256'],contract=context['contract']['id'],
        binding=dict(constructor=hex(ctor),prepare=hex(prepare),pointer=hex(pointer),literal=hex(literal),
            table=hex(table),packet_id=spec['packet_id'],packet_name=spec['packet_name'],tag=tag[:-1].decode()),
        cases=cases,links=links,evidence=h.evidence,network_used=False,profile_activated=False,
        limits=['Whole packet constructor and actual ID leaf; tag assignment slice only.',
            'ASCII FString conversion, allocation and memcpy are exact bounded fixtures.',
            'Full Version/Login preparation, SDK getters, wire IO and server acceptance remain unverified.'])
