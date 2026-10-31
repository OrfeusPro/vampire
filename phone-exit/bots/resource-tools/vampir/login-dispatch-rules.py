"""Source-bound dispatch/lookup, TLS and cleanup with proved child contracts."""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
from importlib.util import module_from_spec, spec_from_file_location

HERE=Path(__file__).resolve().parent
FAMILY='login-dispatch'
CURRENT='login-dispatch-v1'
REFERENCE='reference-login-dispatch'
BINDINGS={'dispatch','lookup','wrapper','tls','cleanup0','cleanup1','cleanup2','cleanup3','handler_table','packet_table','id_getter'}
META={'schema','source','source_sha256','family','format','layout','exports','transfer_proof','release_id','provenance'}
FIELDS={'functions','leaves','helpers','composition_context','container_context','bindings','globals','source_initial',
    'tls_index_span','literals','cleanup_vtables','call_sites','packet_bytes','packet_allocation_bytes','owner_bytes',
    'node_bytes','framing_minimum','verify_whole_exports'}
SHAPES={'dispatch':(154,647),'lookup':(45,171)}
LEAF_SIZES={'wrapper':7,'tls':30,'cleanup0':15,'cleanup1':31,'cleanup2':15,'cleanup3':11}


def load(name):
    s=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'));v=module_from_spec(s);s.loader.exec_module(v);return v


def tools():return {str(HERE/'login-dispatch-rules.py'):hashlib.sha256((HERE/'login-dispatch-rules.py').read_bytes()).hexdigest()}


def address(value):
    if not isinstance(value,str) or not re.fullmatch('0x[0-9a-f]+',value):raise ValueError('Dispatch address differs')
    return int(value,16)


def pointer(p):
    if (not isinstance(p,dict) or set(p)!={'path','sha256'} or not isinstance(p['path'],str) or not p['path']
            or not isinstance(p['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',p['sha256'])):raise ValueError('Dispatch child pointer differs')


def functional(c):
    if not isinstance(c,dict):raise ValueError('Dispatch context must be an object')
    for key in ('functions','leaves','helpers','bindings','globals','source_initial','tls_index_span','literals','cleanup_vtables','call_sites'):
        if not isinstance(c.get(key),dict):raise ValueError('Dispatch context field must be an object: '+key)
    if (set(c)-META!=FIELDS or type(c.get('schema'))is not int or c['schema']!=1 or c.get('family')!=FAMILY
            or c.get('format') not in (CURRENT,REFERENCE) or not isinstance(c.get('source'),str) or not c['source']
            or not isinstance(c.get('source_sha256'),str) or not re.fullmatch('[0-9a-f]{64}',c['source_sha256'])
            or set(c.get('bindings',{}))!=BINDINGS or set(c.get('globals',{}))!={'cookie','archive_flags','tls_index'}
            or set(c.get('source_initial',{}))!={'cookie','archive_flags'} or c.get('verify_whole_exports')is not True
            or set(c.get('literals',{}))!={'dispatch_name','lookup_name','unknown_format','read_failure_format','empty_utf16','packet_empty_ansi'}
            or set(c.get('cleanup_vtables',{}))!={'cleanup0','cleanup1','cleanup2','cleanup3'}
            or set(c.get('helpers',{}))!={'memcpy'} or set(c.get('call_sites',{}))!=set(c.get('functions',{}))):
        raise ValueError('Dispatch fields/source scope differ')
    for key,wanted in (('packet_bytes',352),('packet_allocation_bytes',344),('owner_bytes',80),('node_bytes',40),('framing_minimum',5)):
        if type(c.get(key))is not int or c[key]!=wanted:raise ValueError('Dispatch layout/precondition differs: '+key)
    for key in ('composition_context','container_context'):pointer(c[key])
    if (c['source_initial']['archive_flags']!='01000000' or not isinstance(c['source_initial']['cookie'],str)
            or not re.fullmatch('[0-9a-f]{16}',c['source_initial']['cookie'])):
        raise ValueError('Dispatch source initial flags/cookie differ')
    return {k:copy.deepcopy(v) for k,v in c.items() if k not in META}


def roots(c):
    functional(c)
    f=c['functions'];wanted={'dispatch','lookup'}|{'container.'+k for k in load('login-container-rules').FUNCTIONS}
    wanted|={'composition.'+k for k in (
        'handler.gate','handler.handler','input.bool','input.buffer_constructor','input.constructor','input.raw','input.std_string',
        'input.string','input.time','input.u16','input.u32','input.u64','input.utf8_convert','input.utf8_core','input.utf8_length',
        'input.utf8_scalar','packet.constructor','packet.period_constructor','packet.period_reader','packet.reader','packet.time_constructor','packet.time_reader')}
    actual={address(at) for at in f.values()}
    if set(f)!=wanted or len(actual)!=29 or len(c['leaves'])!=12:raise ValueError('Dispatch whole root/leaf inventory differs')
    for at in c['bindings'].values():address(at)
    for code in c['leaves'].values():
        if not isinstance(code,str) or not re.fullmatch('(?:[0-9a-f]{2})+',code):raise ValueError('Dispatch leaf bytes differ')
    leaves={address(at) for at in c['leaves']}
    if actual&leaves or len(leaves)!=12 or c['leaves'].get(c['bindings']['id_getter'])!='b804000000c3':
        raise ValueError('Dispatch native roots/leaves alias or ID differs')
    if any(len(bytes.fromhex(c['leaves'].get(c['bindings'][role],'')))!=size for role,size in LEAF_SIZES.items()):
        raise ValueError('Dispatch additional leaf extent differs')
    if f['dispatch']!=c['bindings']['dispatch'] or f['lookup']!=c['bindings']['lookup']:raise ValueError('Dispatch function bindings differ')
    return actual


def data(image,at,size):return load('version-system-transfer-rules').image_bytes(image,at,size)


def cstring(image,at):
    out=bytearray()
    for n in range(128):
        byte=data(image,at+n,1);out+=byte
        if byte==b'\0':return bytes(out)
    raise ValueError('Dispatch literal exceeds bound')


def calls(rows):return {hex(r['address']):hex(r['direct_target']) if r['direct_target']is not None else r['operands'] for r in rows if r['call']}


def direct(rows,offset):
    r=next((r for r in rows if r['address']-rows[0]['address']==offset),{})
    if r.get('call')is not True or r.get('direct_target')is None:raise ValueError('Dispatch declared direct call differs')
    return r['direct_target']


def rip(rows,offset):
    r=next((r for r in rows if r['address']-rows[0]['address']==offset),{})
    if len(r.get('rip_references',[]))!=1:raise ValueError('Dispatch declared RIP input differs')
    return r['rip_references'][0]


def whole(native,bindings,image,at,role):
    rr=bindings.rows(native,image,at)
    if not rr or rr[0]['address']!=at or (len(rr),sum(len(bytes.fromhex(r['bytes'])) for r in rr))!=SHAPES[role]:
        raise ValueError('Dispatch whole-body shape differs: '+role)
    return rr


def leaf_rows(native,image,at,size):
    if image.containing(at)is not None:raise ValueError('Dispatch declared frameless leaf has unwind')
    raw=data(image,at,size);cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
    decoded=list(cs.disasm(raw,at))
    if sum(r.size for r in decoded)!=size:raise ValueError('Dispatch leaf instruction boundary differs')
    return raw,decoded


def virtual_span(image,at):
    rva=at-image.pe.base
    selected=[s for s in image.pe.sections if s['rva']+s['raw_size']<=rva and rva+4<=s['rva']+s['size']]
    if len(selected)!=1 or selected[0]['name']!='.data':raise ValueError('TLS index is not the declared zero-initialized virtual tail')
    try:image.offset(rva)
    except ValueError:pass
    else:raise ValueError('TLS index unexpectedly file-backed')
    return dict(selected[0],address=hex(at),size_bytes=4)


def find_owners(image):
    names={}
    for role,name in (('dispatch',b'PacketDispatcher::Dispatch\0'),('lookup',b'PacketDispatcher::GetPacketHandler\0')):
        cursor=0;found=set()
        while True:
            cursor=image.data.find(name,cursor)
            if cursor<0:break
            at=image.pe.address(cursor)
            if at is not None:found.add(at)
            cursor+=len(name)
        if not 1<=len(found)<=4:raise ValueError('Dispatch literal inventory missing/ambiguous')
        for at in found:names[at]=role
    hits={'dispatch':set(),'lookup':set()}
    for section in image.pe.sections:
        if section['name']!='.text':continue
        end=section['raw']+section['raw_size']
        for rex in (0x48,0x4c):
            for modrm in (0x05,0x0d,0x15,0x1d,0x25,0x2d,0x35,0x3d):
                cursor=section['raw'];prefix=bytes([rex,0x8d,modrm])
                while True:
                    pos=image.data.find(prefix,cursor,end)
                    if pos<0:break
                    cursor=pos+3
                    if pos+7>end:continue
                    at=image.pe.address(pos);target=at+7+struct.unpack_from('<i',image.data,pos+3)[0]
                    if target not in names:continue
                    i=image.containing(at)
                    if i is not None:hits[names[target]].add(image.pe.base+image.roots[i][0])
    if any(len(v)!=1 for v in hits.values()):raise ValueError('Dispatch exact literal xrefs have multiple owners')
    return {k:next(iter(v)) for k,v in hits.items()}


def packet_empty_source(native,bindings,image,composition,container):
    constructor=bindings.rows(native,image,address(composition['functions']['packet.constructor']))
    sites=[r['address'] for r in constructor if r['call'] and r['direct_target']==address(container['functions']['string_constructor'])]
    empty=[r for r in constructor if r['mnemonic']=='lea' and r['operands'].startswith('rdx, ') and len(r['rip_references'])==1
        and len(sites)==1 and 0<sites[0]-r['address']<=32]
    if len(empty)!=1 or data(image,empty[0]['rip_references'][0],1)!=b'\0':raise ValueError('Dispatch packet trailing native ANSI constructor source differs')
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    for row in constructor:
        if not empty[0]['address']<row['address']<sites[0]:continue
        ins=next(decoder.disasm(bytes.fromhex(row['bytes']),row['address']))
        if any(ins.reg_name(reg) in ('rdx','edx','dx','dl','dh') for reg in ins.regs_access()[1]):
            raise ValueError('Dispatch trailing constructor source argument overwritten')
    return dict(address=hex(empty[0]['rip_references'][0]),bytes='00')


def project(root,native,bindings,image,composition,container,composition_pointer,container_pointer,*,format=CURRENT):
    core=load('portable-native-family')
    if (composition.get('family')!='login-response-composition' or container.get('family')!='login-container'
            or not composition.get('transfer_proof') or not container.get('transfer_proof')
            or composition['source_sha256']!=container['source_sha256'] or Path(composition['source']).resolve()!=Path(container['source']).resolve()):
        raise ValueError('Dispatch requires independent proved children for the same source')
    pointer(composition_pointer);pointer(container_pointer)
    found=find_owners(image);rr={k:whole(native,bindings,image,at,k) for k,at in found.items()}
    d,l=rr['dispatch'],rr['lookup'];reg=container['bindings']
    if reg['packet_table']!=composition['packet_table'] or reg['handler']!=composition['functions']['handler.handler']:
        raise ValueError('Dispatch child packet/handler links differ')
    getq=lambda at:int.from_bytes(data(image,at,8),'little')
    wrapper=getq(address(reg['handler_table'])+8)
    if getq(address(reg['handler_table'])+0x10)!=address(reg['handler']):raise ValueError('Dispatch handler table slot differs')
    b=dict(dispatch=hex(found['dispatch']),lookup=hex(found['lookup']),wrapper=hex(wrapper),tls=hex(direct(d,0xf8)),
        cleanup0=hex(direct(d,0x255)),handler_table=reg['handler_table'],packet_table=reg['packet_table'],id_getter=reg['id_getter'])
    if (direct(d,0xf0)!=address(composition['functions']['input.constructor']) or direct(d,0x22b)!=address(b['tls'])
            or direct(d,0x247)!=address(b['tls']) or direct(d,0x275)!=address(container['fixtures']['security'])
            or direct(d,0xb6)!=address(container['fixtures']['log']) or direct(d,0x203)!=direct(d,0xb6)
            or direct(l,0x96)!=direct(d,0xb6) or direct(d,0x172)!=address(container['fixtures']['utf8_length'])
            or direct(d,0x1ae)!=address(container['fixtures']['diagnostic_allocate'])
            or direct(d,0x1db)!=address(container['fixtures']['utf8_convert'])
            or direct(d,0x215)!=address(container['fixtures']['free']) or direct(d,0x224)!=direct(d,0x215)):
        raise ValueError('Dispatch native/fixture callee link differs')
    if [r['operands'] for r in d if r['call'] and r['direct_target']is None]!=[
            'qword ptr [rax + 0x20]','qword ptr [rax + 0x38]','qword ptr [rax + 8]'] or len(calls(d))!=16 or len(calls(l))!=1:
        raise ValueError('Dispatch virtual call inventory differs')
    leaves=copy.deepcopy(composition['leaves'])
    for at,code in container['leaves'].items():
        if at in leaves and leaves[at]!=code:raise ValueError('Dispatch child leaves conflict')
        leaves[at]=code
    raw,dec=leaf_rows(native,image,wrapper,7)
    if raw!=bytes.fromhex('488b0148ff6010'):raise ValueError('Dispatch handler wrapper differs')
    leaves[hex(wrapper)]=raw.hex()
    raw,dec=leaf_rows(native,image,address(b['tls']),30)
    if len(dec)!=6 or [r.mnemonic for r in dec]!=['mov','mov','mov','mov','mov','ret']:
        raise ValueError('Dispatch TLS leaf shape differs')
    tls_refs=[r.address+r.size+o.mem.disp for r in dec for o in r.operands if o.type==native.X86_OP_MEM and o.mem.base==native.X86_REG_RIP]
    if (len(tls_refs)!=1 or dec[1].op_str!='rax, qword ptr gs:[0x58]' or dec[2].op_str!='r8d, 0x100cc0'
            or dec[3].op_str!='rax, qword ptr [rax + rdx*8]' or dec[4].op_str!='qword ptr [r8 + rax], rcx'):
        raise ValueError('Dispatch TLS provider slot/argument contract differs')
    span=virtual_span(image,tls_refs[0]);leaves[b['tls']]=raw.hex();vtables={}
    for i in range(4):
        role='cleanup'+str(i);at=address(b[role]);raw,dec=leaf_rows(native,image,at,LEAF_SIZES[role]);leaves[b[role]]=raw.hex()
        refs=[r.address+r.size+o.mem.disp for r in dec for o in r.operands if o.type==native.X86_OP_MEM and o.mem.base==native.X86_REG_RIP]
        if len(refs)!=1 or dec[0].mnemonic!='lea' or dec[1].op_str!='qword ptr [rcx], rax':raise ValueError('Dispatch cleanup vptr contract differs')
        vtables[role]=hex(refs[0])
        if i<3:
            if dec[-1].mnemonic!='jmp' or dec[-1].operands[0].type!=native.capstone.x86.X86_OP_IMM:raise ValueError('Dispatch cleanup tail differs')
            b['cleanup'+str(i+1)]=hex(dec[-1].operands[0].imm)
        elif dec[-1].mnemonic!='ret':raise ValueError('Dispatch final cleanup return differs')
    reader=core.checked(root,composition['reader_context'],'generated-native-contexts')
    handler=core.checked(root,composition['handler_context'],'generated-native-contexts')
    gate=core.checked(root,handler['gate_context'],'generated-native-contexts')
    if vtables['cleanup0']!=reader['input']['table']:raise ValueError('Dispatch cleanup archive table differs')
    literals={}
    for role,rows,offset,size in (('dispatch_name',d,0xaf,None),('lookup_name',l,0x8f,None),('unknown_format',d,0xa3,None),
            ('read_failure_format',d,0x1f0,None),('empty_utf16',d,0x14a,2)):
        at=rip(rows,offset);raw=data(image,at,size) if size else cstring(image,at);literals[role]=dict(address=hex(at),bytes=raw.hex())
    if (bytes.fromhex(literals['dispatch_name']['bytes'])!=b'PacketDispatcher::Dispatch\0'
            or bytes.fromhex(literals['lookup_name']['bytes'])!=b'PacketDispatcher::GetPacketHandler\0'
            or literals['empty_utf16']['bytes']!='0000' or rip(l,0x83)!=address(literals['unknown_format']['address'])
            or rip(d,0x1fc)!=address(literals['dispatch_name']['address'])):raise ValueError('Dispatch literal roles differ')
    literals['packet_empty_ansi']=packet_empty_source(native,bindings,image,composition,container)
    cookie,flags=rip(d,13),rip(d,0xcc)
    if cookie!=address(container['globals']['cookie']):raise ValueError('Dispatch source cookie differs')
    source_initial=dict(cookie=data(image,cookie,8).hex(),archive_flags=data(image,flags,4).hex())
    if source_initial['archive_flags']!='01000000':raise ValueError('Dispatch archive flags initial value changed')
    if {r['address']-found['dispatch'] for r in d if r['rip_references']}!={13,0xa3,0xaf,0xcc,0x14a,0x1f0,0x1fc}:
        raise ValueError('Dispatch undeclared RIP input')
    if {r['address']-found['lookup'] for r in l if r['rip_references']}!={0x83,0x8f}:raise ValueError('Lookup undeclared RIP input')
    functions={'composition.'+key:at for key,at in composition['functions'].items()}
    functions.update({'container.'+key:at for key,at in container['functions'].items()});functions.update({k:hex(v) for k,v in found.items()})
    call_sites={}
    for role,at in functions.items():
        rows=load('result-gate-transfer-rules').rows(native,image,gate) if role=='composition.handler.gate' else bindings.rows(native,image,address(at))
        call_sites[role]=calls(rows)
    c=dict(schema=1,family=FAMILY,format=format,source=composition['source'],source_sha256=composition['source_sha256'],
        functions=functions,leaves=leaves,helpers=copy.deepcopy(composition['helpers']),composition_context=copy.deepcopy(composition_pointer),
        container_context=copy.deepcopy(container_pointer),bindings=b,globals=dict(cookie=hex(cookie),archive_flags=hex(flags),tls_index=hex(tls_refs[0])),
        source_initial=source_initial,tls_index_span=span,literals=literals,cleanup_vtables=vtables,call_sites=call_sites,
        packet_bytes=352,packet_allocation_bytes=344,owner_bytes=80,node_bytes=40,framing_minimum=5,verify_whole_exports=True)
    roots(c);return c,rr


def parents(root,c):
    core=load('portable-native-family')
    return tuple(core.checked(root,c[key+'_context'],'generated-native-contexts') for key in ('composition','container'))


def validate_static(root,native,bindings,image,c):
    roots(c);comp,container=parents(root,c)
    candidate,rr=project(root,native,bindings,image,comp,container,c['composition_context'],c['container_context'],format=c['format'])
    if candidate['source_sha256']!=c['source_sha256'] or Path(candidate['source']).resolve()!=Path(c['source']).resolve() or functional(candidate)!=functional(c):
        raise ValueError('Dispatch source projection differs')
    return rr


def pair_declared_leaf(native,old_rows,new_rows,declared,mapping):
    common=load('update-native-archive-wire');signature=load('update-native-contexts').signature
    if signature(native,old_rows)!=signature(native,new_rows):raise ValueError('Dispatch leaf whole shape changed')
    locations={r['address'] for r in old_rows}
    for a,b in zip(old_rows,new_rows):
        if a['branch'] and a['direct_target'] not in locations and a['direct_target'] not in declared:
            raise ValueError('Dispatch cleanup tail is not an explicit leaf')
        common.add_link(mapping,a['address'],b['address'])
        if a['direct_target']is not None:common.add_link(mapping,a['direct_target'],b['direct_target'])
        if len(a['rip_references'])!=len(b['rip_references']):raise ValueError('Dispatch leaf data edges differ')
        for x,y in zip(a['rip_references'],b['rip_references']):common.add_link(mapping,x,y)


def transfer(root,native,bindings,before,after,baseline,mapping,composition,container,*,composition_pointer,container_pointer):
    previous=validate_static(root,native,bindings,before,baseline)
    current,rr=project(root,native,bindings,after,composition,container,composition_pointer,container_pointer)
    common=load('update-native-archive-wire')
    for role in SHAPES:common.pair_rows(native,previous[role],rr[role],mapping)
    for group in ('functions','bindings','globals','cleanup_vtables'):
        for role,at in baseline[group].items():common.add_link(mapping,address(at),address(current[group][role]))
    for role in baseline['literals']:
        if baseline['literals'][role]['bytes']!=current['literals'][role]['bytes']:raise ValueError('Dispatch typed literal changed')
        common.add_link(mapping,address(baseline['literals'][role]['address']),address(current['literals'][role]['address']))
    if baseline['source_initial']!=current['source_initial']:raise ValueError('Dispatch source initial data changed')
    for role,size in LEAF_SIZES.items():
        at,bt=address(baseline['bindings'][role]),address(current['bindings'][role])
        old,_=leaf_rows(native,before,at,size);new,_=leaf_rows(native,after,bt,size)
        cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
        def decode(raw,base):
            return [dict(address=r.address,bytes=bytes(r.bytes).hex(),mnemonic=r.mnemonic,operands=r.op_str,
                call=r.mnemonic=='call',branch=r.mnemonic.startswith('j'),direct_target=r.operands[0].imm if r.mnemonic.startswith('j') and r.operands[0].type==native.capstone.x86.X86_OP_IMM else None,
                rip_references=[r.address+r.size+o.mem.disp for o in r.operands if o.type==native.X86_OP_MEM and o.mem.base==native.X86_REG_RIP]) for r in cs.disasm(raw,base)]
        if role=='wrapper':
            if old!=new or old!=bytes.fromhex('488b0148ff6010'):raise ValueError('Dispatch wrapper contract changed')
            common.add_link(mapping,at,bt)
        else:
            old_rows,new_rows=decode(old,at),decode(new,bt)
            pair_declared_leaf(native,old_rows,new_rows,{address(baseline['bindings'][k]) for k in LEAF_SIZES},mapping)
    return current,dict(method='native_dispatch_with_independent_children_tls_and_cleanup',new_whole_shapes={k:list(v) for k,v in SHAPES.items()},
        child_contexts=dict(composition=composition_pointer,container=container_pointer),framing_precondition=5,initial_active_packet=0,
        os_tls_provider='Synthetic index/provider; source-bound setter and cleanup execute natively',session_executed=False)


def export_coverage(root,c,native,bindings,image):
    rr=validate_static(root,native,bindings,image,c);expected={address(c['functions'][k]):v for k,v in rr.items()};seen=set()
    for run,sha in c.get('exports',{}).items():
        if Path(run).name!=run or not run.startswith('run-'):raise ValueError('Dispatch export name differs')
        p=Path(root)/'ghidra/request-exports'/c['source_sha256']/run/'details.json';raw=p.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('Dispatch export hash differs')
        report=json.loads(raw)
        if report.get('new_source_sha256',report.get('source_sha256'))!=c['source_sha256']:raise ValueError('Dispatch export source differs')
        for fn in report['functions']:
            at=address(fn['address'])
            if at not in expected:continue
            if any(fn.get(flag)is not True for flag in ('decompilation_completed','block_coverage_complete','direct_flow_coverage_complete')):
                raise ValueError('Dispatch export whole coverage incomplete')
            rows=[(address(r['address']),r['bytes'].lower()) for r in fn['instructions']]
            wanted=[(r['address'],r['bytes'].lower()) for r in expected[at]]
            if len(rows)!=len(set(a for a,_ in rows)) or sorted(rows)!=sorted(wanted):raise ValueError('Dispatch export whole instructions differ')
            load('audit-launcher-shape-11318').normalize_function(native,image,fn);seen.add(at)
    if seen!=set(expected):raise ValueError('Dispatch exports lack both whole roots')
    comp,container=parents(root,c)
    load('login-composition-rules').export_coverage(root,comp,native,bindings,image)
    load('login-container-rules').export_coverage(root,container,native,bindings,image)
