"""Portable VersionResult and bounded shared input-buffer/scalar verification.

String code is carried as checked source material but VersionResult does not
execute string fields. Endian-swap/string/OS effects remain outside this scope.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
from types import SimpleNamespace
from importlib.util import spec_from_file_location,module_from_spec

HERE=Path(__file__).resolve().parent
ADAPTER='version-result-v1'
FAMILY='version-result'
SCOPE='bounded_native_version_result_input'
INDEX='generated-version-results'
PROOFS='native-version-result-proofs'
WINDOW=65536
SLOTS={0x28:'time',0x30:'std_string',0x50:'u64',0x58:'u32',0x60:'u32',0x70:'u16',0x88:'bool',0x90:'raw'}
LAYOUT=dict(abi='win64',packet_bytes=40,body_bytes=17,input_bytes=64,input_table_bytes=152,
            reading_mode=1,reading_endian=0,reader_slot=32,id_slot=40,max_buffer=4096,max_leaf_bytes=512)
TOOLS=('update-native-version-result.py','verify-version-result-context.py','login-result-input-fixtures.py',
       'update-native-contexts.py','update-native-harness.py','update-bindings.py',
       'build-native-entry-code.py','build-object-zero-init-code.py','extract-native-enums.py',
       'native-release-registry.py','research-workflow.py','knowledge-index.py','knowledge-context.py',
       'audit-launcher-shape-11318.py')
INPUT_NAMES={'constructor','u16','u32','time','u64','bool','raw','string','std_string',
             'utf8_length','utf8_convert','utf8_core','utf8_scalar','buffer_constructor'}
TAIL_BYTES=bytes.fromhex('488b0141b80100000048ffa090000000')


def load(name):
    spec=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def tools():
    result={str(HERE/name):digest(HERE/name) for name in TOOLS}
    decoder=HERE.parents[1]/'vampir-shared/vampir_core/version_result.py'
    result[str(decoder)]=digest(decoder)
    return result
def checked(root,item,category):return load('update-native-contexts').checked(root,item,category)
def image_bytes(image,at,size):return load('update-native-contexts').image_bytes(image,at,size)


def plain(context):
    value=copy.deepcopy(context)
    for key in ('transfer_proof','exports','release_id'):value.pop(key,None)
    nested=value.get('native_input',{})
    for key in ('portable_buffer_proof','exports'):nested.pop(key,None)
    return value


def roots(context):
    functions=context['native_input']['functions']
    if set(functions)!=INPUT_NAMES:raise ValueError('Version input function scope differs')
    result={int(at,16) for at in functions.values()}|{int(context['reader'],16)}
    if len(result)!=15:raise ValueError('Version input requires fifteen explicit roots')
    return result


def add_link(mapping,a,b):
    if type(a) is not int or type(b) is not int:raise ValueError('Invalid Version relocation edge')
    if a in mapping and mapping[a]!=b:raise ValueError('Inconsistent Version relocation edge')
    mapping[a]=b


def pair_rows(native,before,after,mapping,*,tail=False):
    signature=load('update-native-contexts').signature
    if signature(native,before)!=signature(native,after):raise ValueError('Version instruction/control shape changed')
    locations={row['address'] for row in before}
    for old,new in zip(before,after):
        if old['branch'] and not old['call'] and old['direct_target'] not in locations:
            if not tail or old is not before[-1] or old.get('operands')!='qword ptr [rax + 0x90]':
                raise ValueError('Version external branch is not admitted')
        if (old['call'] or (tail and old is before[-1])) and old['direct_target'] is None and not old['rip_references']:
            if old.get('operands')!=new.get('operands'):raise ValueError('Version indirect dispatch changed')
        add_link(mapping,old['address'],new['address'])
        if old['direct_target'] is not None:add_link(mapping,old['direct_target'],new['direct_target'])
        if len(old['rip_references'])!=len(new['rip_references']):raise ValueError('Version data edge count changed')
        for a,b in zip(old['rip_references'],new['rip_references']):add_link(mapping,a,b)


def leaf_rows(native,image,at,spec,*,tail=False):
    raw=bytes.fromhex(spec['bytes'])
    if not 1<=len(raw)<=512 or hashlib.sha256(raw).hexdigest()!=spec['sha256']:
        raise ValueError('Version leaf size or hash differs')
    actual=image_bytes(image,at,len(raw));decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    instructions=list(decoder.disasm(actual,at))
    if sum(row.size for row in instructions)!=len(raw) or not instructions:raise ValueError('Version leaf instruction gap')
    if tail:
        if raw!=TAIL_BYTES or actual!=TAIL_BYTES or instructions[-1].mnemonic!='jmp' or instructions[-1].op_str!='qword ptr [rax + 0x90]':
            raise ValueError('Version typed byte-reader tail differs')
    elif instructions[-1].mnemonic!='ret':raise ValueError('Version returning leaf boundary differs')
    locations={row.address for row in instructions};result=[]
    for ins in instructions:
        call=ins.group(native.capstone.CS_GRP_CALL);branch=ins.group(native.capstone.CS_GRP_JUMP)
        target=ins.operands[0].imm if (call or branch) and ins.operands and ins.operands[0].type==native.X86_OP_IMM else None
        if call or (branch and target not in locations and not (tail and ins is instructions[-1])):
            raise ValueError('Version leaf external edge')
        result.append(dict(address=ins.address,bytes=ins.bytes.hex(),mnemonic=ins.mnemonic,operands=ins.op_str,
            call=call,branch=branch,direct_target=target,rip_references=[ins.address+ins.size+op.mem.disp for op in ins.operands
                if op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP]))
    return result


def baseline_leaf(image,at,spec):
    raw=bytes.fromhex(spec['bytes'])
    if not 1<=len(raw)<=512 or hashlib.sha256(raw).hexdigest()!=spec['sha256'] or image_bytes(image,at,len(raw))!=raw:
        raise ValueError('Version baseline leaf bytes/hash changed')


def candidates(native,bindings,before,after,at):
    old=bindings.rows(native,before,at);span=before.roots[before.containing(at)]
    possible={row for row in after.roots.values() if abs(after.pe.base+row[0]-at)<=WINDOW and row[1]-row[0]==span[1]-span[0]}
    if len(possible)>4096:raise ValueError('Version root candidate budget exceeded')
    signature=load('update-native-contexts').signature;expected=signature(native,old);hits=[]
    for row in sorted(possible):
        current=after.pe.base+row[0]
        try:new=bindings.rows(native,after,current)
        except ValueError:continue
        if signature(native,new)==expected:hits.append(current)
    if not hits or len(hits)>32:raise ValueError('Version missing/excess root candidates: '+hex(at))
    return hits


def resolve_roots(native,bindings,before,after,addresses,mapping):
    reports={at:candidates(native,bindings,before,after,at) for at in sorted(addresses)};pending=set(addresses)
    while pending:
        progress=False
        for at in sorted(pending):
            hits=reports[at]
            if at in mapping:hits=[hit for hit in hits if hit==mapping[at]]
            if len(hits)!=1:continue
            target=hits[0];add_link(mapping,at,target)
            pair_rows(native,bindings.rows(native,before,at),bindings.rows(native,after,target),mapping)
            pending.remove(at);progress=True
        if not progress:raise ValueError('Version ambiguous call-constrained roots: '+','.join(hex(at) for at in sorted(pending)))
    return {hex(at):hex(mapping[at]) for at in sorted(addresses)}


def table_candidates(image,old_table,target,slot,size):
    hits=[];pattern=struct.pack('<Q',target)
    for section in image.pe.sections:
        if section['name']!='.rdata':continue
        start=max(section['rva'],old_table-image.pe.base-WINDOW)
        end=min(section['rva']+section['raw_size']-size,old_table-image.pe.base+WINDOW)
        if end<start:continue
        cursor=image.offset(start)+slot;stop=image.offset(end)+slot+8
        while cursor<stop:
            cursor=image.data.find(pattern,cursor,stop)
            if cursor<0:break
            table=image.pe.base+section['rva']+cursor-section['raw']-slot;cursor+=1
            if table%8==0:hits.append(table)
    return sorted(set(hits))


def table_links(before,after,old_at,new_at,old_bytes,mapping,used):
    old=bytes.fromhex(old_bytes);new=image_bytes(after,new_at,len(old))
    if not old or len(old)%8 or image_bytes(before,old_at,len(old))!=old:
        raise ValueError('Version baseline pointer table changed')
    old_values=struct.unpack('<'+'Q'*(len(old)//8),old);new_values=struct.unpack('<'+'Q'*(len(new)//8),new)
    for a,b in zip(old_values,new_values):add_link(mapping,a,b)
    # Every known role and duplicate slot must retain one consistent identity.
    if len(set(old_values))!=len(set(new_values)):raise ValueError('Version pointer table alias topology changed')
    return dict(address=hex(new_at),bytes=new.hex(),sha256=hashlib.sha256(new).hexdigest(),
        used_slots=sorted(used),excluded_slots=[slot for slot in range(0,len(old),8) if slot not in used],
        excluded_scope='Unexecuted slot code is not admitted by its pointer or table bytes.')


def cookie_address(image):
    pe=struct.unpack_from('<I',image.data,60)[0];opt=pe+24
    if struct.unpack_from('<H',image.data,opt)[0]!=0x20b or struct.unpack_from('<I',image.data,opt+108)[0]<=10:
        raise ValueError('Version string cookie needs PE32+ load config')
    rva,size=struct.unpack_from('<II',image.data,opt+112+80)
    if not rva or size<96:raise ValueError('Version string cookie load config is absent')
    offset=image.offset(rva)
    if struct.unpack_from('<I',image.data,offset)[0]<96:raise ValueError('Version string cookie load config truncated')
    return struct.unpack_from('<Q',image.data,offset+88)[0]


def call_sites(native,bindings,image,functions):
    return {hex(row['address']):{'target':hex(row['direct_target']) if row['direct_target'] is not None else row['operands']}
        for at in functions.values() for row in bindings.rows(native,image,int(at,16)) if row['call']}


def static_inputs(native,bindings,before,after,baseline,mapping):
    nested=baseline['native_input'];known={int(nested['table'],16),int(nested['buffer_construction']['base_table'],16)}
    cookie=int(nested['cookie'],16);result=[];seen=set()
    if cookie_address(before)!=cookie or cookie_address(after)!=mapping[cookie]:raise ValueError('Version string cookie linkage changed')
    imports=load('build-object-zero-init-code')
    for at in nested['functions'].values():
        for row in bindings.rows(native,before,int(at,16)):
            for ref in row['rip_references']:
                if ref in known or ref in seen:continue
                seen.add(ref);new=mapping[ref]
                if row['call']:
                    old_identity=imports.import_at(before.data,before,ref);new_identity=imports.import_at(after.data,after,new)
                    allowed=('api-ms-win-crt-runtime-l1-1-0.dll','_invalid_parameter_noinfo_noreturn')
                    if (old_identity['dll'].lower(),old_identity['name'])!=allowed or (new_identity['dll'].lower(),new_identity['name'])!=allowed:
                        raise ValueError('Version input string import identity changed')
                    result.append(dict(address=hex(new),kind='unexecuted-string-import',identity=new_identity));continue
                if ref==cookie:
                    result.append(dict(address=hex(new),kind='unexecuted-string-cookie',bytes=image_bytes(after,new,8).hex()));continue
                expected=bytes.fromhex('00000000000000000f00000000000000')
                if image_bytes(before,ref,16)!=expected or image_bytes(after,new,16)!=expected:
                    raise ValueError('Version undeclared static input data')
                result.append(dict(address=hex(new),kind='unexecuted-string-SSO',bytes=expected.hex()))
    return result


def leaf_candidate(native,before,after,at,spec,mapping):
    baseline_leaf(before,at,spec)
    old=leaf_rows(native,before,at,spec);signature=load('update-native-contexts').signature;expected=signature(native,old)
    size=len(bytes.fromhex(spec['bytes']));hits=[]
    for section in after.pe.sections:
        if section['name']!='.text':continue
        first=max(section['rva'],at-after.pe.base-WINDOW);last=min(section['rva']+section['raw_size']-size,at-after.pe.base+WINDOW)
        if last<first:continue
        cursor=after.offset(first);stop=after.offset(last)+1;prefix=bytes.fromhex(spec['bytes'])[:3]
        while cursor<stop:
            cursor=after.data.find(prefix,cursor,stop)
            if cursor<0:break
            target=after.pe.base+section['rva']+cursor-section['raw'];cursor+=1
            try:new=leaf_rows(native,after,target,spec)
            except ValueError:continue
            if signature(native,new)!=expected:continue
            revised=dict(mapping)
            try:pair_rows(native,old,new,revised)
            except ValueError:continue
            hits.append(target)
            if len(hits)>32:raise ValueError('Version leaf candidate budget exceeded')
    if len(hits)!=1:raise ValueError('Version missing/ambiguous bounded leaf: '+hex(at))
    return hits[0]


def transfer(native,bindings,before,after,baseline,sha,source):
    old_input=baseline['native_input'];mapping={};root_map=resolve_roots(native,bindings,before,after,roots(baseline),mapping)
    if call_sites(native,bindings,before,old_input['functions'])!=old_input['call_sites']:
        raise ValueError('Version baseline input call-site declaration differs')
    if {hex(row['address']):row['operands'] for row in bindings.rows(native,before,int(baseline['reader'],16)) if row['call']}!=baseline['call_sites']:
        raise ValueError('Version baseline packet call-site declaration differs')
    if set(old_input['leaves'])-set(baseline['leaves']) or len(baseline['leaves'])!=5 or len(old_input['leaves'])!=3:
        raise ValueError('Version leaf scope differs')
    for at,spec in old_input['leaves'].items():
        if baseline['leaves'][at]!=spec:raise ValueError('Version nested leaf declaration differs')
    def mapped(text):
        at=int(text,16)
        if at not in mapping:raise ValueError('Version undeclared address relocation: '+text)
        return hex(mapping[at])
    old_table=int(old_input['table'],16)
    if len(bytes.fromhex(old_input['table_bytes']))!=152:raise ValueError('Version input table layout differs')
    if old_table not in mapping:raise ValueError('Version input table has no constructor linkage')
    input_relation=table_links(before,after,old_table,mapping[old_table],old_input['table_bytes'],mapping,SLOTS)
    for slot,name in SLOTS.items():
        if struct.unpack_from('<Q',bytes.fromhex(input_relation['bytes']),slot)[0]!=int(mapped(old_input['functions'][name]),16):
            raise ValueError('Version input table role changed: '+name)
    packet_table=int(baseline['packet_table'],16);packet_spec=next((row for row in baseline['tables'] if int(row['address'],16)==packet_table),None)
    if packet_spec is None or len(bytes.fromhex(packet_spec['bytes']))!=80:raise ValueError('Version packet table scope differs')
    if hashlib.sha256(bytes.fromhex(packet_spec['bytes'])).hexdigest()!=packet_spec['sha256']:raise ValueError('Version baseline packet table hash differs')
    hits=table_candidates(after,packet_table,int(mapped(baseline['reader']),16),32,80)
    if len(hits)!=1:raise ValueError('Version missing/ambiguous reader-linked packet table')
    add_link(mapping,packet_table,hits[0]);packet_relation=table_links(before,after,packet_table,hits[0],packet_spec['bytes'],mapping,{32,40})
    if struct.unpack_from('<Q',bytes.fromhex(packet_spec['bytes']),32)[0]!=int(baseline['reader'],16):
        raise ValueError('Version baseline packet reader slot differs')
    if struct.unpack_from('<Q',bytes.fromhex(packet_spec['bytes']),40)[0]!=int(baseline['id_getter'],16):
        raise ValueError('Version baseline packet ID slot differs')
    packet_ctor=int(baseline['constructor'],16)
    if packet_ctor not in mapping:add_link(mapping,packet_ctor,leaf_candidate(native,before,after,packet_ctor,baseline['leaves'][baseline['constructor']],mapping))
    leaves={};leaf_data=[]
    for text,spec in baseline['leaves'].items():
        at=int(text,16)
        baseline_leaf(before,at,spec)
        if at not in mapping:raise ValueError('Version leaf has no caller/table constraint')
        target=mapping[at];tail=bytes.fromhex(spec['bytes'])==TAIL_BYTES
        old=leaf_rows(native,before,at,spec,tail=tail);new=leaf_rows(native,after,target,spec,tail=tail)
        pair_rows(native,old,new,mapping,tail=tail)
        raw=image_bytes(after,target,len(bytes.fromhex(spec['bytes'])))
        leaves[hex(target)]=dict(bytes=raw.hex(),sha256=hashlib.sha256(raw).hexdigest())
        if at==packet_ctor:
            refs=[ref for row in old for ref in row['rip_references'] if ref!=packet_table]
            if len(refs)!=2:raise ValueError('Version packet constructor default fields differ')
            for ref in refs:
                old_bytes=image_bytes(before,ref,4);new_bytes=image_bytes(after,mapping[ref],4)
                if old_bytes!=b'\x01\0\0\0' or new_bytes!=old_bytes:raise ValueError('Version packet default uint32 changed')
                leaf_data.append(dict(address=hex(mapping[ref]),bytes=new_bytes.hex(),scope='packet-constructor uint32 default'))
    if leaves[mapped(baseline['id_getter'])]['bytes']!='b802000000c3':raise ValueError('Version ID getter is not 2')
    base_spec=old_input.get('buffer_construction')
    if (not isinstance(base_spec,dict) or set(base_spec)!={'base_table','reading_mode','reading_endian'}
            or type(base_spec.get('reading_mode')) is not int or type(base_spec.get('reading_endian')) is not int
            or base_spec['reading_mode']!=1 or base_spec['reading_endian']!=0):
        raise ValueError('Version buffer construction mode/endian differs')
    base_table=int(base_spec['base_table'],16)
    if base_table not in mapping:raise ValueError('Version buffer base vptr has no constructor link')
    # Shared string/UTF8 code is source-bound and exported but not executed by
    # this packet. Preserve declared call/data boundaries without claiming it.
    nested=copy.deepcopy(old_input);nested.pop('portable_buffer_proof',None);nested.pop('exports',None)
    nested['source_sha256']=sha;nested['functions']={key:mapped(at) for key,at in old_input['functions'].items()}
    nested['leaves']={mapped(at):leaves[mapped(at)] for at in old_input['leaves']};nested['table']=mapped(old_input['table'])
    nested['table_bytes']=input_relation['bytes'];nested['buffer_construction']=dict(base_table=mapped(base_spec['base_table']),reading_mode=1,reading_endian=0)
    nested['call_sites']=call_sites(native,bindings,after,nested['functions'])
    for key,at in old_input.get('string_fixtures',{}).items():nested['string_fixtures'][key]=mapped(at)
    if old_input.get('cookie'):nested['cookie']=mapped(old_input['cookie'])
    name=next((row for row in baseline['tables'] if row is not packet_spec),None)
    if len(baseline['tables'])!=2 or name is None or int(name['address'],16)!=packet_table+80 or bytes.fromhex(name['bytes'])!=b'PktVersionResult\0':
        raise ValueError('Version packet-name literal scope differs')
    literal_at=hits[0]+80;literal=image_bytes(after,literal_at,len(bytes.fromhex(name['bytes'])))
    if literal!=bytes.fromhex(name['bytes']) or hashlib.sha256(literal).hexdigest()!=name['sha256']:
        raise ValueError('Version packet-name literal changed')
    packet_calls={hex(row['address']):row['operands'] for row in bindings.rows(native,after,int(mapped(baseline['reader']),16)) if row['call']}
    if len(packet_calls)!=5:raise ValueError('Version reader virtual-call scope differs')
    current=dict(schema=1,family=FAMILY,source_sha256=sha,source=str(source),layout=LAYOUT,verify_whole_exports=True,
        helpers={key:mapped(at) for key,at in baseline['helpers'].items()},reader=mapped(baseline['reader']),constructor=mapped(baseline['constructor']),
        packet_table=mapped(baseline['packet_table']),id_getter=mapped(baseline['id_getter']),leaves=leaves,native_input=nested,call_sites=packet_calls,
        tables=[dict(address=hex(hits[0]),bytes=packet_relation['bytes'],sha256=packet_relation['sha256']),dict(address=hex(literal_at),bytes=literal.hex(),sha256=name['sha256'])])
    roots(current)
    load('update-native-contexts').memcpy_identity(native,before,int(baseline['helpers']['memcpy'],16))
    load('update-native-contexts').memcpy_identity(native,after,int(current['helpers']['memcpy'],16))
    return current,dict(roots=root_map,mapping={hex(a):hex(b) for a,b in sorted(mapping.items())},
        input_table=input_relation,packet_table=packet_relation,default_fields=leaf_data,
        static_inputs=static_inputs(native,bindings,before,after,baseline,mapping),
        base_buffer_vptr=dict(address=hex(mapping[base_table]),bytes=image_bytes(after,mapping[base_table],8).hex(),scope='constructor vptr only, not dispatch'),
        scope_limits=['Only VersionResult scalar/raw and bounded buffer constructors execute.',
            'String/UTF8 and endian-swap/exception callees are carried as static source links; no semantic coverage for those branches.'])


def export_coverage(root,context,native,bindings,image):
    required=roots(context);available=set();declared=dict(context.get('exports',{}))
    for run,expected in context['native_input'].get('exports',{}).items():
        if run in declared and declared[run]!=expected:raise ValueError('Conflicting Version export hashes')
        declared[run]=expected
    for run,expected in declared.items():
        if not isinstance(run,str) or Path(run).name!=run or not run.startswith('run-'):raise ValueError('Invalid Version export name')
        path=Path(root)/'ghidra/request-exports'/context['source_sha256']/run/'details.json'
        if digest(path)!=expected:raise ValueError('Version export changed')
        report=json.loads(path.read_text('utf-8'))
        if report.get('new_source_sha256',report.get('source_sha256'))!=context['source_sha256']:raise ValueError('Version export source differs')
        for function in report.get('functions',[]):
            at=int(function['address'],16)
            if at not in required or function.get('decompilation_completed') is not True:continue
            actual={(int(row['address'],16),row['bytes'].lower()) for row in function.get('instructions',[])}
            expected_rows={(row['address'],row['bytes'].lower()) for row in bindings.rows(native,image,at)}
            if expected_rows<=actual:available.add(at)
    if available!=required:raise ValueError('Version exports do not cover fifteen complete roots')


def report_valid(report,context,context_sha):
    if (report.get('source_sha256')!=context['source_sha256'] or report.get('scope')!=SCOPE or report.get('method')!='bounded_native'
            or report.get('network_used') is not False or report.get('profile_activated') is not False or report.get('runtime_activated') is not False
            or report.get('context_sha256')!=context_sha or report.get('proof')!=context.get('transfer_proof')
            or len(report.get('cases',[]))!=32 or len(report.get('truncated',[]))!=17 or len(report.get('failures',[]))!=5
            or len(report.get('construction_cases',[]))!=72 or report.get('extra',{}).get('returned')!=1
            or report.get('extra',{}).get('consumed')!=17
            or not all(row.get('guards') is True for row in report['construction_cases'])
            or not all(row.get('returned')==1 and row.get('consumed')==17 for row in report['cases'])
            or not all(row.get('returned')==0 for row in report['truncated']+report['failures'])):
        raise ValueError('Version context lacks its reviewed semantic proof')


def published_contexts(root,registry,*,value=None):
    root=Path(root);path=root/'knowledge'/INDEX/'index.json'
    if value is None:
        if not path.is_file():return []
        value=json.loads(path.read_text('utf-8'))
    if value.get('schema')!=1 or not isinstance(value.get('contexts'),list) or len(value['contexts'])>4096:
        raise ValueError('Invalid generated Version index')
    ranks={row['source_sha256']:row['order'] for row in registry['releases']};seen=set();result=[]
    for item in value['contexts']:
        if set(item)!={'context','check','order'} or type(item['order']) is not int or item['order']<0:raise ValueError('Invalid generated Version declaration')
        context=checked(root,item['context'],'generated-native-contexts');sha=context.get('source_sha256')
        if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha) or sha in seen or context.get('family')!=FAMILY:
            raise ValueError('Invalid generated Version source/family')
        report_valid(checked(root,item['check'],'native-adapter-checks'),context,item['context']['sha256'])
        seen.add(sha);result.append((Path(item['context']['path']),context,ranks.get(sha,item['order'])))
    return result


def baseline_context(root,knowledge):
    api=load('native-release-registry');registry=api.read(knowledge);found=[]
    for path in (Path(knowledge)/'native-contexts').glob('version-result-*.json'):
        context=json.loads(path.read_text('utf-8'));identity=api.context_identity(path,context,registry)
        if identity is None:continue
        version,family=identity
        if family==FAMILY:found.append((path,context,next(row['order'] for row in registry['releases'] if row['id']==version)))
    found.extend(published_contexts(root,registry))
    if not found:raise ValueError('No reviewed VersionResult baseline')
    return max(found,key=lambda row:(row[2],str(row[0])))[:2]


def plan_inputs(index,args,sha):
    path,baseline=baseline_context(args.root,args.knowledge)
    contexts={str(p):index.digest(p) for p in (Path(args.knowledge)/'native-contexts').glob('version-result-*.json')};contexts[str(path)]=index.digest(path)
    declared=dict(baseline.get('exports',{}),**baseline['native_input'].get('exports',{}))
    exports={str(Path(args.root)/'ghidra/request-exports'/baseline['source_sha256']/run/'details.json'):index.digest(
        Path(args.root)/'ghidra/request-exports'/baseline['source_sha256']/run/'details.json') for run in declared}
    return dict(source=sha,tools=tools(),registry=index.digest(Path(args.knowledge)/'native-release-registry.json'),baselines=contexts,baseline_exports=exports)


def planned(context,proof):
    return dict(state='planned',source_sha256=context['source_sha256'],context={k:v for k,v in context.items() if k!='exports'},
        exports=sorted((hex(at) for at in roots(context)),key=lambda at:int(at,16)),dependencies=tools(),
        artifacts={proof['baseline']['path']:proof['baseline']['sha256'],context['transfer_proof']['path']:context['transfer_proof']['sha256']})


def attach_proof(context,proof):
    context=copy.deepcopy(context);context['transfer_proof']=copy.deepcopy(proof)
    context['native_input']['portable_buffer_proof']=copy.deepcopy(proof)
    return context


def discover(index,args,sha):
    registry=load('native-release-registry').read(args.knowledge)
    existing=[context for _,context,_ in published_contexts(args.root,registry) if context['source_sha256']==sha]
    if existing:
        context=existing[0];validate(index,args,context)
        return planned(context,checked(args.root,context['transfer_proof'],PROOFS))
    path,baseline=baseline_context(args.root,args.knowledge)
    if baseline.get('transfer_proof'):validate(index,args,baseline)
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    before=args.source_store.image(native,baseline['source_sha256']);after=args.source_store.image(native,sha)
    export_coverage(args.root,baseline,native,bindings,before)
    context,relocation=transfer(native,bindings,before,after,baseline,sha,Path(args.root)/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe')
    proof=load('update-native-contexts').receipt(args.root,PROOFS,dict(schema=1,adapter=ADAPTER,scope=SCOPE,
        baseline=dict(path=str(path),sha256=digest(path)),target=context,relocation=relocation,tools=tools(),runtime_activated=False))
    return planned(attach_proof(context,proof),checked(args.root,proof,PROOFS))


def validate(index,args,context,seen=None):
    pointer=context['transfer_proof'];proof=checked(args.root,pointer,PROOFS);seen=set(seen or ())
    if pointer['sha256'] in seen or len(seen)>=32:raise ValueError('Version proof cycle/depth budget exceeded')
    seen.add(pointer['sha256'])
    if (proof.get('schema')!=1 or proof.get('adapter')!=ADAPTER or proof.get('scope')!=SCOPE or proof.get('tools')!=tools()
            or proof.get('runtime_activated') is not False or context.get('layout')!=LAYOUT or proof.get('target')!=plain(context)
            or context['native_input'].get('portable_buffer_proof')!=pointer):
        raise ValueError('Version proof fields, tools, layout or portable pointer differ')
    path=Path(proof['baseline']['path']).resolve()
    if not (path.is_relative_to((HERE/'knowledge/native-contexts').resolve()) or path.is_relative_to((Path(args.root)/'knowledge/generated-native-contexts').resolve())):
        raise ValueError('Version baseline outside reviewed contexts')
    if digest(path)!=proof['baseline']['sha256']:raise ValueError('Version baseline changed')
    baseline=json.loads(path.read_text('utf-8'))
    if baseline.get('transfer_proof'):validate(index,args,baseline,seen)
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    before=args.source_store.image(native,baseline['source_sha256']);after=args.source_store.image(native,context['source_sha256'])
    export_coverage(args.root,baseline,native,bindings,before)
    expected,relocation=transfer(native,bindings,before,after,baseline,context['source_sha256'],Path(args.root)/'client-code-snapshots'/context['source_sha256']/'ProjectRED-Win64-Shipping.exe')
    if expected!=proof['target'] or relocation!=proof['relocation']:raise ValueError('Version relocated closure/data/layout differs')
    if context.get('exports'):export_coverage(args.root,context,native,bindings,after)
    return context


def admit_input_buffer(h,context):
    """Guard the sole portable helper hook without replay, login or broad SHA lists."""
    pointer=context.get('portable_buffer_proof')
    if not isinstance(pointer,dict):raise ValueError('Version portable buffer proof is missing')
    proof=checked(h.root,pointer,PROOFS);outer=attach_proof(proof['target'],pointer)
    if (h.sha!=outer['source_sha256'] or context.get('source_sha256')!=h.sha or hashlib.sha256(h.raw).hexdigest()!=h.sha
            or {k:v for k,v in context.items() if k not in ('exports','portable_buffer_proof')}!=plain(outer)['native_input']):
        raise ValueError('Version portable buffer context/source differs')
    spec=context.get('buffer_construction',{})
    if spec.get('reading_mode')!=1 or spec.get('reading_endian')!=0:raise ValueError('Version portable buffer mode/endian differs')
    index=load('knowledge-index').api();store=load('update-bindings').SourceStore(index,h.root)
    store._sources[h.sha]=h.raw;store._images[h.sha]=h.image
    args=SimpleNamespace(root=Path(h.root),source_store=store)
    validate(index,args,outer);store.validate()
    return True


def materialize(index,args,sha,plan,database):
    context=copy.deepcopy(plan['context']);db=index.open_index(database);exports={};workflow=load('research-workflow')
    try:
        for at in plan['exports']:
            state=workflow.function_state(index,db,sha,at)
            if state['state']!='ready':raise ValueError('Version target export is not ready: '+at)
            for row in state['variants']:
                if not row['completed']:continue
                path=Path(row['artifact']).resolve();parent=(Path(args.root)/'ghidra/request-exports'/sha).resolve()
                if path.is_relative_to(parent) and path.name=='details.json':exports[path.parent.name]=index.digest(path)
    finally:db.close()
    context['exports']=exports;context['native_input']['exports']=exports.copy();validate(index,args,context)
    target=load('update-native-contexts').receipt(args.root,'generated-native-contexts',context)
    artifacts={**plan['artifacts'],target['path']:target['sha256']}
    artifacts.update({str(Path(args.root)/'ghidra/request-exports'/sha/run/'details.json'):expected for run,expected in exports.items()})
    declaration=dict(id='native-auto-version-result',adapter=ADAPTER,scope=SCOPE,contracts=[],context=target,
        proof=context['transfer_proof'],dependencies=tools(),artifacts=artifacts)
    return dict(checks=[declaration],queue=[])


def execute(index,args,sha,declaration):
    context=checked(args.root,declaration['context'],'generated-native-contexts')
    if (declaration.get('adapter')!=ADAPTER or declaration.get('scope')!=SCOPE or context['source_sha256']!=sha
            or declaration['dependencies']!=tools()):raise ValueError('Version check declaration differs')
    for filename,expected in declaration['artifacts'].items():
        if index.digest(filename)!=expected:raise ValueError('Version check artifact changed')
    validate(index,args,context)
    report=load('verify-version-result-context').verify(context,args.root)
    report.update(scope=SCOPE,proof=context['transfer_proof'],context_sha256=declaration['context']['sha256'],runtime_activated=False,
        runtime=load('update-native-harness').runtime_inputs())
    report_valid(report,context,declaration['context']['sha256'])
    target=load('update-native-contexts').receipt(args.root,'native-adapter-checks',report)
    return dict(id=declaration['id'],state='passed',report=target['path'],sha256=target['sha256'],scope=SCOPE,runtime_activated=False,profile_activated=False)


def publish(index,args,sha,declaration,outcome):
    if outcome.get('state')!='passed':raise ValueError('Only a passed Version context can be published')
    context=checked(args.root,declaration['context'],'generated-native-contexts');validate(index,args,context)
    if context['source_sha256']!=sha:raise ValueError('Version publication source differs')
    check=dict(path=outcome['report'],sha256=outcome['sha256']);report_valid(checked(args.root,check,'native-adapter-checks'),context,declaration['context']['sha256'])
    registry=load('native-release-registry').read(args.knowledge);published_contexts(args.root,registry)
    path=Path(args.root)/'knowledge'/INDEX/'index.json';old=json.loads(path.read_text('utf-8')) if path.is_file() else dict(schema=1,contexts=[])
    entries=[row for row in old['contexts'] if checked(args.root,row['context'],'generated-native-contexts')['source_sha256']!=sha]
    ranks={row['source_sha256']:row['order'] for row in registry['releases']}
    rank=ranks.get(sha,max([row['order'] for row in registry['releases']]+[row['order'] for row in entries])+1)
    entries.append(dict(context=declaration['context'],check=check,order=rank));value=dict(schema=1,contexts=sorted(entries,key=lambda row:(row['order'],row['context']['path'])))
    published_contexts(args.root,registry,value=value)
    workflow=load('research-workflow');workflow.atomic(path,workflow.canonical(value))
    return dict(path=str(path),sha256=index.digest(path))
