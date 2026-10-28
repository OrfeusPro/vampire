"""Portable two-root Login preparation with explicit synthetic input boundaries."""
import copy
import hashlib
import itertools
import json
from pathlib import Path
import re
import struct
from importlib.util import spec_from_file_location,module_from_spec

HERE=Path(__file__).resolve().parent
ADAPTER='login-prepare-v1'
FAMILY='login-prepare'
SCOPE='bounded_native_login_prepare'
INDEX='generated-login-prepare'
PROOFS='native-login-prepare-proofs'
LAYOUT=dict(abi='win64',packet_bytes=320,max_allocation=2048,executed_roots=2,optional_native_helpers=False)
OWN_TOOLS=('update-native-login-prepare.py','verify-login-prepare-context.py')
# Offsets are part of the reviewed shape/layout rule, not release addresses.
DATA_ROLES={49:('android',16),153:('ios',8),252:('windows',16),344:('enabled',1),
    573:('compiled_tag_pointer',8),691:('text_count',4),698:('number',4),704:('text_pointer',8),
    781:('enabled',1),1159:('send_argument',8),1194:('log_descriptor',16),1211:('log_integer',4),
    1218:('log_address_argument',8),1225:('log_float',4),1238:('log_bss',8),1304:('format_literal',66),
    1349:('enabled',1),1495:('event_literal',8)}
LEAF_SIZES={'wide_compare':71,'sdk_manager':8,'owner_number':11,'language':8,'flags_manager':8,
    'sdk_flag':8,'sdk_extra_flag':5,'session':8,'log':3,'post_receiver':8,'variant_number':25}
PLATFORMS={'android':'Android','ios':'IOS','windows':'Windows'}


def load(name):
    spec=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):return load('update-native-contexts').digest(path)
def tools():return {**load('update-native-archive-wire').tools(),**{str(HERE/n):digest(HERE/n) for n in OWN_TOOLS}}
def checked(root,item,category):return load('update-native-contexts').checked(root,item,category)
def image_bytes(image,address,size):return load('update-native-contexts').image_bytes(image,address,size)


def plain(context):return {k:copy.deepcopy(v) for k,v in context.items() if k not in ('exports','transfer_proof','release_id')}


def roots(context):
    if any(k in context for k in ('native_sdk','native_metadata','function_budget')):
        raise ValueError('Base Login prepare cannot admit optional native SDK/metadata helpers')
    values={int(context[k],16) for k in ('prepare','constructor')}
    if len(values)!=2:raise ValueError('Login prepare root aliases constructor')
    return values


def data_input(image,address,size):
    """Only file-backed data or a completely proven PE zero-fill interval."""
    try:return dict(storage='file',bytes=image_bytes(image,address,size).hex())
    except ValueError:
        rva=address-image.pe.base
        sections=[s for s in image.pe.sections if s['rva']+s['raw_size']<=rva and rva+size<=s['rva']+s['size']]
        if len(sections)!=1:raise ValueError('Login data is outside file and PE zero-fill')
        s=sections[0]
        return dict(storage='pe-zero-fill',size=size,section=s['name'],virtual_size=s['size'],raw_size=s['raw_size'])


def typed_data(before,after,baseline,mapping):
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    rows=bindings.rows(native,before,int(baseline['prepare'],16));refs={r['address']-int(baseline['prepare'],16):r['rip_references'] for r in rows if r['rip_references']}
    if set(refs)!=set(DATA_ROLES) or any(len(v)!=1 for v in refs.values()):raise ValueError('Login prepare static data roles changed')
    result=[]
    for offset,(role,size) in DATA_ROLES.items():
        old=refs[offset][0];new=mapping[old]
        old_data,new_data=data_input(before,old,size),data_input(after,new,size)
        if role=='compiled_tag_pointer':
            if old!=int(baseline['globals']['tag_pointer'],16):raise ValueError('Login tag pointer role changed')
            old_literal=struct.unpack('<Q',bytes.fromhex(old_data['bytes']))[0]
            if old_literal!=int(baseline['compiled_tag_source']['literal'],16):raise ValueError('Login baseline tag pointer changed')
            old_raw=image_bytes(before,old_literal,33)
            if old_raw!=baseline['compiled_tag_source']['value'].encode('ascii')+b'\0':raise ValueError('Login baseline tag literal changed')
            literal=struct.unpack('<Q',bytes.fromhex(new_data['bytes']))[0];raw=image_bytes(after,literal,33)
            if not re.fullmatch(b'[0-9A-F]{32}\0',raw):raise ValueError('Login compiled tag is not an exact bounded hex literal')
            new_data.update(literal=hex(literal),value=raw[:-1].decode('ascii'))
        elif old_data!=new_data:
            raise ValueError('Login typed input changed: '+role)
        if role in PLATFORMS and new_data!=dict(storage='file',bytes=(PLATFORMS[role]+'\0').encode('utf-16le').hex()):
            raise ValueError('Login platform literal changed')
        if role=='text_count' and old!=int(baseline['globals']['text'],16)+8:raise ValueError('Login text count linkage changed')
        if role=='text_pointer' and old!=int(baseline['globals']['text'],16):raise ValueError('Login text descriptor linkage changed')
        if role in ('enabled','number') and old!=int(baseline['globals'][role],16):raise ValueError('Login global input linkage changed')
        if role=='send_argument' and (old!=int(baseline['send_argument_global'],16) or new_data!=dict(storage='file',bytes='00'*8)):
            raise ValueError('Login send argument differs')
        if role in ('format_literal','event_literal'):
            expected='RdPeer::Login() - ServerId( %d )' if role=='format_literal' else '{0}'
            if old!=int(baseline[role],16) or new_data!=dict(storage='file',bytes=(expected+'\0').encode('utf-16le').hex()):
                raise ValueError('Login event/format literal changed')
        result.append(dict(offset=offset,role=role,address=hex(new),input=new_data,
            scope='Synthetic emulator input' if role in ('text_count','text_pointer','enabled','number') else 'Static literal or non-executed logging boundary'))
    enum=int(baseline['globals']['enum'],16)
    a,b=data_input(before,enum,4),data_input(after,mapping[enum],4)
    if a!=b or b!=dict(storage='file',bytes='01000000'):raise ValueError('Login constructor enum default changed')
    result.append(dict(role='constructor_enum',address=hex(mapping[enum]),input=b,scope='Synthetic enum overwritten by fixture'))
    return result


def fixture_leaf(native,image,address,size):
    raw=image_bytes(image,address,size);decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    instructions=list(decoder.disasm(raw,address))
    if sum(i.size for i in instructions)!=size or not instructions or instructions[-1].mnemonic!='ret':
        raise ValueError('Login fixture leaf boundary differs')
    locations={i.address for i in instructions};result=[]
    for i in instructions:
        call=i.group(native.capstone.CS_GRP_CALL);branch=i.group(native.capstone.CS_GRP_JUMP)
        target=i.operands[0].imm if (call or branch) and i.operands and i.operands[0].type==native.X86_OP_IMM else None
        if call or branch and target not in locations:raise ValueError('Login fixture leaf has external control edge')
        result.append(dict(address=i.address,bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str,call=call,branch=branch,
            direct_target=target,rip_references=[i.address+i.size+o.mem.disp for o in i.operands if o.type==native.X86_OP_MEM and o.mem.base==native.X86_REG_RIP]))
    return result


def fixture_boundaries(native,before,after,baseline,context,mapping):
    values={name:int(value,16) for name,value in context['fixtures'].items()}
    if len(values)!=len(set(values.values())) or set(values.values())&roots(context):raise ValueError('Login fixture aliases executable code or another role')
    if len(values)!=32 or set(values)!=set(baseline['fixtures']):raise ValueError('Login fixture role set differs')
    common=load('update-native-archive-wire');result={}
    for role,at in values.items():
        old=int(baseline['fixtures'][role],16)
        if role in LEAF_SIZES:
            size=LEAF_SIZES[role];a=fixture_leaf(native,before,old,size);b=fixture_leaf(native,after,at,size)
            common.pair_rows(native,a,b,mapping);inputs=[]
            for row in a:
                for ref in row['rip_references']:
                    count=128 if role=='wide_compare' else 8
                    old_data,new_data=data_input(before,ref,count),data_input(after,mapping[ref],count)
                    if old_data!=new_data:raise ValueError('Login fixture leaf static input changed: '+role)
                    inputs.append(dict(address=hex(mapping[ref]),input=new_data))
            if role=='log' and image_bytes(after,at,size)!=b'\xc2\0\0':raise ValueError('Login logger leaf changed')
            result[role]=dict(address=hex(at),kind='bounded-fixture-leaf',size=size,inputs=inputs,
                bytes_sha256=hashlib.sha256(image_bytes(after,at,size)).hexdigest(),scope='Static leaf linkage only; replaced, not executed')
        else:
            for image,address in ((before,old),(after,at)):
                part=image.containing(address)
                if part is None or image.roots[part][0]+image.pe.base!=address:raise ValueError('Login fixture is not a concrete unwind entry: '+role)
            result[role]=dict(address=hex(at),kind='unwind-fixture',scope='Captured/replaced fixture; body not executed')
    return result


def transfer(native,bindings,before,after,baseline,archive):
    common=load('update-native-archive-wire');mapping={};roots(baseline)
    old_prepare,old_ctor=[int(baseline[k],16) for k in ('prepare','constructor')]
    # The large unique caller resolves its constructor by an exact call edge.
    new_prepare=common.unique_root(native,bindings,before,after,old_prepare)
    common.add_link(mapping,old_prepare,new_prepare)
    common.pair_rows(native,bindings.rows(native,before,old_prepare),bindings.rows(native,after,new_prepare),mapping)
    if old_ctor not in mapping:raise ValueError('Login constructor has no prepare call edge')
    new_ctor=mapping[old_ctor]
    common.pair_rows(native,bindings.rows(native,before,old_ctor),bindings.rows(native,after,new_ctor),mapping)
    declared={hex(r['address']):dict(target=hex(r['direct_target']) if r['direct_target'] is not None else r['operands'])
        for at in (old_prepare,old_ctor) for r in bindings.rows(native,before,at) if r['call']}
    if declared!=baseline['call_sites']:raise ValueError('Login baseline call roles changed')
    def mapped(text):
        at=int(text,16)
        if at not in mapping:raise ValueError('Login preparation undeclared address: '+text)
        return hex(mapping[at])
    ctor_refs=[r for r in bindings.rows(native,before,old_ctor) if r['rip_references']]
    if [r['address']-old_ctor for r in ctor_refs]!=[12,211,223]:raise ValueError('Login constructor data offsets changed')
    for row,expected in zip(ctor_refs,(baseline['packet_table'],baseline['globals']['tag_pointer'],baseline['globals']['enum'])):
        if row['rip_references']!=[int(expected,16)]:raise ValueError('Login constructor data role changed')
    packet=archive['packets']['game-login'];packet_table=mapped(baseline['packet_table'])
    if packet.get('object_size')!=LAYOUT['packet_bytes'] or packet_table!=packet['table'] or struct.unpack('<Q',image_bytes(after,int(packet_table,16)+16,8))[0]!=int(packet['writer'],16):
        raise ValueError('Login constructor packet table does not match proved wire writer')
    current=copy.deepcopy(baseline)
    for key in ('exports','release_id','transfer_proof'):current.pop(key,None)
    current.update(schema=1,family=FAMILY,source_sha256=archive['source_sha256'],source=archive['source'],layout=LAYOUT,
        prepare=hex(new_prepare),constructor=hex(new_ctor),packet_table=packet_table,globals={key:mapped(at) for key,at in baseline['globals'].items()},
        fixtures={key:mapped(at) for key,at in baseline['fixtures'].items()},helpers={'memcpy':archive['helpers']['memcpy']},verify_whole_exports=True)
    if mapped(baseline['helpers']['memcpy'])!=archive['helpers']['memcpy']:raise ValueError('Login prepare memcpy dependency changed')
    data=typed_data(before,after,baseline,mapping);tag=next(row['input'] for row in data if row['role']=='compiled_tag_pointer')
    common.add_link(mapping,int(baseline['tag_literal'],16),int(tag['literal'],16))
    current.update(tag_literal=tag['literal'],send_argument_global=mapped(baseline['send_argument_global']),
        format_literal=mapped(baseline['format_literal']),event_literal=mapped(baseline['event_literal']))
    current['compiled_tag_source']=dict(literal=tag['literal'],value=tag['value'])
    current['call_sites']={hex(r['address']):dict(target=hex(r['direct_target']) if r['direct_target'] is not None else r['operands'])
        for at in (new_prepare,new_ctor) for r in bindings.rows(native,after,at) if r['call']}
    boundaries=fixture_boundaries(native,before,after,baseline,current,mapping)
    return current,dict(mapping={hex(a):hex(b) for a,b in sorted(mapping.items())},typed_inputs=data,fixtures=boundaries,
        packet_wire_dependency=dict(table=packet_table,writer=packet['writer']))


def export_coverage(root,context,native,bindings,image):
    needed=roots(context);available=set()
    for run,expected in context.get('exports',{}).items():
        if Path(run).name!=run or not run.startswith('run-'):raise ValueError('Invalid Login prepare export')
        p=Path(root)/'ghidra/request-exports'/context['source_sha256']/run/'details.json'
        if digest(p)!=expected:raise ValueError('Login prepare export changed')
        report=json.loads(p.read_text('utf-8'))
        if report.get('new_source_sha256',report.get('source_sha256'))!=context['source_sha256']:raise ValueError('Login prepare export source differs')
        for fn in report['functions']:
            at=int(fn['address'],16)
            if at not in needed or fn.get('decompilation_completed') is not True:continue
            wanted={(r['address'],r['bytes']) for r in bindings.rows(native,image,at)}
            actual={(int(r['address'],16),r['bytes'].lower()) for r in fn['instructions']}
            if wanted<=actual:available.add(at)
    if available!=needed:raise ValueError('Login prepare exports lack complete two-root coverage')


def report_valid(report,context,sha):
    if (report.get('source_sha256')!=context['source_sha256'] or report.get('scope')!=SCOPE or report.get('method')!='bounded_native'
            or report.get('network_used') is not False or report.get('profile_activated') is not False or report.get('runtime_activated') is not False
            or report.get('proof')!=context.get('transfer_proof') or report.get('context_sha256')!=sha
            or len(report.get('cases',[]))!=672 or not all(r.get('guards') is True for r in report['cases'])
            or any(report.get(name) is not False for name in ('native_sdk_used','native_metadata_used'))):
        raise ValueError('Login prepare lacks its bounded semantic proof')
    fields=('scenario','selector','empty','send_return','poison')
    expected=set(itertools.product([row[0] for row in load('verify-login-prepare-context').SCENARIOS],
        (0,1,2,3,4,255),(False,True),(0,1),(0x55,0xaa)))
    actual={tuple(row.get(key) for key in fields) for row in report['cases']}
    if len(expected)!=672 or actual!=expected:
        raise ValueError('Login prepare scenario/selector/empty/send/poison matrix is incomplete or duplicated')


def published_contexts(root,registry,*,value=None):
    p=Path(root)/'knowledge'/INDEX/'index.json'
    if value is None:
        if not p.is_file():return []
        value=json.loads(p.read_text('utf-8'))
    if value.get('schema')!=1 or not isinstance(value.get('contexts'),list) or len(value['contexts'])>4096:raise ValueError('Invalid generated preparation index')
    known={r['source_sha256']:r['order'] for r in registry['releases']};seen=set();result=[]
    for row in value['contexts']:
        if set(row)!={'context','check','order'} or type(row['order']) is not int or row['order']<0:raise ValueError('Invalid generated preparation declaration')
        context=checked(root,row['context'],'generated-native-contexts');sha=context.get('source_sha256')
        if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha) or sha in seen or context.get('family')!=FAMILY:raise ValueError('Invalid generated preparation source')
        report_valid(checked(root,row['check'],'native-adapter-checks'),context,row['context']['sha256']);seen.add(sha)
        result.append((Path(row['context']['path']),context,known.get(sha,row['order'])))
    return result


def baseline_context(root,knowledge):
    api=load('native-release-registry');registry=api.read(knowledge);found=[]
    for p in (Path(knowledge)/'native-contexts').glob('login-prepare-*.json'):
        c=json.loads(p.read_text('utf-8'));identity=api.context_identity(p,c,registry)
        if identity and identity[1]==FAMILY:found.append((p,c,next(r['order'] for r in registry['releases'] if r['id']==identity[0])))
    found.extend(published_contexts(root,registry))
    if not found:raise ValueError('No reviewed Login prepare baseline')
    return max(found,key=lambda r:(r[2],str(r[0])))[:2]


def target_archive(root,knowledge,sha):
    registry=load('native-release-registry').read(knowledge)
    found=[(p,c) for p,c,_ in load('update-native-archive-wire').published_contexts(root,registry) if c['source_sha256']==sha]
    if len(found)!=1:raise ValueError('A reviewed target archive-wire context is required')
    return found[0]


def plan_inputs(index,args,sha):
    p,base=baseline_context(args.root,args.knowledge);archive_path,_=target_archive(args.root,args.knowledge,sha)
    contexts={str(f):index.digest(f) for f in (Path(args.knowledge)/'native-contexts').glob('login-prepare-*.json')};contexts[str(p)]=index.digest(p)
    return dict(source=sha,tools=tools(),registry=index.digest(Path(args.knowledge)/'native-release-registry.json'),baselines=contexts,
        baseline_exports={str(Path(args.root)/'ghidra/request-exports'/base['source_sha256']/run/'details.json'):index.digest(
            Path(args.root)/'ghidra/request-exports'/base['source_sha256']/run/'details.json') for run in base['exports']},
        archive=dict(path=str(archive_path),sha256=index.digest(archive_path)))


def planned(context,proof):
    return dict(state='planned',source_sha256=context['source_sha256'],context={k:v for k,v in context.items() if k!='exports'},
        exports=sorted(hex(a) for a in roots(context)),dependencies=tools(),artifacts={proof['baseline']['path']:proof['baseline']['sha256'],
            proof['archive']['path']:proof['archive']['sha256'],context['transfer_proof']['path']:context['transfer_proof']['sha256']})


def discover(index,args,sha):
    registry=load('native-release-registry').read(args.knowledge)
    existing=[c for _,c,_ in published_contexts(args.root,registry) if c['source_sha256']==sha]
    if existing:
        c=existing[0];validate(index,args,c);return planned(c,checked(args.root,c['transfer_proof'],PROOFS))
    archive_path,archive=target_archive(args.root,args.knowledge,sha);load('update-native-archive-wire').validate(index,args,archive)
    p,base=baseline_context(args.root,args.knowledge)
    if base.get('transfer_proof'):validate(index,args,base)
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    before=args.source_store.image(native,base['source_sha256']);after=args.source_store.image(native,sha)
    export_coverage(args.root,base,native,bindings,before);context,relocation=transfer(native,bindings,before,after,base,archive)
    proof=load('update-native-contexts').receipt(args.root,PROOFS,dict(schema=1,adapter=ADAPTER,scope=SCOPE,baseline=dict(path=str(p),sha256=digest(p)),
        archive=dict(path=str(archive_path),sha256=digest(archive_path)),target=context,relocation=relocation,tools=tools(),runtime_activated=False))
    context=dict(context,transfer_proof=proof);return planned(context,checked(args.root,proof,PROOFS))


def validate(index,args,context,seen=None):
    pointer=context['transfer_proof'];proof=checked(args.root,pointer,PROOFS);seen=set(seen or ())
    if pointer['sha256'] in seen or len(seen)>=32:raise ValueError('Login prepare proof cycle/depth exceeded')
    seen.add(pointer['sha256'])
    if (proof.get('schema')!=1 or proof.get('adapter')!=ADAPTER or proof.get('scope')!=SCOPE or proof.get('tools')!=tools()
            or proof.get('runtime_activated') is not False or context.get('layout')!=LAYOUT or proof.get('target')!=plain(context)):
        raise ValueError('Login prepare proof fields, tools or layout differ')
    p=Path(proof['baseline']['path']).resolve()
    if not (p.is_relative_to((HERE/'knowledge/native-contexts').resolve()) or p.is_relative_to((Path(args.root)/'knowledge/generated-native-contexts').resolve())):
        raise ValueError('Login prepare baseline outside reviewed contexts')
    if digest(p)!=proof['baseline']['sha256']:raise ValueError('Login prepare baseline changed')
    baseline=json.loads(p.read_text('utf-8'))
    if baseline.get('transfer_proof'):validate(index,args,baseline,seen)
    archive=checked(args.root,proof['archive'],'generated-native-contexts');load('update-native-archive-wire').validate(index,args,archive)
    if archive['source_sha256']!=context['source_sha256']:raise ValueError('Login prepare archive source differs')
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    before=args.source_store.image(native,baseline['source_sha256']);after=args.source_store.image(native,context['source_sha256'])
    export_coverage(args.root,baseline,native,bindings,before)
    target,relocation=transfer(native,bindings,before,after,baseline,archive)
    if target!=proof['target'] or relocation!=proof['relocation']:raise ValueError('Login prepare relocated data/calls differ')
    if context.get('exports'):export_coverage(args.root,context,native,bindings,after)
    return context


def materialize(index,args,sha,plan,database):
    c=copy.deepcopy(plan['context']);workflow=load('research-workflow');db=index.open_index(database);exports={}
    try:
        for at in plan['exports']:
            state=workflow.function_state(index,db,sha,at)
            if state['state']!='ready':raise ValueError('Login prepare target export missing: '+at)
            for r in state['variants']:
                p=Path(r['artifact']).resolve()
                if r['completed'] and p.is_relative_to((Path(args.root)/'ghidra/request-exports'/sha).resolve()) and p.name=='details.json':exports[p.parent.name]=index.digest(p)
    finally:db.close()
    c['exports']=exports;validate(index,args,c);target=load('update-native-contexts').receipt(args.root,'generated-native-contexts',c)
    artifacts={**plan['artifacts'],target['path']:target['sha256']}
    artifacts.update({str(Path(args.root)/'ghidra/request-exports'/sha/run/'details.json'):expected for run,expected in exports.items()})
    return dict(checks=[dict(id='native-auto-login-prepare',adapter=ADAPTER,scope=SCOPE,contracts=[],context=target,
        proof=c['transfer_proof'],dependencies=tools(),artifacts=artifacts)],queue=[])


def execute(index,args,sha,declaration):
    c=checked(args.root,declaration['context'],'generated-native-contexts')
    if declaration.get('adapter')!=ADAPTER or declaration.get('scope')!=SCOPE or c['source_sha256']!=sha or declaration['dependencies']!=tools():
        raise ValueError('Login prepare check declaration differs')
    for p,expected in declaration['artifacts'].items():
        if index.digest(p)!=expected:raise ValueError('Login prepare artifact changed')
    validate(index,args,c);r=load('verify-login-prepare-context').verify(c,args.root)
    r.update(scope=SCOPE,proof=c['transfer_proof'],context_sha256=declaration['context']['sha256'],runtime_activated=False)
    report_valid(r,c,declaration['context']['sha256']);p=load('update-native-contexts').receipt(args.root,'native-adapter-checks',r)
    return dict(id=declaration['id'],state='passed',report=p['path'],sha256=p['sha256'],scope=SCOPE,runtime_activated=False,profile_activated=False)


def publish(index,args,sha,declaration,outcome):
    if outcome.get('state')!='passed':raise ValueError('Only a passed Login prepare context can be published')
    c=checked(args.root,declaration['context'],'generated-native-contexts');validate(index,args,c)
    if c['source_sha256']!=sha:raise ValueError('Login prepare publication source differs')
    check=dict(path=outcome['report'],sha256=outcome['sha256']);report_valid(checked(args.root,check,'native-adapter-checks'),c,declaration['context']['sha256'])
    registry=load('native-release-registry').read(args.knowledge);published_contexts(args.root,registry)
    p=Path(args.root)/'knowledge'/INDEX/'index.json';old=json.loads(p.read_text('utf-8')) if p.is_file() else dict(schema=1,contexts=[])
    entries=[r for r in old['contexts'] if checked(args.root,r['context'],'generated-native-contexts')['source_sha256']!=sha]
    ranks={r['source_sha256']:r['order'] for r in registry['releases']};rank=ranks.get(sha,max([r['order'] for r in registry['releases']]+[r['order'] for r in entries])+1)
    entries.append(dict(context=declaration['context'],check=check,order=rank));value=dict(schema=1,contexts=sorted(entries,key=lambda r:(r['order'],r['context']['path'])))
    published_contexts(args.root,registry,value=value);w=load('research-workflow');w.atomic(p,w.canonical(value))
    return dict(path=str(p),sha256=index.digest(p))
