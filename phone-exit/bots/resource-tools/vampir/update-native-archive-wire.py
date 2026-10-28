"""Portable bounded archive IO and Version/Login wire writers; no runtime admission.

Selected archive slots execute. Other table slots are pinned as target data but
their pointed-to code is outside the checked behavior and cannot run in harness.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
from importlib.util import spec_from_file_location, module_from_spec

HERE=Path(__file__).resolve().parent
ADAPTER='archive-wire-v1'
SCOPE='bounded_native_archive_wire'
FAMILY='archive-wire'
INDEX='generated-archive-wire'
PROOFS='native-archive-wire-proofs'
WINDOW=65536
SLOTS={'string':0x28,'u16':0x60,'raw':0x88,'u64':0xb8,'u32':0xc8,'u8':0xe0,'bool':0xf0}
LAYOUT=dict(abi='win64',archive_bytes=64,table_bytes=248,preallocated_capacity=16384,
            max_leaf_bytes=512,archive_slots=SLOTS,packet_writer_slot=16)
TOOLS=('update-native-archive-wire.py','update-native-string-writer.py','verify-archive-wire-context.py',
       'verify-string-writer-context.py','verify-utf8-context.py','update-native-contexts.py',
       'update-native-harness.py','update-bindings.py','build-native-entry-code.py',
       'build-object-zero-init-code.py','extract-native-enums.py','audit-launcher-shape-11318.py',
       'align-wire-contexts-11320.py','function-reuse-plan.py','native-release-registry.py',
       'research-workflow.py')


def load(name):
    spec=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):return load('update-native-contexts').digest(path)
def tools():return {str(HERE/name):digest(HERE/name) for name in TOOLS}
def checked(root,item,category):return load('update-native-contexts').checked(root,item,category)


def roots(context):
    values={int(context['bindings'][key],16) for key in ('length','convert','string-writer')}
    values.update(int(at,16) for key,at in context['archive'].items() if key not in ('table','growth'))
    values.update(int(packet['writer'],16) for packet in context['packets'].values())
    if len(values)!=14:raise ValueError('Archive wire root scope differs')
    return values


def export_coverage(root,context,native,bindings,image):
    available={};expected=roots(context)
    for run,sha in context.get('exports',{}).items():
        if not isinstance(run,str) or Path(run).name!=run or not run.startswith('run-'):
            raise ValueError('Invalid archive wire export name')
        path=Path(root)/'ghidra/request-exports'/context['source_sha256']/run/'details.json'
        if digest(path)!=sha:raise ValueError('Archive wire export changed')
        value=json.loads(path.read_text('utf-8'))
        if value.get('new_source_sha256',value.get('source_sha256'))!=context['source_sha256']:
            raise ValueError('Archive wire export source differs')
        for function in value.get('functions',[]):
            at=int(function['address'],16)
            if at not in expected or function.get('decompilation_completed') is not True:continue
            actual={(int(row['address'],16),row['bytes'].lower()) for row in function.get('instructions',[])}
            wanted={(row['address'],row['bytes'].lower()) for row in bindings.rows(native,image,at)}
            if wanted<=actual:available[at]=True
    if set(available)!=expected:raise ValueError('Archive wire exports do not cover fourteen complete roots')


def add_link(mapping,before,after):
    if type(before) is not int or type(after) is not int:raise ValueError('Invalid archive edge target')
    if before in mapping and mapping[before]!=after:raise ValueError('Archive relocated edge is inconsistent')
    mapping[before]=after


def pair_rows(native,before,after,mapping):
    """Whole instruction equality plus consistent relocation of every external edge."""
    signature=load('update-native-contexts').signature
    if signature(native,before)!=signature(native,after):raise ValueError('Archive whole instruction shape changed')
    locations={row['address'] for row in before}
    for old,new in zip(before,after):
        if old['branch'] and not old['call'] and old['direct_target'] not in locations:
            raise ValueError('Archive unreviewed external branch')
        if old['call'] and old['direct_target'] is None:
            if not old['rip_references'] and old.get('operands')!=new.get('operands'):
                raise ValueError('Archive indirect dispatch changed')
        add_link(mapping,old['address'],new['address'])
        if old['direct_target'] is not None:add_link(mapping,old['direct_target'],new['direct_target'])
        if len(old['rip_references'])!=len(new['rip_references']):raise ValueError('Archive data edge count changed')
        for a,b in zip(old['rip_references'],new['rip_references']):add_link(mapping,a,b)


def unique_root(native,bindings,before,after,at):
    old=bindings.rows(native,before,at);part=before.containing(at);span=before.roots[part]
    candidates={r for r in after.roots.values() if abs(after.pe.base+r[0]-at)<=WINDOW and r[1]-r[0]==span[1]-span[0]}
    if len(candidates)>4096:raise ValueError('Archive candidate root budget exceeded')
    signature=load('update-native-contexts').signature;expected=signature(native,old);hits=[]
    for span in sorted(candidates):
        current=after.pe.base+span[0]
        try:rows=bindings.rows(native,after,current)
        except ValueError:continue  # An unrelated same-size root is only a candidate.
        if signature(native,rows)==expected:hits.append(current)
    if len(hits)!=1:raise ValueError('Archive missing or ambiguous complete root: '+hex(at))
    return hits[0]


def validate_packets(packets):
    if set(packets)!={'game-version','game-login'}:raise ValueError('Archive packet scope differs')
    widths={'string':16,'u32':4,'u8':1,'bool':1,'u64':8}
    for spec in packets.values():
        size=spec['object_size'];occupied=set()
        if type(size) is not int or not 16<=size<=512 or not 1<=len(spec['fields'])<=32:
            raise ValueError('Archive packet layout budget differs')
        for kind,offset in spec['fields']:
            if kind not in widths or type(offset) is not int or not 8<=offset<=size-widths[kind]:
                raise ValueError('Archive packet field layout differs')
            span=set(range(offset,offset+widths[kind]))
            if span&occupied:raise ValueError('Archive packet fields overlap')
            occupied.update(span)


def growth_boundary(image,context):
    """Rejected allocation growth still needs a real, non-overlapping entry."""
    growth=int(context['archive']['growth'],16);part=image.containing(growth)
    if part is None or image.roots[part][0]+image.pe.base!=growth:
        raise ValueError('Archive growth fixture is not an explicit unwind root')
    excluded=roots(context)|{int(at,16) for at in context['archive_leaves']}
    excluded.add(int(context['bindings']['encoder'],16));excluded.add(int(context['helpers']['memcpy'],16))
    excluded.update(int(at,16) for key,at in context['fixtures'].items() if key!='archive_slot')
    if growth in excluded:raise ValueError('Archive growth fixture overlaps native code or another fixture')
    return dict(address=hex(growth),boundary='unwind-root',scope='Growth body is not executed; all growth calls are rejected.')


def table_relation(before,after,baseline,current,mapping):
    """Only selected virtual slots are semantic dependencies; all bytes are pinned."""
    image_bytes=load('update-native-contexts').image_bytes
    old=image_bytes(before,int(baseline['archive']['table'],16),248)
    new=image_bytes(after,int(current['archive']['table'],16),248)
    if hashlib.sha256(old).hexdigest()!=baseline['archive_table_sha256']:
        raise ValueError('Archive baseline table changed')
    used=[]
    for name,slot in SLOTS.items():
        a,b=struct.unpack_from('<Q',old,slot)[0],struct.unpack_from('<Q',new,slot)[0]
        if a!=int(baseline['archive'][name],16) or b!=int(current['archive'][name],16) or mapping.get(a)!=b:
            raise ValueError('Archive used table slot changed: '+name)
        used.append(dict(slot=slot,role=name,before=hex(a),after=hex(b)))
    # Preserve the alias partition, without claiming semantic equivalence of
    # unexecuted entries. Unknown virtual targets still cannot execute.
    old_values=struct.unpack('<31Q',old);new_values=struct.unpack('<31Q',new)
    for i in range(31):
        for j in range(i):
            if (old_values[i]==old_values[j])!=(new_values[i]==new_values[j]):
                raise ValueError('Archive table alias layout changed')
    return dict(sha256=hashlib.sha256(new).hexdigest(),used_slots=used,
        excluded_slots=[slot for slot in range(0,248,8) if slot not in SLOTS.values()],
        excluded_scope='Target bytes/alias topology only; unexecuted table entries grant no semantic coverage.')


def transfer(native,bindings,before,after,baseline,writer):
    """Read-only typed mapping, shared by discovery and proof revalidation."""
    validate_packets(baseline['packets']);common=load('update-native-contexts');align=load('align-wire-contexts-11320')
    mapping={}
    for group in ('bindings','helpers'):
        if set(baseline[group])!=set(writer[group]):raise ValueError('Archive writer prerequisite fields differ')
        for key,value in baseline[group].items():add_link(mapping,int(value,16),int(writer[group][key],16))
    for key,value in baseline['fixtures'].items():
        if key=='archive_slot':
            if value!=writer['fixtures'][key] or value!=40:raise ValueError('Archive string slot changed')
        else:add_link(mapping,int(value,16),int(writer['fixtures'][key],16))
    for key in ('cookie','invalid_parameter_iat'):
        add_link(mapping,int(baseline['writer_metadata'][key],16),int(writer['writer_metadata'][key],16))
    if len(baseline['writer_metadata']['exception_calls'])!=len(writer['writer_metadata']['exception_calls']):
        raise ValueError('Archive writer exception fixture scope changed')
    for old,new in zip(baseline['writer_metadata']['exception_calls'],writer['writer_metadata']['exception_calls']):
        add_link(mapping,int(old,16),int(new,16))
    pair_rows(native,bindings.rows(native,before,int(baseline['bindings']['string-writer'],16)),
        bindings.rows(native,after,int(writer['bindings']['string-writer'],16)),mapping)
    for key,value in baseline['archive'].items():
        if key in ('table','growth'):continue
        old=int(value,16);target=unique_root(native,bindings,before,after,old)
        add_link(mapping,old,target)
        pair_rows(native,bindings.rows(native,before,old),bindings.rows(native,after,target),mapping)
    for spec in baseline['packets'].values():
        old=int(spec['writer'],16);target=unique_root(native,bindings,before,after,old)
        add_link(mapping,old,target)
        pair_rows(native,bindings.rows(native,before,old),bindings.rows(native,after,target),mapping)
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    leaves={}
    for text,spec in baseline['archive_leaves'].items():
        old=int(text,16)
        if old not in mapping:raise ValueError('Archive leaf has no reviewed direct caller')
        target=mapping[old];raw=common.image_bytes(before,old,spec['size'])
        if raw.hex()!=spec['bytes'] or hashlib.sha256(raw).hexdigest()!=spec['sha256']:
            raise ValueError('Archive baseline leaf changed')
        old_rows=align.leaf_rows(native,before,old,spec,decoder);new_rows=align.leaf_rows(native,after,target,spec,decoder)
        pair_rows(native,old_rows,new_rows,mapping)
        raw=common.image_bytes(after,target,spec['size'])
        leaves[hex(target)]=dict(bytes=raw.hex(),size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    if len(leaves)!=2 or set(baseline['archive_helpers'])!={'base_leaf','set_count_leaf'}:
        raise ValueError('Archive leaf/helper scope differs')
    def mapped(value):
        old=int(value,16)
        if old not in mapping:raise ValueError('Archive context contains undeclared relocation: '+value)
        return hex(mapping[old])
    archive={key:mapped(value) for key,value in baseline['archive'].items()}
    helpers={key:mapped(value) for key,value in baseline['archive_helpers'].items()}
    packets=copy.deepcopy(baseline['packets'])
    for name,spec in packets.items():
        original=baseline['packets'][name];spec['writer']=mapped(original['writer'])
        old_table=int(original['table'],16)
        if struct.unpack('<Q',common.image_bytes(before,old_table+16,8))[0]!=int(original['writer'],16):
            raise ValueError('Archive baseline packet table link changed')
        hits=align.packet_table_candidates(after,old_table,int(spec['writer'],16))
        if len(hits)!=1:raise ValueError('Archive missing or ambiguous packet table: '+name)
        add_link(mapping,old_table,hits[0]);spec['table']=hex(hits[0])
    current=dict(schema=1,family=FAMILY,source_sha256=writer['source_sha256'],source=writer['source'],
        bindings=copy.deepcopy(writer['bindings']),encoder_leaf=copy.deepcopy(writer['encoder_leaf']),
        helpers=copy.deepcopy(writer['helpers']),fixtures=copy.deepcopy(writer['fixtures']),
        writer_metadata=copy.deepcopy(writer['writer_metadata']),verify_whole_exports=True,
        archive=archive,archive_helpers=helpers,archive_leaves=leaves,packets=packets,layout=LAYOUT)
    growth_boundary(before,baseline);growth=growth_boundary(after,current)
    relation=table_relation(before,after,baseline,current,mapping);current['archive_table_sha256']=relation['sha256']
    # Validate the exact declared call and data closure, not any shape-masked
    # additional target. Growth is an explicit rejection fixture, not a root.
    allowed_calls={int(v,16) for key,v in archive.items() if key!='table'}|{int(v,16) for v in helpers.values()}|{int(writer['helpers']['memcpy'],16)}
    data_allowed={int(archive['table'],16)}
    data_allowed.update(mapping[ref] for text,spec in baseline['archive_leaves'].items()
        for row in align.leaf_rows(native,before,int(text,16),spec,decoder) for ref in row['rip_references'])
    base_refs=[row for row in bindings.rows(native,before,int(baseline['archive']['base-constructor'],16)) if row['rip_references']]
    if len(base_refs)!=1 or base_refs[0]['mnemonic']!='lea' or len(base_refs[0]['rip_references'])!=1:
        raise ValueError('Archive base constructor transient vptr source changed')
    transient=base_refs[0]['rip_references'][0];data_allowed.add(mapping[transient])
    for key,at in archive.items():
        if key in ('table','growth'):continue
        for row in bindings.rows(native,after,int(at,16)):
            if row['call'] and row['direct_target'] is not None and row['direct_target'] not in allowed_calls:
                raise ValueError('Archive callee outside declared closure')
            if any(ref not in data_allowed for ref in row['rip_references']):
                raise ValueError('Archive static data outside declared closure')
    return current,dict(mapping={hex(a):hex(b) for a,b in sorted(mapping.items())},table=relation,
        growth_fixture=growth,
        transient_tables=[dict(address=hex(at),bytes=common.image_bytes(after,at,8).hex(),
            scope='Overwritten constructor vptr only; no dispatch through this table is admitted.')
            for at in sorted(data_allowed-{int(archive['table'],16)})])


def report_valid(report,context,context_sha):
    if (report.get('source_sha256')!=context['source_sha256'] or report.get('scope')!=SCOPE
            or report.get('method')!='bounded_native' or report.get('network_used') is not False
            or report.get('profile_activated') is not False or report.get('runtime_activated') is not False
            or report.get('proof')!=context.get('transfer_proof') or report.get('context_sha256')!=context_sha
            or report.get('archive')!=context['archive'] or len(report.get('cases',[]))!=45
            or len(report.get('wire_cases',[]))!=64 or not all(r.get('guards') is True for r in report['wire_cases'])):
        raise ValueError('Archive context lacks its reviewed semantic proof')


def published_contexts(root,registry,*,value=None):
    root=Path(root);path=root/'knowledge'/INDEX/'index.json'
    if value is None:
        if not path.is_file():return []
        value=json.loads(path.read_text('utf-8'))
    if value.get('schema')!=1 or not isinstance(value.get('contexts'),list) or len(value['contexts'])>4096:
        raise ValueError('Invalid generated archive index')
    known={r['source_sha256']:r['order'] for r in registry['releases']};seen=set();result=[]
    for row in value['contexts']:
        if set(row)!={'context','check','order'} or type(row['order']) is not int or row['order']<0:
            raise ValueError('Invalid generated archive declaration')
        context=checked(root,row['context'],'generated-native-contexts');sha=context.get('source_sha256')
        if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha) or sha in seen or context.get('family')!=FAMILY:
            raise ValueError('Invalid generated archive source/family')
        report_valid(checked(root,row['check'],'native-adapter-checks'),context,row['context']['sha256'])
        seen.add(sha);result.append((Path(row['context']['path']),context,known.get(sha,row['order'])))
    return result


def baseline_context(root,knowledge):
    registry=load('native-release-registry').read(knowledge);found=[]
    api=load('native-release-registry')
    for path in (Path(knowledge)/'native-contexts').glob('archive-wire-*.json'):
        context=json.loads(path.read_text('utf-8'));identity=api.context_identity(path,context,registry)
        if identity is None:continue
        version,family=identity
        if family==FAMILY:found.append((path,context,next(r['order'] for r in registry['releases'] if r['id']==version)))
    found.extend(published_contexts(root,registry))
    if not found:raise ValueError('No reviewed archive wire baseline')
    return max(found,key=lambda row:(row[2],str(row[0])))[:2]


def target_writer(root,registry,sha):
    rows=[(path,context) for path,context,_ in load('update-native-string-writer').published_contexts(root,registry)
        if context['source_sha256']==sha]
    if len(rows)!=1:raise ValueError('A reviewed target string writer is required before archive transfer')
    return rows[0]


def plan_inputs(index,args,sha):
    registry=load('native-release-registry').read(args.knowledge);baseline_path,baseline=baseline_context(args.root,args.knowledge)
    writer_path,writer=target_writer(args.root,registry,sha)
    baselines={str(p):index.digest(p) for p in (Path(args.knowledge)/'native-contexts').glob('archive-wire-*.json')}
    baselines[str(baseline_path)]=index.digest(baseline_path)
    exports={str(Path(args.root)/'ghidra/request-exports'/baseline['source_sha256']/run/'details.json'):index.digest(
        Path(args.root)/'ghidra/request-exports'/baseline['source_sha256']/run/'details.json') for run in baseline['exports']}
    return dict(source=sha,tools=tools(),registry=index.digest(Path(args.knowledge)/'native-release-registry.json'),
        baselines=baselines,baseline_exports=exports,writer=dict(path=str(writer_path),sha256=index.digest(writer_path)))


def planned(context,proof):
    context={key:value for key,value in context.items() if key!='exports'}
    return dict(state='planned',source_sha256=context['source_sha256'],context=context,
        exports=sorted((hex(at) for at in roots(context)),key=lambda at:int(at,16)),dependencies=tools(),
        artifacts={proof['baseline']['path']:proof['baseline']['sha256'],proof['writer']['path']:proof['writer']['sha256'],
            context['transfer_proof']['path']:context['transfer_proof']['sha256']})


def discover(index,args,sha):
    registry=load('native-release-registry').read(args.knowledge)
    existing=[context for _,context,_ in published_contexts(args.root,registry) if context['source_sha256']==sha]
    if existing:
        context=existing[0];validate(index,args,context)
        return planned(context,checked(args.root,context['transfer_proof'],PROOFS))
    writer_path,writer=target_writer(args.root,registry,sha)
    load('update-native-string-writer').validate(index,args,writer)
    path,baseline=baseline_context(args.root,args.knowledge)
    if baseline.get('transfer_proof'):validate(index,args,baseline)
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    before=args.source_store.image(native,baseline['source_sha256']);after=args.source_store.image(native,sha)
    export_coverage(args.root,baseline,native,bindings,before)
    context,relocation=transfer(native,bindings,before,after,baseline,writer)
    proof=load('update-native-contexts').receipt(args.root,PROOFS,dict(schema=1,adapter=ADAPTER,scope=SCOPE,
        baseline=dict(path=str(path),sha256=digest(path)),writer=dict(path=str(writer_path),sha256=digest(writer_path)),
        target=context,relocation=relocation,tools=tools(),runtime_activated=False))
    context=dict(context,transfer_proof=proof)
    return planned(context,checked(args.root,proof,PROOFS))


def validate(index,args,context,seen=None):
    proof=checked(args.root,context['transfer_proof'],PROOFS);seen=set(seen or ())
    identity=context['transfer_proof']['sha256']
    if identity in seen or len(seen)>=32:raise ValueError('Archive proof cycle/depth budget exceeded')
    seen.add(identity)
    if (proof.get('schema')!=1 or proof.get('adapter')!=ADAPTER or proof.get('scope')!=SCOPE
            or proof.get('tools')!=tools() or proof.get('runtime_activated') is not False
            or context.get('layout')!=LAYOUT or proof.get('target')!={k:v for k,v in context.items() if k not in ('exports','transfer_proof','release_id')}):
        raise ValueError('Archive proof fields, tools or layout differ')
    path=Path(proof['baseline']['path']).resolve()
    if not (path.is_relative_to((HERE/'knowledge/native-contexts').resolve()) or
            path.is_relative_to((Path(args.root)/'knowledge/generated-native-contexts').resolve())):
        raise ValueError('Archive baseline outside reviewed contexts')
    if digest(path)!=proof['baseline']['sha256']:raise ValueError('Archive baseline changed')
    baseline=json.loads(path.read_text('utf-8'))
    if baseline.get('transfer_proof'):validate(index,args,baseline,seen)
    writer=checked(args.root,proof['writer'],'generated-native-contexts')
    load('update-native-string-writer').validate(index,args,writer)
    if writer['source_sha256']!=context['source_sha256']:raise ValueError('Archive target writer source differs')
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    before=args.source_store.image(native,baseline['source_sha256']);after=args.source_store.image(native,context['source_sha256'])
    export_coverage(args.root,baseline,native,bindings,before)
    expected,relocation=transfer(native,bindings,before,after,baseline,writer)
    if expected!=proof['target'] or relocation!=proof['relocation']:
        raise ValueError('Archive relocated closure, fields or table differs')
    if context.get('exports'):export_coverage(args.root,context,native,bindings,after)
    return context


def materialize(index,args,sha,plan,database):
    context=copy.deepcopy(plan['context']);db=index.open_index(database);exports={};workflow=load('research-workflow')
    try:
        for at in plan['exports']:
            state=workflow.function_state(index,db,sha,at)
            if state['state']!='ready':raise ValueError('Archive target export is not ready: '+at)
            for row in state['variants']:
                if not row['completed']:continue
                path=Path(row['artifact']).resolve();parent=(Path(args.root)/'ghidra/request-exports'/sha).resolve()
                if path.is_relative_to(parent) and path.name=='details.json':exports[path.parent.name]=index.digest(path)
    finally:db.close()
    context['exports']=exports;validate(index,args,context)
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    export_coverage(args.root,context,native,bindings,args.source_store.image(native,sha))
    target=load('update-native-contexts').receipt(args.root,'generated-native-contexts',context)
    artifacts={**plan['artifacts'],target['path']:target['sha256']}
    artifacts.update({str(Path(args.root)/'ghidra/request-exports'/sha/run/'details.json'):value for run,value in exports.items()})
    declaration=dict(id='native-auto-archive-wire',adapter=ADAPTER,scope=SCOPE,contracts=[],context=target,
        proof=context['transfer_proof'],dependencies=tools(),artifacts=artifacts)
    return dict(checks=[declaration],queue=[])


def execute(index,args,sha,declaration):
    context=checked(args.root,declaration['context'],'generated-native-contexts')
    if (declaration.get('adapter')!=ADAPTER or declaration.get('scope')!=SCOPE or context['source_sha256']!=sha
            or declaration['dependencies']!=tools()):raise ValueError('Archive check declaration differs')
    for filename,expected in declaration['artifacts'].items():
        if index.digest(filename)!=expected:raise ValueError('Archive check artifact changed')
    validate(index,args,context)
    report=load('verify-archive-wire-context').verify(context,args.root)
    report.update(scope=SCOPE,proof=context['transfer_proof'],context_sha256=declaration['context']['sha256'],runtime_activated=False)
    report_valid(report,context,declaration['context']['sha256'])
    target=load('update-native-contexts').receipt(args.root,'native-adapter-checks',report)
    return dict(id=declaration['id'],state='passed',report=target['path'],sha256=target['sha256'],scope=SCOPE,
        runtime_activated=False,profile_activated=False)


def publish(index,args,sha,declaration,outcome):
    if outcome.get('state')!='passed':raise ValueError('Only a passed archive context can be published')
    context=checked(args.root,declaration['context'],'generated-native-contexts');validate(index,args,context)
    if context['source_sha256']!=sha:raise ValueError('Archive publication source differs')
    check=dict(path=outcome['report'],sha256=outcome['sha256'])
    report_valid(checked(args.root,check,'native-adapter-checks'),context,declaration['context']['sha256'])
    registry=load('native-release-registry').read(args.knowledge);published_contexts(args.root,registry)
    path=Path(args.root)/'knowledge'/INDEX/'index.json';old=json.loads(path.read_text('utf-8')) if path.is_file() else dict(schema=1,contexts=[])
    entries=[row for row in old['contexts'] if checked(args.root,row['context'],'generated-native-contexts')['source_sha256']!=sha]
    ranks={row['source_sha256']:row['order'] for row in registry['releases']}
    rank=ranks.get(sha,max([row['order'] for row in registry['releases']]+[row['order'] for row in entries])+1)
    entries.append(dict(context=declaration['context'],check=check,order=rank))
    value=dict(schema=1,contexts=sorted(entries,key=lambda row:(row['order'],row['context']['path'])))
    published_contexts(args.root,registry,value=value)
    workflow=load('research-workflow');workflow.atomic(path,workflow.canonical(value))
    return dict(path=str(path),sha256=index.digest(path))
