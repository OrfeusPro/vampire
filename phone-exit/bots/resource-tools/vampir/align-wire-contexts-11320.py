"""Bounded archive/string candidates and source-bound contexts; replay remains required."""
import argparse
import copy
import hashlib
import importlib.util
import importlib.metadata
import json
from pathlib import Path
import re
import struct
import platform
import sys

HERE=Path(__file__).resolve().parent
OLD='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
NEW='544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c'
WINDOW=65536
NAMES=('utf8','string-writer','archive-wire')


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def leaf_rows(native,image,address,spec,decoder):
    size=spec['size']
    if type(size) is not int or not 1<=size<=512:raise ValueError('Explicit leaf size budget exceeded')
    offset=image.offset(address-image.pe.base);raw=image.data[offset:offset+size]
    instructions=list(decoder.disasm(raw,address))
    if sum(i.size for i in instructions)!=size or not instructions or instructions[-1].mnemonic!='ret':
        raise ValueError('Explicit leaf is not a complete returning span')
    locations={i.address for i in instructions};result=[]
    for ins in instructions:
        call,branch=ins.group(native.capstone.CS_GRP_CALL),ins.group(native.capstone.CS_GRP_JUMP)
        target=ins.operands[0].imm if (call or branch) and ins.operands and ins.operands[0].type==native.X86_OP_IMM else None
        if call or (branch and target not in locations):raise ValueError('Explicit leaf has an external edge')
        result.append(dict(address=ins.address,bytes=ins.bytes.hex(),call=call,branch=branch,direct_target=target,
            rip_references=[ins.address+ins.size+op.mem.disp for op in ins.operands
                if op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP]))
    return result


def packet_table_candidates(image,old_table,writer):
    """Explicit writer slot +16 only, bounded to the old table's address window."""
    pattern=struct.pack('<Q',writer);hits=[]
    for section in image.pe.sections:
        begin=max(section['rva'],old_table-image.pe.base-WINDOW)
        end=min(section['rva']+section['raw_size']-24,old_table-image.pe.base+WINDOW)
        if end<begin:continue
        start=image.offset(begin)+16;stop=image.offset(end)+24;cursor=start
        while cursor<stop:
            cursor=image.data.find(pattern,cursor,stop)
            if cursor<0:break
            table=image.pe.base+section['rva']+cursor-section['raw']-16
            if table%8==0:hits.append(table)
            cursor+=1
    return sorted(set(hits))


def discover(root):
    native,bindings,align=load('build-native-entry-code'),load('update-bindings'),load('align-stat-batch-11318')
    paths={name:HERE/'knowledge/native-contexts'/(name+'-11318.json') for name in NAMES}
    raw_contexts={name:path.read_bytes() for name,path in paths.items()}
    contexts={name:json.loads(raw.decode('utf-8')) for name,raw in raw_contexts.items()}
    if any(c.get('source_sha256')!=OLD for c in contexts.values()):raise ValueError('Wire baseline context source differs')
    images={};pinned={str(paths[n]):hashlib.sha256(v).hexdigest() for n,v in raw_contexts.items()}
    for sha in (OLD,NEW):
        path=root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe';raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('Wire alignment source SHA differs')
        images[sha]=native.Image(raw);pinned[str(path)]=sha
    # Keep every inherited baseline export pinned even when this scanner uses bytes.
    for context in contexts.values():
        for run,sha in context['exports'].items():
            if Path(run).name!=run or not run.startswith('run-') or not re.fullmatch('[0-9a-f]{64}',sha):
                raise ValueError('Invalid baseline export declaration')
            path=root/'ghidra/request-exports'/OLD/run/'details.json'
            if digest(path)!=sha:raise ValueError('Wire baseline export changed')
            pinned[str(path)]=sha
    context=contexts['archive-wire'];roles={}
    for group in ('bindings','archive'):
        roles.update({group+':'+name:at for name,at in context[group].items() if name!='table'})
    roles.update({'packet:'+name:p['writer'] for name,p in context['packets'].items()})
    leaves={context['bindings']['encoder']:context['encoder_leaf'],**context['archive_leaves']}
    roles.update({'leaf:'+at:at for at in context['archive_leaves']})
    wanted=sorted(set(roles.values()))
    if len(wanted)!=18:raise ValueError('Explicit wire candidate scope changed')
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    if native.capstone.__version__!='5.0.6':raise ValueError('Pinned wire candidate runtime required')
    cache={};reports={};links={}
    def rows(sha,at):
        if (sha,at) not in cache:cache[(sha,at)]=bindings.rows(native,images[sha],at)
        return cache[(sha,at)]
    def link(before,after):links.setdefault(hex(before),set()).add(hex(after))
    for text in wanted:
        address=int(text,16);leaf=leaves.get(text);method='whole_unwind';hits=[]
        try:before=rows(OLD,address)
        except ValueError as error:
            if leaf is None:reports[text]=dict(candidates=[],reason=str(error));continue
            method='explicit_leaf_candidate';offset=images[OLD].offset(address-images[OLD].pe.base)
            raw=images[OLD].data[offset:offset+leaf['size']]
            if raw.hex()!=leaf['bytes'] or hashlib.sha256(raw).hexdigest()!=leaf['sha256']:
                raise ValueError('Wire baseline leaf bytes differ')
            before=leaf_rows(native,images[OLD],address,leaf,decoder)
        expected=align.instruction_shape(before,decoder)
        if method=='whole_unwind':
            part=images[OLD].containing(address);old_root=images[OLD].roots[part];size=old_root[1]-old_root[0]
            roots={root for root in images[NEW].roots.values()
                if abs(images[NEW].pe.base+root[0]-address)<=WINDOW and root[1]-root[0]==size}
            if len(roots)>4096:raise ValueError('Wire root candidate budget exceeded')
            for root in sorted(roots):
                current=images[NEW].pe.base+root[0]
                try:after=rows(NEW,current)
                except ValueError:continue
                if align.instruction_shape(after,decoder)==expected:hits.append(hex(current))
        else:
            section=next(s for s in images[OLD].pe.sections if s['rva']<=address-images[OLD].pe.base<s['rva']+s['raw_size'])
            target_section=next(s for s in images[NEW].pe.sections if s['name']==section['name'])
            begin=max(target_section['rva'],address-images[NEW].pe.base-WINDOW)
            end=min(target_section['rva']+target_section['raw_size']-leaf['size'],address-images[NEW].pe.base+WINDOW)
            cursor=images[NEW].offset(begin);stop=images[NEW].offset(end)+1
            prefix=bytes.fromhex(before[0]['bytes'])[:3]
            while cursor<stop:
                cursor=images[NEW].data.find(prefix,cursor,stop)
                if cursor<0:break
                current=images[NEW].pe.base+target_section['rva']+cursor-target_section['raw']
                try:after=leaf_rows(native,images[NEW],current,leaf,decoder)
                except ValueError:cursor+=1;continue
                if align.instruction_shape(after,decoder)==expected:hits.append(hex(current))
                cursor+=1
        hits=sorted(set(hits))
        if len(hits)>32:raise ValueError('Wire shape candidate budget exceeded')
        reports[text]=dict(method=method,candidates=hits,instructions=len(before),
            shape_sha256=hashlib.sha256(json.dumps(expected,separators=(',',':')).encode()).hexdigest(),
            reason=None if len(hits)==1 else 'Missing/ambiguous complete shape')
        if len(hits)!=1:continue
        current=int(hits[0],16)
        after=rows(NEW,current) if method=='whole_unwind' else leaf_rows(native,images[NEW],current,leaf,decoder)
        for a,b in zip(before,after):
            link(a['address'],b['address'])
            if a['direct_target'] is not None:link(a['direct_target'],b['direct_target'])
            for old,new in zip(a['rip_references'],b['rip_references']):link(old,new)
    packet_tables={}
    for name,packet in context['packets'].items():
        writer=reports[packet['writer']]['candidates']
        if len(writer)!=1:continue
        old_table=int(packet['table'],16);old_off=images[OLD].offset(old_table-images[OLD].pe.base)
        if struct.unpack_from('<Q',images[OLD].data,old_off+16)[0]!=int(packet['writer'],16):
            raise ValueError('Baseline packet writer slot differs')
        hits=packet_table_candidates(images[NEW],old_table,int(writer[0],16))
        packet_tables[name]=[hex(v) for v in hits]
        if len(hits)==1:link(old_table,hits[0])
    return native,images,contexts,pinned,roles,reports,links,packet_tables


def generate_contexts(root,images,contexts,reports,links,packet_tables,exports):
    if any(len(item['candidates'])!=1 for item in reports.values()) or any(len(v)!=1 for v in links.values()):
        raise ValueError('Missing/ambiguous explicit wire candidates')
    if set(packet_tables)!=set(contexts['archive-wire']['packets']) or any(len(v)!=1 for v in packet_tables.values()):
        raise ValueError('Missing/ambiguous packet table candidates')
    mapping={key:next(iter(values)) for key,values in links.items()}
    required={int(item['candidates'][0],16) for old,item in reports.items()
        if item['method']=='whole_unwind' and old!=contexts['archive-wire']['archive']['growth']}
    if len(required)!=14:raise ValueError('Whole wire export scope differs')
    available=set();current_exports={};pinned={};native=load('build-native-entry-code');binding=load('update-bindings')
    for supplied in exports:
        path=Path(supplied).resolve()
        if (not path.is_relative_to((root/'ghidra/request-exports'/NEW).resolve()) or path.name!='details.json'
                or not path.parent.name.startswith('run-')):raise ValueError('Wire export outside target library')
        raw=path.read_bytes();report=json.loads(raw.decode('utf-8'));sha=hashlib.sha256(raw).hexdigest()
        if report.get('new_source_sha256',report.get('source_sha256'))!=NEW:raise ValueError('Wire export source differs')
        for function in report.get('functions',[]):
            at=int(function['address'],16)
            if at not in required or function.get('decompilation_completed') is not True:continue
            expected={(r['address'],r['bytes']) for r in binding.rows(native,images[NEW],at)}
            actual={(int(r['address'],16),r['bytes'].lower()) for r in function.get('instructions',[])}
            if expected<=actual:available.add(at)
        current_exports[path.parent.name]=sha;pinned[str(path)]=sha
    if not required<=available:raise ValueError('Wire exports do not cover all fourteen full roots')
    image=images[NEW]
    def mapped(value):
        if value not in mapping:raise ValueError('Unreviewed context address '+value)
        return mapping[value]
    def leaf(old,location):
        at=int(location,16);off=image.offset(at-image.pe.base);raw=image.data[off:off+old['size']]
        return dict(bytes=raw.hex(),sha256=hashlib.sha256(raw).hexdigest(),size=len(raw))
    def convert(value,key=None):
        if key=='source_sha256':return NEW
        if key=='source':return str(root/'client-code-snapshots'/NEW/'ProjectRED-Win64-Shipping.exe')
        if key=='exports':return current_exports.copy()
        if key=='encoder_leaf':return leaf(value,mapped(contexts['archive-wire']['bindings']['encoder']))
        if key=='archive_leaves':return {mapped(a):leaf(item,mapped(a)) for a,item in value.items()}
        if key=='archive_table_sha256':
            table=int(mapped(contexts['archive-wire']['archive']['table']),16);off=image.offset(table-image.pe.base)
            return hashlib.sha256(image.data[off:off+0xf8]).hexdigest()
        if isinstance(value,dict):return {k:convert(v,k) for k,v in value.items()}
        if isinstance(value,list):return [convert(v) for v in value]
        if isinstance(value,str) and re.fullmatch('0x[0-9a-fA-F]+',value):return mapped(value.lower())
        return value
    generated={name:convert(copy.deepcopy(context)) for name,context in contexts.items()}
    writer=int(mapping[contexts['archive-wire']['bindings']['string-writer']],16)
    indirect=[r['operands'] for r in binding.rows(native,image,writer) if r['call'] and r['direct_target'] is None]
    for context in generated.values():
        context['writer_metadata']['indirect']=indirect.copy();context['verify_whole_exports']=True
    return generated,pinned,sorted(hex(a) for a in required)


def run(root,exports=()):
    tool_sha=digest(__file__)
    dependencies={n:digest(HERE/n) for n in ('build-native-entry-code.py','extract-native-enums.py',
        'update-bindings.py','align-stat-batch-11318.py','research-workflow.py')}
    load('build-native-entry-code')  # Adds the project's pinned analysis runtime path.
    runtime=importlib.metadata.distribution('capstone');record=runtime.read_text('RECORD')
    if runtime.version!='5.0.6' or not record:raise ValueError('Pinned wire runtime metadata required')
    runtime_sha=hashlib.sha256(record.encode()).hexdigest()
    root=Path(root);native,images,contexts,pinned,roles,reports,links,tables=discover(root)
    report=dict(schema=1,baseline_sha256=OLD,source_sha256=NEW,roles=roles,functions=reports,
        links={a:sorted(b) for a,b in sorted(links.items())},packet_table_candidates=tables,
        search_window=WINDOW,inputs=pinned,tool_sha256=tool_sha,dependency_sha256=dependencies,
        runtime=dict(python=platform.python_version(),executable=sys.executable,capstone=runtime.version,
            capstone_record_sha256=runtime_sha),
        semantic_verification=False,native_replay_verified=False,network_used=False,profile_activated=False,
        limits=['Explicit complete unwind/leaf candidate shapes only; indirect dispatch, data ownership and fixture effects remain unverified.',
            'Generated contexts require independent semantic replay; shape/slot matches never grant runtime or profile admission.'])
    if exports:
        generated,export_inputs,required=generate_contexts(root,images,contexts,reports,links,tables,exports)
        report.update(contexts=generated,required_export_roots=required);pinned.update(export_inputs)
    for path,sha in pinned.items():
        if digest(path)!=sha:raise ValueError('Wire alignment input changed during execution')
    for name,sha in report['dependency_sha256'].items():
        if digest(HERE/name)!=sha:raise ValueError('Wire alignment tool changed during execution')
    if digest(__file__)!=report['tool_sha256']:raise ValueError('Wire alignment producer changed during execution')
    if hashlib.sha256((runtime.read_text('RECORD') or '').encode()).hexdigest()!=runtime_sha:
        raise ValueError('Wire alignment runtime changed during execution')
    path=load('research-workflow').snapshot(root,'wire-context-alignment-11320',report)
    return path,report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--export',type=Path,action='append',default=[])
    args=parser.parse_args();path,report=run(args.root,args.export)
    print(json.dumps(dict(report=str(path),sha256=digest(path),
        roots={old:item['candidates'] for old,item in report['functions'].items()},
        packet_tables=report['packet_table_candidates'],contexts=list(report.get('contexts',{})))))
