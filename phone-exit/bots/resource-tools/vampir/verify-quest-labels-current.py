"""Source-bound Russian quest labels, reusing qualified names and packet proofs."""
import argparse
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import struct
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
ROOT=Path('F:/PhoneExit Resources/Vampir')
CONTEXT=HERE/'knowledge/native-contexts/quest-labels-current.json'
UI=HERE.parents[1]/'vampir/ui-prototype'
TARGET=UI/'quest-names-current.js'
RECIPE='quest-labels-current-v1'
SHA=re.compile('[a-f0-9]{64}')
RULE=dict(receiver_load_offset=186,receiver_load_hex='488b5308',receiver_call_offset=202,
    producer_literal_offset=36,producer_result_offset=66,producer_result_hex='488bf8',
    producer_store_offset=1024,producer_store_hex='48897d6f',producer_call_offset=1032,prefix_call_offset=37)
PREFIX='40555641544155488d6c24b84881ec480100004c8bea488955784c8be1488d5578488d4de0'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def require(ok,reason):
    if not ok:raise ValueError('Quest labels: '+reason)


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def retain(owner,values):
    require(isinstance(values,dict) and values,'empty retained inputs')
    for name,expected in values.items():
        require(Path(name).is_absolute() and SHA.fullmatch(str(expected)),'retained descriptor differs')
        owner.expect(name,expected)


def checked(owner,pointer):
    require(isinstance(pointer,dict) and set(pointer)=={'path','sha256'} and SHA.fullmatch(str(pointer['sha256'])),
        'exact proof pointer required')
    path=Path(pointer['path']).resolve()
    require(path.is_relative_to(owner.root) and path.name in ('manifest.json','details.json'),'proof location differs')
    raw=path.read_bytes();require(len(raw)<=32*1024*1024,'proof byte budget exceeded')
    require(owner.remember(path,raw)==pointer['sha256'],'proof SHA differs')
    return json.loads(raw)


def inputs(root,context_path):
    index=load('knowledge-index')
    # Loads the retained decoder environment; does not construct a PE image.
    load('build-native-entry-code')
    args=SimpleNamespace(root=Path(root).resolve(),knowledge=HERE/'knowledge')
    owner=index.extension('resource-owner-v4').begin(index,args)
    try:
        path=Path(context_path).resolve();raw=path.read_bytes()
        owner.remember(path,raw);context=json.loads(raw)
        require(context.get('schema')==1 and context.get('recipe')==RECIPE
            and SHA.fullmatch(str(context.get('source_sha256')))
            and SHA.fullmatch(str(context.get('baseline_sha256')))
            and context.get('key_rule')==RULE and context.get('prefix_hex')==PREFIX,'context rule differs')
        directory=index.extension('resource-directory-v1').Scope(index,args)
        args.resource_directory_v1_scope=directory
        named=index.extension('resource-named-tables-v1').Scope(index,args)
        baseline=named.read(context['named_baseline']);parent=directory.read(baseline['named_report'])
        source=parent['inputs']['source'];archive=Path(source['path']).resolve()
        require(baseline.get('recipe')=='named-table-baselines-v1'
            and baseline['source']==dict(archive_key=str(archive),sha256=source['sha256'])
            and parent.get('recipe')=='resource-directory-v1'
            and parent.get('authoritative_directory_for_archive') is True
            and parent['inputs']['rules']==directory.rules and parent['inputs']['runtime']==directory.runtime
            and parent['inputs']['key_proof']==directory.configuration['key_proof'], 'named resource scope differs')
        owner.expect(archive,source['sha256'])
        for name in ('record_index','current_csv','key_proof'):directory.read(parent['inputs'][name])
        key_source=parent['inputs']['key_source'];owner.expect(key_source['path'],key_source['sha256'])
        tables={};bodies={}
        require(set(context['tables'])=={'Quest','QuestNamesRu'},'table roles differ')
        for name,canonical in context['tables'].items():
            matches=[t for t in parent['csv_bindings'] if t.get('canonical_path')==canonical]
            require(len(matches)==1 and matches[0].get('directory_identity_verified') is True,'named table is ambiguous')
            table=matches[0]
            selected={key:table[key] for key in ('canonical_path','sha256','file','bytes','header','rows')}
            reference=[t for t in baseline['tables'] if t.get('canonical_path')==canonical]
            require(len(reference)==1 and reference[0].get('state')=='verified_payload'
                and all(reference[0].get(key)==value for key,value in selected.items())
                and table['sha256']==context['expected_table_sha256'][name], 'named table baseline differs')
            bodies[name]=named.payload(selected);tables[name]=selected
        observation=checked(owner,context['observation_proof'])
        require(observation.get('recipe')=='quest-observation-current-v1'
            and observation.get('source_sha256')==context['source_sha256']
            and observation.get('observation_projection_verified') is True
            and observation.get('packet_compatibility',{}).get('1854') is True,'packet key observation is unqualified')
        retain(owner,observation['definition']['inputs'])
        dispatch=checked(owner,context['dispatch_proof'])
        require(dispatch.get('source_sha256')==context['source_sha256']
            and dispatch.get('whole_instruction_shape_verified') is True
            and dispatch['functions']['receiver']==context['receiver']
            and dispatch['fixture_boundaries']['key_wrapper']['target']==context['wrapper_prefix'], 'receiver binding differs')
        exports={role:checked(owner,context[role+'_export']) for role in ('receiver','producer')}
        for role,export in exports.items():
            require(export.get('new_source_sha256')==context['source_sha256'],role+' export source differs')
        for file in [Path(__file__).resolve(),UI/'quest-names-ru.js',HERE/'build-native-entry-code.py',
                HERE/'extract-native-enums.py',HERE/'research-workflow.py',HERE/'audit-client-release.py']:
            owner.digest(file)
        runtime=dict(observation['definition']['runtime_inputs'])
        runtime.update(directory.runtime['portable']['files'])
        runtime[directory.runtime['cryptography']['binary']['path']]=directory.runtime['cryptography']['binary']['sha256']
        producer=int(context['producer'],16)
        function=next(f for f in exports['producer']['functions'] if int(f['address'],16)==producer)
        at=producer+RULE['producer_call_offset']
        row=next(r for r in function['instructions'] if int(r['address'],16)==at)
        operand=bytes.fromhex(row['bytes']);require(len(operand)==5 and operand[0]==0xe8,'selected key call differs')
        binding=dict(receiver=context['receiver'],producer=context['producer'],wrapper_prefix=context['wrapper_prefix'],
            shared_lookup=hex(at+5+struct.unpack_from('<i',operand,1)[0]),property='QuestInfoId',
            scope='incoming_key_shared_lookup_prefix',active_task_verified=False)
        selected=dict(recipe=RECIPE,source_sha256=context['source_sha256'],
            inputs={str(p):sha for p,sha in owner.files.items()},runtime_inputs=runtime,
            context_sha256=digest(path),tables=tables,source=source,key_binding=binding,limits=context['limits'])
        return owner,directory,context,parent,exports,bodies,selected
    except BaseException:
        owner.abort();raise


def key_binding(context,exports,source):
    native=load('build-native-entry-code');image=native.Image(source)
    def data(address,size):
        offset=image.offset(address-image.pe.base);value=source[offset:offset+size]
        require(len(value)==size,'key data exceeds source');return value
    def function(role):
        address=int(context[role],16)
        matches=[f for f in exports[role]['functions'] if int(f['address'],16)==address]
        require(len(matches)==1 and matches[0]['decompilation_completed']
            and matches[0]['block_coverage_complete'],role+' export is incomplete')
        rows=matches[0]['instructions']
        require(all(data(int(row['address'],16),len(bytes.fromhex(row['bytes'])))==bytes.fromhex(row['bytes'])
            for row in rows),role+' export bytes differ')
        return address,{int(row['address'],16):row for row in rows}
    def exact(rows,at,expected):
        require(rows.get(at,{}).get('bytes')==expected,'key forwarding instruction differs')
    def call(rows,at):
        raw=bytes.fromhex(rows.get(at,{}).get('bytes',''))
        require(len(raw)==5 and raw[0]==0xe8,'direct key call differs')
        return at+5+struct.unpack_from('<i',raw,1)[0]
    receiver,rows=function('receiver');rule=context['key_rule']
    exact(rows,receiver+rule['receiver_load_offset'],rule['receiver_load_hex'])
    require(call(rows,receiver+rule['receiver_call_offset'])==int(context['wrapper_prefix'],16),'incoming wrapper target differs')
    producer,named=function('producer');literal_at=producer+rule['producer_literal_offset']
    raw=bytes.fromhex(named.get(literal_at,{}).get('bytes',''))
    require(raw[:3]==bytes.fromhex('488d15') and len(raw)==7,'named quest key LEA differs')
    literal=literal_at+7+struct.unpack_from('<i',raw,3)[0]
    require(data(literal,24)=='QuestInfoId\0'.encode('utf-16le'),'named quest key literal differs')
    exact(named,producer+rule['producer_result_offset'],rule['producer_result_hex'])
    exact(named,producer+rule['producer_store_offset'],rule['producer_store_hex'])
    lookup=call(named,producer+rule['producer_call_offset'])
    wrapper=int(context['wrapper_prefix'],16);prefix=bytes.fromhex(PREFIX)
    part=image.containing(wrapper)
    require(part is not None and image.pe.base+image.roots[part][0]==wrapper
        and data(wrapper,len(prefix))==prefix,'wrapper forwarding prefix differs')
    at=wrapper+rule['prefix_call_offset'];raw=data(at,5)
    require(raw[0]==0xe8 and at+5+struct.unpack_from('<i',raw,1)[0]==lookup,'shared key lookup differs')
    return dict(receiver=hex(receiver),producer=hex(producer),wrapper_prefix=hex(wrapper),shared_lookup=hex(lookup),
        property='QuestInfoId',scope='incoming_key_shared_lookup_prefix',active_task_verified=False)


def catalog(bodies):
    quests=list(csv.DictReader(io.StringIO(bodies['Quest'].decode('utf-8-sig'))))
    labels=list(csv.DictReader(io.StringIO(bodies['QuestNamesRu'].decode('utf-8-sig'))))
    require(quests and labels and set(('Id','PreQuestId'))<=quests[0].keys()
        and set(('Id','Name','DescObjective'))<=labels[0].keys(),'catalog schema differs')
    require(len({q['Id'] for q in quests})==len(quests),'quest IDs are ambiguous')
    grouped={}
    for label in labels:grouped.setdefault(label['Id'],[]).append(label)
    values={};skipped=[]
    for quest in sorted(quests,key=lambda row:int(row['Id'])):
        key=quest['Id']
        require(re.fullmatch(r'(?:0|[1-9][0-9]{0,19})',key) and int(key)<2**64,'quest key exceeds bounds')
        matches=grouped.get(key,[])
        if len(matches)!=1:
            skipped.append(dict(id=key,reason='ambiguous' if matches else 'missing'));continue
        row=matches[0]
        if not row['Name'] or not re.search('[А-Яа-яЁё]',row['Name']):
            skipped.append(dict(id=key,reason='untranslated'));continue
        require(len(row['Name'])<=256 and len(row['DescObjective'])<=2048,'quest text exceeds bounds')
        values[key]=dict(title=row['Name'],objective=row['DescObjective'])
    return values,skipped


def render(context,selected,values):
    payload=json.dumps(values,ensure_ascii=False,separators=(',',':'))
    shared=('const names='+payload+';') in (UI/'quest-names-ru.js').read_text('utf-8')
    metadata=dict(source_sha256=context['source_sha256'],archive_sha256=selected['source']['sha256'],
        tables={name:{key:row[key] for key in ('canonical_path','sha256','rows')} for name,row in selected['tables'].items()},
        scope='quest_labels_only',shared_catalog=shared)
    baseline=context['baseline_sha256'];source=context['source_sha256']
    code='/* Generated current quest labels; verify-quest-labels-current.py. No game actions. */\n'
    code+="(function(root){'use strict';const base=root.VampirQuestNamesRu;\n"
    code+='if(!base||base.sourceSha256!=='+json.dumps(baseline)+"){if(typeof module!=='undefined')module.exports=null;return;}\n"
    code+='const source='+json.dumps(source)+',metadata=Object.freeze('+json.dumps(metadata,ensure_ascii=False,separators=(',',':'))+');\n'
    if shared:
        checks=['base.count==='+str(len(values))]+['base.metadata?.tables?.'+name+'?.sha256==='+json.dumps(context['expected_table_sha256'][name]) for name in ('Quest','QuestNamesRu')]
        code+='if(!('+ '&&'.join(checks)+")){if(typeof module!=='undefined')module.exports=null;return;}\n"
        lookup='base.get(id,base.sourceSha256)'
    else:
        code+='const names='+payload+';Object.values(names).forEach(Object.freeze);Object.freeze(names);\n'
        lookup="typeof id==='string'&&Object.hasOwn(names,id)?names[id]:null"
    code+='const api=Object.freeze({...base,currentSourceSha256:source,metadataBySource:Object.freeze({[base.sourceSha256]:base.metadata,[source]:metadata}),\n'
    code+='get(id,sha=base.sourceSha256){if(sha!==source)return base.get(id,sha);return '+lookup+';}});\n'
    code+="root.VampirQuestNamesRu=api;if(typeof module!=='undefined')module.exports=api;})(typeof window==='undefined'?globalThis:window);\n"
    return code,metadata


def validate(report,selected):
    require(report.get('schema')==1 and report.get('recipe')==RECIPE and report.get('definition')==selected
        and report.get('source_sha256')==selected['source_sha256'] and report.get('native_execution') is False
        and report.get('native_proofs_reused') is True and report.get('network_used') is False
        and report.get('runtime_admitted') is False and report.get('labels_verified') is True
        and report.get('dialogues_verified') is False and report.get('outgoing_actions_admitted') is False
        and report.get('key_binding')==selected['key_binding'] and report.get('limits')==selected['limits']
        and report.get('tables')==selected['tables'] and report.get('names',0)>0
        and SHA.fullmatch(str(report.get('output_sha256'))),'cached proof boundary differs')


def verify(*,root=ROOT,context_path=CONTEXT,write=False):
    owner,directory,context,parent,exports,bodies,selected=inputs(root,context_path)
    try:
        workflow=load('research-workflow');key=hashlib.sha256(workflow.canonical(selected)).hexdigest()
        cache=Path(root)/'knowledge'/(RECIPE+'-cache')/(key+'.json')
        if cache.is_file():
            pointer=json.loads(cache.read_bytes());report=checked(owner,pointer);validate(report,selected)
            if not write:require(digest(TARGET)==report['output_sha256'],'generated catalog changed')
            elif not TARGET.is_file() or digest(TARGET)!=report['output_sha256']:
                values,_=catalog(bodies);code,_=render(context,selected,values)
                require(hashlib.sha256(code.encode()).hexdigest()==report['output_sha256'],'regenerated catalog differs')
                TARGET.write_text(code,encoding='utf-8',newline='\n')
            owner.expect(TARGET,report['output_sha256']);owner.finish()
            return dict(report=pointer['path'],sha256=pointer['sha256'],reused=True)
        source_path=Path(root)/'client-code-snapshots'/context['source_sha256']/'ProjectRED-Win64-Shipping.exe'
        source=source_path.read_bytes();require(hashlib.sha256(source).hexdigest()==context['source_sha256'],'source changed')
        binding=key_binding(context,exports,source)
        _,_,_,directory_proof=directory.directory(Path(selected['source']['path']))
        require(directory_proof==parent['proof'],'authenticated directory changed')
        values,skipped=catalog(bodies);code,metadata=render(context,selected,values)
        report=dict(schema=1,recipe=RECIPE,source_sha256=context['source_sha256'],definition=selected,
            native_execution=False,native_proofs_reused=True,network_used=False,runtime_admitted=False,
            labels_verified=True,dialogues_verified=False,outgoing_actions_admitted=False,key_binding=binding,
            tables=selected['tables'],names=len(values),skipped=skipped,metadata=metadata,
            output_sha256=hashlib.sha256(code.encode()).hexdigest(),limits=context['limits'])
        validate(report,selected)
        if write:TARGET.write_text(code,encoding='utf-8',newline='\n')
        else:require(TARGET.is_file() and digest(TARGET)==report['output_sha256'],'generate current catalog explicitly')
        owner.expect(TARGET,report['output_sha256']);owner.finish()
        path=load('audit-client-release').save_snapshot(Path(root)/'code-clues'/RECIPE,report)
        pointer=dict(path=str(path),sha256=digest(path));workflow.atomic(cache,workflow.canonical(pointer))
        return dict(report=str(path),sha256=pointer['sha256'],reused=False)
    except BaseException:
        if not owner.closed:owner.abort()
        raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true')
    args=parser.parse_args();print(json.dumps(verify(write=args.write)))
