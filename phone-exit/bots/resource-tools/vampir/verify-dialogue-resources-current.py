"""Source-bound dialogue resources and native parameter selection, without gameplay."""
import argparse
from collections import defaultdict
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
ROOT=Path('F:/PhoneExit Resources/Vampir')
CONTEXT=HERE/'knowledge/native-contexts/dialogue-resources-current.json'
RECIPE='dialogue-resources-current-v1'
TABLES={
    'tasks':'ProjectRED/Content/RED/Data/CSV/QuestTask.csv',
    'lines':'ProjectRED/Content/RED/Data/CSV/Dialog.csv',
    'choices':'ProjectRED/Content/RED/Data/CSV/DialogChoice.csv',
    'lines_ru':'ProjectRED/Content/RED/Data/CSV/L10N/ru/Dialog_Name.csv',
    'choices_ru':'ProjectRED/Content/RED/Data/CSV/L10N/ru/DialogChoice_Name.csv',
}
SHA=re.compile('[a-f0-9]{64}')
LIMITS=[
    'Native execution selects a parameter group only; JSON values and class/actor providers are explicit fixtures.',
    'The parameter parser is not yet bound to the active quest task or dialogue player.',
    'Resource membership, field masks and skip flags are data; display order, playback, selection and skip effects are unverified.',
    'Class strings remain raw until the native scalar conversion is qualified; non-null shared controls are not executed.',
    'Current source/archive context only; automatic discovery of a later source context remains open.',
    'No received prompt, game command, live dialogue or runtime action admission is established.',
]


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def require(ok,why):
    if not ok:raise ValueError('Dialogue resources: '+why)


def numeric(value):
    require(type(value) is str and re.fullmatch(r'(?:0|[1-9][0-9]{0,19})',value)
        and int(value)<2**64,'invalid resource ID')
    return value


def flag(value):
    require(value in ('0','1',''),'invalid resource flag')
    return None if value=='' else value=='1'


def strict_object(pairs):
    result={}
    for key,value in pairs:
        require(key not in result,'duplicate JSON parameter key')
        result[key]=value
    return result


def rows(body):
    require(len(body)<=16*1024*1024,'table budget exceeded')
    value=list(csv.DictReader(io.StringIO(body.decode('utf-8-sig'))))
    require(value and len(value)<=20000,'row budget exceeded')
    return value


def graph(bodies):
    parsed={key:rows(body) for key,body in bodies.items()}
    needed=dict(tasks=('Id','QuestInfoId','Type','Param'),lines=('Id','GroupId','DialogChoiceGroupId',
        'UnableToSkip','UnableToSkipLine','IgnoreAutoSetting'),choices=('Id','GroupId','Order','DialogGroupId'),
        lines_ru=('Id','Name','Title','Text','Untranslated'),choices_ru=('Id','Text','Untranslated'))
    for key,columns in needed.items():require(set(columns)<=set(parsed[key][0]),'table schema differs: '+key)
    indexed={}
    for kind,values in parsed.items():
        index=defaultdict(list)
        for row in values:index[numeric(row['Id'])].append(row)
        indexed[kind]=index
    result=dict(schema=1,scope='resource_links_only',active=False,order_admitted=False,
        skip_behavior_verified=False,groups={},choice_groups={},tasks={},unresolved=[])
    def text(kind,key):
        found=indexed[kind].get(key,[])
        if len(found)!=1:
            return dict(status='ambiguous' if found else 'missing')
        row=found[0]
        require(all(len(row.get(k,''))<=16384 for k in ('Name','Title','Text')),'text budget exceeded')
        fields=row['Untranslated'].split('|') if row['Untranslated'] else []
        require(len(set(fields))==len(fields) and set(fields)<=set(row)&{'Name','Title','Text'},'invalid untranslated field mask')
        return dict(status='untranslated' if 'Text' in fields else 'text_present' if row['Text'] else 'empty',
            **{k:row[k] for k in ('Name','Title','Text') if k in row},untranslated_fields=sorted(fields))
    for kind in ('lines','choices','tasks'):
        for key,found in indexed[kind].items():
            if len(found)!=1:
                result['unresolved'].append(dict(kind=kind,id=key,reason='ambiguous_primary_id'));continue
            row=found[0]
            if kind=='lines':
                group=numeric(row['GroupId'])
                link=dict(id=key,text=text('lines_ru',key),choice_group_id=numeric(row['DialogChoiceGroupId']),
                    unable_to_skip=flag(row['UnableToSkip']),unable_to_skip_line=flag(row['UnableToSkipLine']),
                    ignore_auto_setting=flag(row['IgnoreAutoSetting']))
                result['groups'].setdefault(group,[]).append(link)
            elif kind=='choices':
                group=numeric(row['GroupId'])
                link=dict(id=key,text=text('choices_ru',key),order=numeric(row['Order']),next_group_id=numeric(row['DialogGroupId']))
                result['choice_groups'].setdefault(group,[]).append(link)
            else:
                if row['Type']!='6':continue
                try:param=json.loads(row['Param'],object_pairs_hook=strict_object)
                except (ValueError,TypeError):
                    result['unresolved'].append(dict(kind=kind,id=key,reason='unparsed_script_parameter'));continue
                if type(param) is not dict or param.get('type')!='Dialog':continue
                groups=[]
                direct=param.get('dialogGroupId')
                # Record candidates, not the active class or task. Never use CSV order as progress.
                if type(direct) is int and 0<=direct<2**64:
                    groups.append(dict(group_id=str(direct),class_id=None,route='direct'))
                elif direct is not None:
                    result['unresolved'].append(dict(kind=kind,id=key,reason='invalid_direct_group'));continue
                elif 'classBranch' in param:
                    branch=param['classBranch']
                    if type(branch) is not list or len(branch)>64:
                        result['unresolved'].append(dict(kind=kind,id=key,reason='invalid_class_branches'));continue
                    scalar_unknown=False
                    for position,value in enumerate(branch):
                        if (type(value) is not dict or type(value.get('dialogGroupId')) is not int
                                or type(value.get('classInfoId')) not in (int,str) or not 0<=value['dialogGroupId']<2**64):
                            result['unresolved'].append(dict(kind=kind,id=key,reason='invalid_class_branch',position=position));continue
                        class_raw=value['classInfoId']
                        if type(class_raw) is int:
                            require(0<=class_raw<2**32,'class ID exceeds bounds')
                        else:
                            require(len(class_raw)<=32,'class scalar exceeds bounds')
                            scalar_unknown=True
                        groups.append(dict(group_id=str(value['dialogGroupId']),class_id_raw=class_raw,
                            class_scalar_conversion_verified=False,route='class_branch',position=position))
                    if scalar_unknown:result['unresolved'].append(dict(kind=kind,id=key,reason='class_scalar_conversion_not_verified'))
                result['tasks'][key]=dict(quest_id=numeric(row['QuestInfoId']),candidates=groups,active=False)
    # Sorted membership is deterministic storage only, not a proved display/execution order.
    for values in (result['groups'],result['choice_groups']):
        for group,items in values.items():items.sort(key=lambda row:int(row['id']))
    for task,value in result['tasks'].items():
        for candidate in value['candidates']:
            if candidate['group_id'] not in result['groups']:
                result['unresolved'].append(dict(kind='task_group',id=task,reason='missing_group',group_id=candidate['group_id']))
    for group,values in result['choice_groups'].items():
        for value in values:
            if value['next_group_id'] not in result['groups']:
                reason='zero_target_semantics_unknown' if value['next_group_id']=='0' else 'missing_group'
                result['unresolved'].append(dict(kind='choice_target',id=value['id'],reason=reason,group_id=value['next_group_id']))
    for group,values in result['groups'].items():
        for value in values:
            if value['choice_group_id']!='0' and value['choice_group_id'] not in result['choice_groups']:
                result['unresolved'].append(dict(kind='line_choice',id=value['id'],reason='missing_choice_group',choice_group_id=value['choice_group_id']))
    return result


def validate(report,definition):
    require(report.get('schema')==1 and report.get('recipe')==RECIPE and report.get('definition')==definition
        and report.get('source_sha256')==definition['source_sha256'] and report.get('runtime_admitted') is False
        and report.get('active_task_verified') is False and report.get('skip_behavior_verified') is False
        and report.get('network_used') is False and report.get('received_prompts_verified') is False
        and report.get('limits')==LIMITS and report.get('native_execution') is True,
        'cached proof scope differs')
    load('dialogue-parameter-cases-v1').validate(report.get('native_parameter',{}))


def checked_receipt(labels,owner,pointer,recipe):
    path=Path(pointer['path']).resolve()
    require(path==owner.root/'code-clues'/recipe/pointer['sha256']/'manifest.json','receipt location differs')
    return labels.checked(owner,pointer)


def verify(*,root=ROOT,context_path=CONTEXT):
    labels=load('verify-quest-labels-current')
    owner,directory,label_context,parent,_,_,label_definition=labels.inputs(root,labels.CONTEXT)
    index=owner.index
    try:
        context_raw=Path(context_path).read_bytes();owner.remember(context_path,context_raw)
        context=json.loads(context_raw)
        require(context.get('schema')==1 and context.get('recipe')==RECIPE
            and context.get('source_sha256')==label_definition['source_sha256']
            and context.get('tables')==TABLES,'context/source differs')
        export=labels.checked(owner,context['export'])
        require(export.get('new_source_sha256')==context['source_sha256'],'export source differs')
        named=index.extension('resource-named-tables-v1').Scope(index,owner.args)
        baseline=named.read(label_context['named_baseline'])
        tables={}
        for role,path in TABLES.items():
            found=[t for t in parent['csv_bindings'] if t.get('canonical_path')==path]
            require(len(found)==1 and found[0].get('directory_identity_verified') is True,'table identity differs')
            value={k:found[0][k] for k in ('canonical_path','sha256','file','bytes','header','rows')}
            references=[t for t in baseline['tables'] if t.get('canonical_path')==path]
            require(value['sha256']==context['table_sha256'][role] and len(references)==1
                and references[0].get('state')=='verified_payload'
                and all(references[0].get(k)==v for k,v in value.items()),'table payload changed')
            require(Path(value['file']).resolve().is_relative_to(owner.root),'table outside library')
            owner.expect(value['file'],value['sha256']);tables[role]=value
        source_path=owner.root/'client-code-snapshots'/context['source_sha256']/'ProjectRED-Win64-Shipping.exe'
        owner.expect(source_path,context['source_sha256'])
        for file in (Path(__file__),HERE/'dialogue-parameter-cases-v1.py',HERE/'quest-tutorial-state-harness-v1.py',
                HERE/'update-bindings.py',HERE/'login-input-transfer-rules.py',HERE/'build-native-entry-code.py',
                HERE/'extract-native-enums.py',HERE/'audit-client-release.py',HERE/'research-workflow.py'):
            owner.digest(file.resolve())
        definition=dict(source_sha256=context['source_sha256'],inputs={str(p):sha for p,sha in owner.files.items()},
            source=parent['inputs']['source'],runtime_inputs=label_definition['runtime_inputs'],
            tables=tables,context_sha256=hashlib.sha256(context_raw).hexdigest())
        workflow=index.extension('research-workflow');key=hashlib.sha256(workflow.canonical(definition)).hexdigest()
        cache=Path(root)/'knowledge'/(RECIPE+'-cache')/(key+'.json')
        if cache.is_file():
            pointer=json.loads(cache.read_bytes());report=checked_receipt(labels,owner,pointer,RECIPE);validate(report,definition)
            parameter=checked_receipt(labels,owner,report['native_parameter_proof'],'dialogue-parameter-native-v1')
            require(parameter.get('schema')==1 and parameter.get('recipe')=='dialogue-parameter-native-v1'
                and parameter.get('result')==report['native_parameter']
                and parameter['inputs']['source_sha256']==context['source_sha256']
                and parameter['inputs']['export']==context['export']
                and parameter['inputs']['context']=={k:context[k] for k in ('parser','literal_roles','literals','native')}
                and parameter['inputs']['runtime_inputs']==definition['runtime_inputs']
                and all(definition['inputs'].get(k)==v for k,v in parameter['inputs']['files'].items()),'native child proof differs')
            graph_pointer=report['graph'];path=Path(graph_pointer['path']).resolve()
            require(path.is_relative_to(Path(root).resolve()/'code-clues/dialogue-resource-graphs-v1')
                and path.name=='manifest.json' and path.parent.name==graph_pointer['sha256'],'graph location differs')
            with path.open('rb') as stream:raw=stream.read(32*1024*1024+1)
            require(len(raw)<=32*1024*1024 and hashlib.sha256(raw).hexdigest()==graph_pointer['sha256'],'cached graph changed')
            owner.remember(graph_pointer['path'],raw);owner.finish()
            return dict(report=pointer['path'],sha256=pointer['sha256'],reused=True)
        value=graph({role:named.payload(table) for role,table in tables.items()})
        source=source_path.read_bytes();require(hashlib.sha256(source).hexdigest()==context['source_sha256'],'source changed')
        native=index.extension('build-native-entry-code');image=native.Image(source)
        require({f['address'] for f in export['functions']}==set(context['roots']),'selected roots differ')
        for function in export['functions']:
            actual=index.extension('update-bindings').rows(native,image,int(function['address'],16))
            require(function.get('decompilation_completed') is True and function.get('block_coverage_complete') is True
                and function.get('direct_flow_coverage_complete') is True
                and [(int(r['address'],16),r['bytes'].lower()) for r in function['instructions']]
                    ==[(r['address'],r['bytes'].lower()) for r in actual],'whole export bytes differ')
        parameter,parameter_proof,parameter_cache=load('dialogue-parameter-cases-v1').cached_execute(
            index,owner,Path(root).resolve(),context,export,source,definition['runtime_inputs'])
        graph_path=index.extension('audit-client-release').save_snapshot(Path(root)/'code-clues/dialogue-resource-graphs-v1',value)
        graph_pointer=dict(path=str(graph_path),sha256=labels.digest(graph_path));owner.expect(graph_path,graph_pointer['sha256'])
        report=dict(schema=1,recipe=RECIPE,source_sha256=context['source_sha256'],definition=definition,
            graph=graph_pointer,native_parameter=parameter,native_parameter_proof=parameter_proof,
            native_execution=True,whole_exports_verified=len(export['functions']),
            counts=dict(dialogue_groups=len(value['groups']),choice_groups=len(value['choice_groups']),
                scripted_dialogue_tasks=len(value['tasks']),lines=sum(map(len,value['groups'].values())),
                choices=sum(map(len,value['choice_groups'].values())),unresolved=len(value['unresolved'])),
            runtime_admitted=False,active_task_verified=False,skip_behavior_verified=False,
            received_prompts_verified=False,network_used=False,limits=LIMITS)
        validate(report,definition);owner.finish()
        if parameter_cache is not None:
            workflow.atomic(Path(parameter_cache['path']),workflow.canonical(parameter_cache['pointer']))
        path=index.extension('audit-client-release').save_snapshot(Path(root)/'code-clues'/RECIPE,report)
        pointer=dict(path=str(path),sha256=labels.digest(path));workflow.atomic(cache,workflow.canonical(pointer))
        return dict(report=str(path),sha256=pointer['sha256'],reused=False)
    except BaseException:
        owner.abort();raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT)
    args=parser.parse_args();print(json.dumps(verify(root=args.root),ensure_ascii=False))
