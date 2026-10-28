"""Extensible native families without invalidating the frozen UTF-8 proof engine."""
from pathlib import Path

SPECS=(dict(id='native-auto-string-writer',family='string-writer',adapter='string-writer-v1'),
       dict(id='native-auto-archive-wire',family='archive-wire',adapter='archive-wire-v1'),
       dict(id='native-auto-version-result',family='version-result',adapter='version-result-v1'),
       dict(id='native-auto-version-prepare',family='version-prepare',adapter='version-prepare-v1'))
MODULES={'string-writer-v1':'update-native-string-writer','archive-wire-v1':'update-native-archive-wire',
         'version-result-v1':'update-native-version-result','version-prepare-v1':'update-native-version-prepare'}


def registry(index,knowledge):
    path=Path(knowledge)/'native-check-adapters.json'
    if not path.is_file():return []
    value=index.read_json(path)
    selected=value.get('adapters')
    if (value.get('schema')!=1 or not isinstance(selected,list) or not selected
            or any(spec not in SPECS for spec in selected)
            or len({spec['id'] for spec in selected})!=len(selected)
            or selected!=[spec for spec in SPECS if spec in selected]):
        raise ValueError('Unreviewed native adapter driver registry')
    return selected


def run(index,args,sha,journal,database,*,families=None):
    selection=set(families) if families is not None else None
    registered=registry(index,args.knowledge)
    if selection is not None and (not selection or selection-{spec['family'] for spec in registered}):
        raise ValueError('Selected native family is not registered')
    declarations=[];checks=[];queue=[];families=[]
    for spec in registered:
        if selection is not None and spec['family'] not in selection:continue
        family=spec['family'];families.append(family)
        tool=index.extension(MODULES[spec['adapter']])
        try:
            inputs=tool.plan_inputs(index,args,sha)
            def plan_writer():
                try:return tool.discover(index,args,sha)
                except (ValueError,OSError,KeyError,StopIteration) as error:
                    return dict(state='requires_review',reason=str(error))
            plan=journal.stage('native-plan-'+family,inputs,plan_writer)
            if plan['state']!='planned':raise ValueError(plan['reason'])
            contexts=dict(source_sha256=sha,contracts={spec['id']:dict(bindings={str(i):at for i,at in enumerate(plan['exports'])})})
            # Reuse the normal missing-only collector, serial batches <=32 and
            # the same journal. No nested research lock or private Ghidra path.
            exports=index.extension('update-run').collect_batches(index,index.extension('research-workflow'),
                journal,args,database,contexts,sha)
            def materialize():
                try:return tool.materialize(index,args,sha,plan,database)
                except ValueError as error:
                    return dict(checks=[],queue=[dict(family=family,reason='native_adapter_requires_review',details=str(error))])
            material=journal.stage('native-context-'+family,dict(source=sha,plan=plan,exports=exports,tools=tool.tools()),materialize)
            declarations.extend(material['checks']);queue.extend(material['queue'])
            for declaration in material['checks']:
                def execute():
                    try:return tool.execute(index,args,sha,declaration)
                    except ValueError as error:
                        return dict(id=declaration['id'],state='requires_review',reason=str(error))
                result=journal.stage('native-check-'+declaration['id'],dict(source=sha,declaration=declaration,
                    suite_runtime=index.extension('update-native-harness').runtime_inputs()),
                    execute)
                if result['state']=='passed':tool.publish(index,args,sha,declaration,result)
                checks.append(result)
        except (ValueError,OSError,KeyError,StopIteration) as error:
            queue.append(dict(family=family,reason='native_adapter_requires_review',details=str(error)))
    return dict(declarations=declarations,checks=checks,queue=queue,families=families)


def merge(native,checks,extra):
    """Replace only the covered family's unsupported marker; retain all other gaps."""
    covered=set(extra['families']);queue=[]
    for item in native['queue']:
        item=dict(item)
        if item.get('family') in covered:continue
        if item.get('reason')=='unregistered_native_suite_families':
            item['families']=[name for name in item['families'] if name not in covered]
            if not item['families']:continue
        queue.append(item)
    native['queue']=queue+extra['queue']
    native['checks'].extend(extra['declarations']);checks.extend(extra['checks'])
    for row in native.get('family_coverage',[]):
        if row['family'] in covered:
            row.update(adapter=next(spec['adapter'] for spec in SPECS if spec['family']==row['family']),reason='')
