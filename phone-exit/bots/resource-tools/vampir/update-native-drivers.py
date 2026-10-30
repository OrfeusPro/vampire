"""Extensible native families without invalidating the frozen UTF-8 proof engine."""
from pathlib import Path

SPECS=(dict(id='native-auto-string-writer',family='string-writer',adapter='string-writer-v1'),
       dict(id='native-auto-archive-wire',family='archive-wire',adapter='archive-wire-v1'),
       dict(id='native-auto-version-result',family='version-result',adapter='version-result-v1'),
       dict(id='native-auto-version-prepare',family='version-prepare',adapter='version-prepare-v1'),
       dict(id='native-auto-login-prepare',family='login-prepare',adapter='login-prepare-v1'),
       dict(id='native-auto-login-sdk',family='login-prepare-sdk',adapter='login-sdk-v1'),
       *[dict(id='native-auto-'+family,family=family,adapter='version-helper-v1') for family in
         ('version-nm-device','version-cpu','version-windows','version-combiner','version-platform',
          'version-prepare-nm','version-prepare-system','version-prepare-combiner','version-prepare-platform')],
       *[dict(id='native-auto-'+family,family=family,adapter='login-metadata-v1') for family in
         ('login-metadata','login-prepare-metadata')],
       *[dict(id='native-auto-'+family,family=family,adapter='login-input-v1') for family in
         ('login-nested','login-strings-buffer')],
       *[dict(id='native-auto-'+family,family=family,adapter='login-handler-v1') for family in
         ('login-continuation','login-handler-early')],
       *[dict(id='native-auto-'+family,family=family,adapter='response-v1') for family in
         ('result-gate','login-post-state')],
       dict(id='native-auto-login-full-handler',family='login-full-handler',adapter='login-full-v1'))
MODULES={'string-writer-v1':'update-native-string-writer','archive-wire-v1':'update-native-archive-wire',
         'version-result-v1':'update-native-version-result','version-prepare-v1':'update-native-version-prepare',
         'login-prepare-v1':'update-native-login-prepare','login-sdk-v1':'update-native-login-sdk',
         'version-helper-v1':'update-native-version-helpers','login-metadata-v1':'update-native-login-metadata',
         'login-input-v1':'update-native-login-input','login-handler-v1':'update-native-login-handler',
         'response-v1':'update-native-response','login-full-v1':'update-native-login-full'}


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
    publication=index.extension('native-publication-cache').begin(index,args,sha)
    declarations=[];checks=[];queue=[];families=[]
    for spec in registered:
        if selection is not None and spec['family'] not in selection:continue
        family=spec['family'];families.append(family)
        tool=index.extension(MODULES[spec['adapter']])
        if spec['adapter'] in ('version-helper-v1','login-metadata-v1','login-input-v1','login-handler-v1','response-v1','login-full-v1'):tool=tool.select(family)
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
                if result['state']=='passed':publication.publish(spec,tool,declaration,result)
                checks.append(result)
        except (ValueError,OSError,KeyError,StopIteration) as error:
            queue.append(dict(family=family,reason='native_adapter_requires_review',details=str(error)))
    # Cached native reports still require exact publication membership, complete
    # evidence/tool lineage and a final full-source integrity barrier.
    metrics=publication.finish()
    return dict(declarations=declarations,checks=checks,queue=queue,families=families,publication_cache=metrics)


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
    if 'publication_cache' in extra:native['publication_cache']=extra['publication_cache']
    native['checks'].extend(extra['declarations']);checks.extend(extra['checks'])
    for row in native.get('family_coverage',[]):
        if row['family'] in covered:
            row.update(adapter=next(spec['adapter'] for spec in SPECS if spec['family']==row['family']),reason='')
