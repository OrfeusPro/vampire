"""Retain every first-SDK source proof on cold and cached update checks."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import sys

IDS={'first-sdk-auth-current','first-sdk-terms-current','sdk-first-profile-runtime'}


def load(path):
    spec=importlib.util.spec_from_file_location('first_sdk_check_guard_dependency',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def retained(index,root,knowledge,definition,sha):
    workspace=index.HERE.parents[3].resolve()
    selector=index.child(knowledge,definition['sdk_first_profile_contexts'][sha])
    effective=index.extension('research-workflow').source_definition(definition,sha)
    if selector.relative_to(workspace).as_posix() not in effective['dependencies']:
        raise ValueError('First SDK selector is not a check dependency')
    raw=selector.read_bytes();value=index.read_json(selector)
    if value.get('schema')!=1 or value.get('source_sha256')!=sha:
        raise ValueError('First SDK selector source differs')
    identifier=definition['id']
    if identifier in ('first-sdk-auth-current','first-sdk-terms-current'):
        role='auth' if identifier=='first-sdk-auth-current' else 'terms'
        pointer=value['contracts'][role];path=Path(pointer['path']).resolve()
        if index.digest(path)!=pointer['sha256']:raise ValueError('First SDK source proof pointer changed')
        api=load(index.HERE/('inspect-first-sdk-'+role+'-current.py'))
        report=api.verify_report(path,root=root,workspace=workspace)
    elif identifier=='sdk-first-profile-runtime':
        pointer=value['profile'];path=Path(root)/'sdk-first-profiles'/pointer['sha256']/'manifest.json'
        if Path(pointer['path']).resolve()!=path.resolve():raise ValueError('First SDK profile path differs')
        import importlib
        sys.path.insert(0,str(workspace/'phone-exit/bots/vampir-shared'))
        api=importlib.import_module('vampir_core.sdk_first_profile_admission')
        if Path(api.__file__).resolve()!=workspace/'phone-exit/bots/vampir-shared/vampir_core/sdk_first_profile_admission.py':
            raise ValueError('First SDK runtime loader import origin differs')
        report=api.load_manifest(pointer['sha256'],root=root,workspace=workspace,installed=index.INSTALL)
    else:raise ValueError('First SDK guard requires an explicit source check')
    if report['source_sha256']!=sha or selector.read_bytes()!=raw:
        raise ValueError('First SDK source or selector changed during validation')
    material=dict(report['inputs']);material[str(path.resolve())]=pointer['sha256']
    material[str(selector.resolve())]=hashlib.sha256(raw).hexdigest()
    return material,pointer


def runtime_inputs(index,root,report,identifier):
    definition=report['definition']['check']
    if identifier!=definition['id'] or identifier not in IDS:raise ValueError('First SDK check identity differs')
    material,pointer=retained(index,root,index.KNOWLEDGE,definition,report['definition']['source_sha256'])
    if pointer!=report['sdk_first_profile_guard']['pointer']:raise ValueError('First SDK proof pointer changed')
    if any(report['definition']['artifacts'].get(k)!=v for k,v in material.items()):
        raise ValueError('First SDK check lost a retained input')
    external={str(Path(sys.executable).resolve()),str(Path(index.INSTALL).resolve())}
    return {k:v for k,v in material.items() if k in external}


def run(index,workflow,args,sha,definition):
    if definition['id'] not in IDS or workflow.source_scope(definition)!='client':
        raise ValueError('First SDK requires a source-bound check')
    material,pointer=retained(index,args.root,args.knowledge,definition,sha)
    outcomes=workflow.run_checks(index,args,sha,None,check_ids=[definition['id']])
    fresh,second=retained(index,args.root,args.knowledge,definition,sha)
    if material!=fresh or pointer!=second:raise ValueError('First SDK inputs changed during check')
    results=[]
    for outcome in outcomes:
        if 'report' not in outcome:results.append(outcome);continue
        report=copy.deepcopy(workflow.checked_manifest(index,Path(outcome['report'])))
        if index.digest(outcome['report'])!=outcome['sha256']:raise ValueError('First SDK parent check changed')
        artifacts=report['definition']['artifacts']
        if any(k in artifacts and artifacts[k]!=v for k,v in material.items()):
            raise ValueError('First SDK retained artifacts conflict')
        artifacts.update(material)
        report['sdk_first_profile_guard']=dict(recipe='sdk-first-profile-check-guard-v1',pointer=pointer)
        saved=workflow.snapshot(args.root,'check-results',report)
        results.append(dict(outcome,report=str(saved),sha256=index.digest(saved),
            cache_key=hashlib.sha256(workflow.canonical(report['definition'])).hexdigest()))
    return results
