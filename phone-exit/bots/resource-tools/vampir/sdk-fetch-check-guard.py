"""Recheck Fetch proof/profile retained inputs on every source-check cache hit."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import sys

IDS = {'sdk-fetch-current-contract', 'sdk-fetch-read-runtime'}


def load(path):
    spec = importlib.util.spec_from_file_location('fetch_check_input_guard', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def retained(index, root, knowledge, definition, sha):
    workspace = index.HERE.parents[3].resolve()
    selector = index.child(knowledge, definition['sdk_fetch_contexts'][sha])
    effective = index.extension('research-workflow').source_definition(definition, sha)
    if selector.relative_to(workspace).as_posix() not in effective['dependencies']:
        raise ValueError('Fetch selector is not a check dependency')
    raw = selector.read_bytes()
    value = index.read_json(selector)
    if value.get('schema') != 1 or value.get('source_sha256') != sha:
        raise ValueError('Fetch check selector source differs')
    if definition['id'] == 'sdk-fetch-current-contract':
        api = load(index.HERE / 'inspect-sdk-fetch-current.py')
        pointer = value['contract']
        path = Path(pointer['path'])
        if index.digest(path) != pointer['sha256']:
            raise ValueError('Fetch contract selector changed')
        report = api.verify_report(path, root=root, workspace=workspace)
        material = dict(report['inputs'])
    elif definition['id'] == 'sdk-fetch-read-runtime':
        api = load(workspace / 'phone-exit/bots/vampir-shared/vampir_core/sdk_fetch_admission.py')
        pointer = value['profile']
        path = Path(root) / 'sdk-fetch-profiles' / pointer['sha256'] / 'manifest.json'
        if Path(pointer['path']).resolve() != path.resolve():
            raise ValueError('Fetch profile selector path differs')
        report = api.load_manifest(pointer['sha256'], root=root, workspace=workspace, installed=index.INSTALL)
        material = dict(report['inputs'])
    else:
        raise ValueError('Fetch guard requires an explicit source check')
    if report['source_sha256'] != sha or selector.read_bytes() != raw:
        raise ValueError('Fetch guard changed source or selector')
    material[str(path.resolve())] = pointer['sha256']
    material[str(selector.resolve())] = hashlib.sha256(raw).hexdigest()
    return material, pointer


def runtime_inputs(index, root, report, identifier):
    definition = report['definition']['check']
    if identifier != definition['id'] or identifier not in IDS:
        raise ValueError('Fetch guard check identity differs')
    sha = report['definition']['source_sha256']
    material, pointer = retained(index, root, index.KNOWLEDGE, definition, sha)
    if pointer != report['sdk_fetch_guard']['pointer']:
        raise ValueError('Fetch proof pointer changed')
    if any(report['definition']['artifacts'].get(name) != expected for name, expected in material.items()):
        raise ValueError('Fetch check lost a retained input')
    allowed = {str(Path(sys.executable).resolve()), str(Path(index.INSTALL).resolve())}
    return {name: digest for name, digest in material.items() if name in allowed}


def run(index, workflow, args, sha, definition):
    if definition['id'] not in IDS or workflow.source_scope(definition) != 'client':
        raise ValueError('Fetch requires a source-bound check')
    material, pointer = retained(index, args.root, args.knowledge, definition, sha)
    outcomes = workflow.run_checks(index, args, sha, None, check_ids=[definition['id']])
    fresh, second = retained(index, args.root, args.knowledge, definition, sha)
    if material != fresh or pointer != second:
        raise ValueError('Fetch inputs changed during check')
    results = []
    for outcome in outcomes:
        if 'report' not in outcome:
            results.append(outcome)
            continue
        report = copy.deepcopy(workflow.checked_manifest(index, Path(outcome['report'])))
        if index.digest(outcome['report']) != outcome['sha256']:
            raise ValueError('Fetch parent check changed')
        artifacts = report['definition']['artifacts']
        if any(k in artifacts and artifacts[k] != v for k, v in material.items()):
            raise ValueError('Fetch artifacts conflict')
        artifacts.update(material)
        report['sdk_fetch_guard'] = dict(recipe='sdk-fetch-check-guard-v1', pointer=pointer)
        saved = workflow.snapshot(args.root, 'check-results', report)
        results.append(dict(outcome, report=str(saved), sha256=index.digest(saved),
            cache_key=hashlib.sha256(workflow.canonical(report['definition'])).hexdigest()))
    return results
