"""Retain generated SDK inputs around the unchanged source-check runner."""
import copy
import hashlib
import os
from pathlib import Path
import sys


CHECKS = {'sdk-profile-assembly-11316', 'gmc2-geo-native-11316', 'sdk-native-batch-11318'}
SOURCE_ENV = 'PHONEEXIT_VAMPIR_SDK_CHECK_SOURCE_SHA256'


def runtime_inputs(index, workflow, root, report, identifier):
    """Only the active Python executable can be an external generated input."""
    if identifier not in CHECKS:
        raise ValueError('SDK runtime input needs a registered SDK check')
    pointer = report['sdk_generation_guard']['generation']
    path = Path(pointer['path']).resolve()
    folder = (Path(root) / 'knowledge/sdk-batch-generated-v1').resolve()
    if (path.parent.parent != folder or path.name != 'manifest.json'
            or path.parent.name != pointer['sha256'] or index.digest(path) != pointer['sha256']):
        raise ValueError('SDK runtime generation pointer differs')
    generation = workflow.checked_manifest(index, path)
    executable = Path(sys.executable).resolve()
    definition = report['definition']
    if (generation.get('source_sha256') != definition.get('source_sha256')
            or Path(generation['runtime']['executable']).resolve() != executable
            or Path(definition['executable']).resolve() != executable):
        raise ValueError('SDK runtime Python identity differs')
    expected = generation['inputs'].get(str(executable))
    if expected is None or definition['artifacts'].get(str(executable)) != expected or index.digest(executable) != expected:
        raise ValueError('SDK runtime executable SHA differs')
    return {str(executable): expected}


def run(index, workflow, args, sha, definition):
    contexts = definition.get('generated_sdk_contexts', {})
    if definition['id'] not in CHECKS or workflow.source_scope(definition) != 'client' or sha not in contexts:
        raise ValueError('Generated SDK guard requires a declared source check')
    path = index.child(Path(args.knowledge), contexts[sha])
    effective = workflow.source_definition(definition, sha)
    if str(path.relative_to(index.HERE.parents[3].resolve())).replace('\\', '/') not in effective['dependencies']:
        raise ValueError('SDK runtime context is not a check dependency')
    context_sha = index.digest(path)
    context = index.read_json(path)
    if index.digest(path) != context_sha:
        raise ValueError('SDK runtime context changed while reading')
    if set(context) != {'schema', 'source_sha256', 'generation'} or context['schema'] != 1 or context['source_sha256'] != sha:
        raise ValueError('SDK runtime context source or schema differs')
    profile = index.extension('update-profile')
    files = profile.generated_dependencies(index, workflow, args, context['generation'], sha)
    pointer = context['generation']
    generation = workflow.checked_manifest(index, Path(pointer['path']))
    retained = {**generation['inputs'], **files, pointer['path']: pointer['sha256'], str(path): context_sha}
    # The unchanged runner inherits the explicit check source in its child.
    # Its SDK test refuses direct execution without that source binding.
    with index.extension('tooling-groups-v1')._owner(args.root / 'knowledge/sdk-source-check'):
        previous = os.environ.get(SOURCE_ENV)
        try:
            os.environ[SOURCE_ENV] = sha
            outcomes = workflow.run_checks(index, args, sha, None, check_ids=[definition['id']])
        finally:
            if previous is None:
                os.environ.pop(SOURCE_ENV, None)
            else:
                os.environ[SOURCE_ENV] = previous
    for filename, expected in retained.items():
        if index.digest(Path(filename)) != expected:
            raise ValueError('Generated SDK check input changed')
    results = []
    for outcome in outcomes:
        if 'report' not in outcome:
            results.append(outcome)
            continue
        original = workflow.checked_manifest(index, Path(outcome['report']))
        if index.digest(Path(outcome['report'])) != outcome['sha256']:
            raise ValueError('SDK parent check report changed')
        report = copy.deepcopy(original)
        artifacts = report['definition']['artifacts']
        if any(name in artifacts and artifacts[name] != expected for name, expected in retained.items()):
            raise ValueError('Generated SDK artifacts conflict with source check')
        artifacts.update(retained)
        report['sdk_generation_guard'] = dict(recipe='sdk-check-guard-v1', generation=pointer,
            parent=dict(path=outcome['report'], sha256=outcome['sha256']))
        saved = workflow.snapshot(args.root, 'check-results', report)
        results.append(dict(outcome, report=str(saved), sha256=index.digest(saved),
                            cache_key=hashlib.sha256(workflow.canonical(report['definition'])).hexdigest()))
    return results
