"""Bind bounded entry package receipts and all their inputs to update checks."""
import copy
import hashlib
from pathlib import Path

PACKAGES = {
    'lobby-login-prepare-current': 'verify-lobby-login-prepare-current',
    'create-result-current': 'verify-create-result-current',
    'lobby-sender-current': 'verify-lobby-sender-current',
    'viper-cold-cdo-current': 'verify-viper-cold-cdo-current',
}
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'


def material(index, root, sha, identifier):
    if sha != SOURCE:
        raise ValueError('Entry package source differs')
    verifier = index.extension(PACKAGES[identifier])
    result = verifier.verify(root=root)
    path = Path(result['report']).resolve()
    expected = result['sha256']
    if (path != Path(root).resolve() / 'code-clues' / verifier.RECIPE / expected / 'manifest.json'
            or index.digest(path) != expected):
        raise ValueError('Entry package receipt path or hash differs')
    report = index.read_json(path)
    if (report.get('recipe') != verifier.RECIPE or report.get('source_sha256') != sha
            or report.get('native_execution') is not True or report.get('network_used') is not False
            or report.get('runtime_admitted') is not False):
        raise ValueError('Entry package receipt boundary differs')
    inputs = report['definition']['inputs']
    if (not inputs or any(not Path(name).is_absolute() or index.digest(name) != digest
                          for name, digest in inputs.items())):
        raise ValueError('Entry package retained input changed')
    return {**inputs, str(path): expected}, dict(path=str(path), sha256=expected)


def run(index, workflow, args, sha, definition):
    identifier = definition['id']
    if identifier not in PACKAGES or workflow.source_scope(definition) != 'client':
        raise ValueError('Entry package requires a registered client check')
    material_before, pointer = material(index, args.root, sha, identifier)
    outcomes = workflow.run_checks(index, args, sha, None, check_ids=[identifier])
    if any(index.digest(name) != expected for name, expected in material_before.items()):
        raise ValueError('Entry package changed during update check')
    results = []
    for outcome in outcomes:
        if outcome['state'] != 'passed':
            results.append(outcome)
            continue
        parent = Path(outcome['report'])
        if index.digest(parent) != outcome['sha256']:
            raise ValueError('Entry package parent check changed')
        guarded = copy.deepcopy(workflow.checked_manifest(index, parent))
        artifacts = guarded['definition']['artifacts']
        if any(name in artifacts and artifacts[name] != expected for name, expected in material_before.items()):
            raise ValueError('Entry package parent artifacts conflict')
        artifacts.update(material_before)
        guarded['entry_package'] = pointer
        path = workflow.snapshot(args.root, 'check-results', guarded)
        results.append(dict(outcome, report=str(path), sha256=index.digest(path),
            cache_key=hashlib.sha256(workflow.canonical(guarded['definition'])).hexdigest()))
    return results
