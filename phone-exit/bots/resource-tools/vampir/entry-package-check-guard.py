"""Bind bounded entry package receipts and all their inputs to update checks."""
import copy
import hashlib
from pathlib import Path
import sys

RECIPE = 'entry-package-check-guard-v1'

PACKAGES = {
    'lobby-login-prepare-current': 'verify-lobby-login-prepare-current',
    'create-result-current': 'verify-create-result-current',
    'lobby-sender-current': 'verify-lobby-sender-current',
    'viper-cold-cdo-current': 'verify-viper-cold-cdo-current',
    'lobby-results-current': 'verify-lobby-results-current',
    'create-handler-current': 'verify-create-handler-current',
    'viper-appearance-current': 'build-viper-appearance-current',
    'bounded-entry-current': 'build-bounded-entry-current',
    'create-producer-current': 'verify-create-producer-current',
    'viper-creation-current': 'build-viper-creation-current',
    'bounded-creation-current': 'build-bounded-creation-current',
}
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'


def material(index, root, sha, identifier):
    if sha != SOURCE:
        raise ValueError('Entry package source differs')
    verifier = index.extension(PACKAGES[identifier])
    if identifier in ('bounded-entry-current', 'bounded-creation-current'):
        result = verifier.publish(root=root)
        path = Path(result['report']).resolve()
        profile = index.read_json(path)
        category = 'bounded-entry-profiles' if identifier == 'bounded-entry-current' else 'bounded-creation-profiles'
        operations = ['cdn', 'lobby', 'character-list'] if identifier == 'bounded-entry-current' else ['character-create']
        if (path != Path(root).resolve() / category / result['sha256'] / 'manifest.json'
                or index.digest(path) != result['sha256'] or profile['source_sha256'] != sha
                or profile.get('world_admitted') is not False
                or profile.get('creation_admitted') is not (identifier == 'bounded-creation-current')
                or profile.get('operations') != operations):
            raise ValueError('Bounded entry profile source or operation scope differs')
        # Large base PAK is streamed by the profile verifier. The scoped
        # per-file receipt budget retains its expected SHA through the manifest.
        inputs = {name: sha for name, sha in profile['inputs'].items() if Path(name).suffix.lower() != '.pak'}
        return {**inputs, str(path): result['sha256']}, dict(path=str(path), sha256=result['sha256'])
    result = verifier.verify(root=root)
    path = Path(result['report']).resolve()
    expected = result['sha256']
    if (path != Path(root).resolve() / 'code-clues' / verifier.RECIPE / expected / 'manifest.json'
            or index.digest(path) != expected):
        raise ValueError('Entry package receipt path or hash differs')
    report = index.read_json(path)
    derived = identifier in ('lobby-results-current', 'viper-appearance-current', 'create-producer-current', 'viper-creation-current')
    if (report.get('recipe') != verifier.RECIPE or report.get('source_sha256') != sha
            or report.get('native_execution') is not (not derived)
            or (derived and report.get('native_proofs_reused') is not True)
            or report.get('network_used') is not False
            or report.get('runtime_admitted') is not False):
        raise ValueError('Entry package receipt boundary differs')
    inputs = report['definition']['inputs']
    if (not inputs or any(not Path(name).is_absolute() or index.digest(name) != digest
                          for name, digest in inputs.items())):
        raise ValueError('Entry package retained input changed')
    return {**inputs, str(path): expected}, dict(path=str(path), sha256=expected)


def runtime_inputs(index, root, report, identifier):
    definition = report['definition']
    if identifier not in PACKAGES or definition['check']['id'] != identifier:
        raise ValueError('Entry package runtime check identity differs')
    retained, pointer = material(index, root, definition['source_sha256'], identifier)
    if pointer != report['entry_package_guard']['pointer']:
        raise ValueError('Entry package runtime proof selection changed')
    if any(definition['artifacts'].get(name) != expected for name, expected in retained.items()):
        raise ValueError('Entry package runtime check lost retained inputs')
    python = Path(sys.executable).resolve()
    runtime = {python, python.with_name('python3.dll'),
               python.with_name(f'python{sys.version_info.major}{sys.version_info.minor}.dll'),
               Path(index.INSTALL).resolve(),
               Path(index.INSTALL).resolve().parents[2] /
               'Saved/PersistentDownloadDir/Patch/windows.manifestlist'}
    if identifier in ('viper-appearance-current', 'create-producer-current', 'viper-creation-current'):
        for number in ('1', '100') if identifier == 'viper-creation-current' else ('100',):
            runtime.add(Path(index.INSTALL).resolve().parents[2] /
                        ('Saved/PersistentDownloadDir/Patch/Install/pakchunk' + number + '-Windows.pak'))
    runtime.update(path.resolve() for path in index.extension('native-publication-v2').runtime_files())
    return {name: expected for name, expected in retained.items() if Path(name).resolve() in runtime}


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
        guarded['entry_package_guard'] = dict(recipe=RECIPE, pointer=pointer)
        path = workflow.snapshot(args.root, 'check-results', guarded)
        results.append(dict(outcome, report=str(path), sha256=index.digest(path),
            cache_key=hashlib.sha256(workflow.canonical(guarded['definition'])).hexdigest()))
    return results
