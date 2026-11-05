"""Revalidate ready native proofs and finish projection barriers for a bounded candidate.

This publishes evidence scopes only. It never changes runtime admission or executes
native scenarios, Ghidra, networking, or a game action.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
RECIPE = 'candidate-proof-bridges-v1'
SCOPES = {
    'native-archive-wire-context': ('archive-wire',),
    'native-login-prepare-context': ('login-prepare', 'login-prepare-sdk', 'login-prepare-metadata'),
    'native-version-prepare-context': ('version-prepare', 'version-prepare-platform'),
    'native-version-result-context': ('version-result',),
    'native-login-result-context': ('login-state-flow',),
}
PROVIDERS = frozenset(family for names in SCOPES.values() for family in names) | {'string-writer'}


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def checked(root, pointer, category):
    if not isinstance(pointer, dict) or set(pointer) != {'path', 'sha256'}:
        raise ValueError('Candidate bridge requires an exact proof pointer')
    path = Path(pointer['path']).resolve()
    folder = (Path(root) / 'knowledge' / category).resolve()
    if (not path.is_relative_to(folder) or path.name != 'manifest.json'
            or path.parent.name != pointer['sha256'] or path.stat().st_size > 32 * 1024 * 1024):
        raise ValueError('Candidate bridge proof path or budget differs')
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != pointer['sha256']:
        raise ValueError('Candidate bridge proof SHA changed')
    return json.loads(payload)


def verify(context, root, knowledge=HERE / 'knowledge'):
    if (context.get('schema') != 1 or context.get('recipe') != RECIPE
            or set(context.get('native', {})) != PROVIDERS):
        raise ValueError('Candidate bridge recipe/provider set differs')
    sha = context['source_sha256']
    index = load('knowledge-index').api()
    args = SimpleNamespace(root=Path(root).resolve(), knowledge=Path(knowledge).resolve())
    args.source_store = index.extension('update-bindings').SourceStore(index, args.root, workers=2)
    driver = index.extension('update-native-drivers-v2')
    descriptors = {row['family']: row for row in driver.registry(index, args.knowledge)}
    publication = index.extension('native-publication-v3').begin(index, args, sha)
    declarations, outcomes, reports = {}, {}, {}
    for family in sorted(PROVIDERS):
        item = context['native'][family]
        if set(item) != {'context', 'check'}:
            raise ValueError('Candidate bridge provider declaration differs')
        current = checked(args.root, item['context'], 'generated-native-contexts')
        report = checked(args.root, item['check'], 'native-adapter-checks')
        if current.get('source_sha256') != sha or current.get('family') != family:
            raise ValueError('Candidate bridge provider source/family differs')
        descriptor = descriptors[family]
        tool = driver.tool(index, descriptor)
        artifacts = index.extension('portable-native-family').lineage_inputs(args, item['context']['path'])
        declaration = dict(driver.spec(descriptor), context=item['context'], proof=current['transfer_proof'],
            scope=report['scope'], dependencies=tool.tools(), artifacts=artifacts, contracts=[])
        outcome = dict(id=descriptor['id'], state='passed', report=item['check']['path'],
            sha256=item['check']['sha256'], scope=report['scope'], runtime_activated=False, profile_activated=False)
        # The reviewed publisher checks the exact selected publication, producer
        # closure, source bytes, runtime, transfer proof and complete case matrix.
        # publish() has no replay or collector path.
        publication.publish(driver.spec(descriptor), tool, declaration, outcome)
        declarations[family], outcomes[family], reports[family] = declaration, outcome, report

    projection = index.extension('contract-projections-v1').begin(index, args, sha)
    providers = projection.prepare(dict(checks=list(declarations.values())), list(outcomes.values()))
    if providers['state'] != 'ready':
        raise ValueError('Candidate bridge projection providers: ' + str(providers.get('reason')))
    contracts = index.extension('update-contracts').load(index, args.knowledge)['contracts']
    projected = []
    for name in ('game-version', 'game-login'):
        contract = next(row for row in contracts if row['id'] == name)
        view = projection.project(dict(schema=1, source_sha256=sha,
            source=str(args.root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'),
            contract=contract, bindings=dict(bindings={}), exports=[], dependencies={}))
        for adapter in ('version-login-tag', 'packet-writer-projection'):
            outcome = projection.check(view, adapter)
            projection.observe(view, adapter, outcome)
            if outcome['state'] != 'passed':
                raise ValueError('Candidate bridge projection rejected: ' + outcome.get('reason', ''))
            projected.append(dict(contract=name, **outcome))
    native_barrier = publication.finish()
    projection_barrier = projection.finish()
    if projection_barrier.get('owner_barrier_completed') is not True:
        raise ValueError('Candidate bridge projection owner barrier incomplete')

    scopes = {}
    for name, families in SCOPES.items():
        scopes[name] = dict(method='revalidated_native_proofs', providers=[
            dict(family=family, **context['native'][family], scope=reports[family]['scope'],
                 limits=reports[family]['limits']) for family in families])
    scopes['compiled-tag-native-11316'] = dict(method='static_inheritance', owner_barrier_completed=True,
        providers=[row for row in projected if row['id'] == 'version-login-tag'])
    scopes['version-login-context'] = dict(method='static_inheritance', owner_barrier_completed=True,
        providers=projected)
    # These names map the previous candidate's obligations. They do not issue
    # passed reports under old check IDs or permit a historical runtime profile.
    files = dict(publication.files)
    for inputs in (publication.mutable_files, projection.files):
        for name, expected in inputs.items():
            if expected is None or (name in files and files[name] != expected):
                raise ValueError('Candidate bridge evidence inputs conflict')
            files[name] = expected
    for source_sha in args.source_store._sources:
        files[str(args.root / 'client-code-snapshots' / source_sha / 'ProjectRED-Win64-Shipping.exe')] = source_sha
    return dict(schema=1, recipe=RECIPE, source_sha256=sha, scopes=scopes,
        producer=dict(path=str(Path(__file__).resolve()), sha256=index.digest(Path(__file__))),
        files=files, native_barrier=native_barrier, projection_barrier=projection_barrier,
        target_native_executions=0, new_jvm=0, network_used=False, profile_activated=False,
        runtime_admitted=False, legacy_check_reports_issued=False,
        limits=['Only the seven declared previous-candidate evidence scopes are revalidated.',
                'Projection cases are inherited statically with the completed owner barrier.',
                'Original native fixtures and callback preconditions are preserved.',
                'CharacterList, clock, current SDK runtime and the candidate admission are separate.',
                'No server acceptance, character creation, stats or indefinite-session admission.'])


def validate_saved(context, report):
    """Recheck all retained inputs without repeating the seven publication closures."""
    if (context.get('schema') != 1 or context.get('recipe') != RECIPE
            or set(context.get('native', {})) != PROVIDERS
            or report.get('recipe') != RECIPE or report.get('schema') != 1
            or report.get('source_sha256') != context.get('source_sha256')
            or set(report.get('scopes', {})) != set(SCOPES) | {'compiled-tag-native-11316', 'version-login-context'}
            or any(report.get(key) is not False for key in
                ('network_used', 'profile_activated', 'runtime_admitted', 'legacy_check_reports_issued'))
            or report.get('target_native_executions') != 0 or report.get('new_jvm') != 0):
        raise ValueError('Saved candidate bridge scope differs')
    path = Path(__file__).resolve()
    producer = dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    if report.get('producer') != producer:
        raise ValueError('Saved candidate bridge producer changed')
    for name, families in SCOPES.items():
        scope = report['scopes'][name]
        if (scope.get('method') != 'revalidated_native_proofs'
                or [row.get('family') for row in scope.get('providers', [])] != list(families)):
            raise ValueError('Saved candidate bridge provider coverage differs')
        for row in scope['providers']:
            if any(row.get(key) != context['native'][row['family']][key] for key in ('context', 'check')):
                raise ValueError('Saved candidate bridge provider pointer differs')
    barrier = report.get('projection_barrier', {})
    if barrier.get('owner_barrier_completed') is not True or barrier.get('source_sha256') != context['source_sha256']:
        raise ValueError('Saved candidate bridge owner barrier differs')
    files = report.get('files')
    if not isinstance(files, dict) or not 1 <= len(files) <= 4096:
        raise ValueError('Saved candidate bridge input count differs')
    for name, expected in files.items():
        with Path(name).open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != expected:
            raise ValueError('Saved candidate bridge input changed: ' + name)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    raw = args.context.read_bytes()
    report = verify(json.loads(raw), args.root)
    if args.context.read_bytes() != raw:
        raise ValueError('Candidate bridge context changed')
    report['context_sha256'] = hashlib.sha256(raw).hexdigest()
    path = load('research-workflow').snapshot(args.root, 'candidate-proof-bridges-v1', report)
    print(json.dumps(dict(report=str(path), scopes=len(report['scopes']), new_jvm=0, native_executions=0)))
