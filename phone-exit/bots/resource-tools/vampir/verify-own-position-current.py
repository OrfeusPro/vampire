"""Cache the exact current actor height correction with explicit surface fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/own-position-current.json'
RECIPE = 'own-position-current-v1'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
REPLAY = 'replay-own-position-current-v1'
TOOLS = (
    'verify-own-position-current', REPLAY, 'verify-quest-loader-current',
    'native-request-harness-11316', 'build-native-entry-code', 'build-object-zero-init-code',
    'extract-native-enums', 'update-bindings', 'research-workflow', 'knowledge-index',
    'audit-client-release', 'native-publication-v2',
)
LIMITS = [
    'The whole actor position corrector executes with explicit predicate, navigation and collision providers.',
    'The exact current world dispatch, receiver, spawn and packet producers are retained as static source boundaries.',
    'Capsule dimensions, scale, surface selection and writable globals are fixture inputs with separate provenance.',
    'The actual current own actor transform, active collision resources and first live 1810 remain open.',
]
FALSE_FIELDS = ('network_used', 'runtime_admitted', 'actor_vector_verified', 'live_step_verified')


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(ok, why):
    if not ok:
        raise ValueError('Own position proof: ' + why)


def definition(index, root, context_path):
    common = load('verify-quest-loader-current')
    context_path = Path(context_path).resolve()
    raw = common.read_bounded(context_path, 128 * 1024)
    context = json.loads(raw)
    require(context.get('schema') == 1 and context.get('recipe') == RECIPE
            and context.get('source_sha256') == SOURCE, 'context identity differs')
    roles = context.get('roles', {})
    sources = context.get('source_roles', {})
    require(set(roles) == {'corrector'} and set(sources) == {
        'world_dispatch', 'world_receiver', 'spawn', 'retain_z_predicate',
        'navigation', 'collision', 'quest_producer', 'move_producer'}, 'source role scope differs')
    require(all(re.fullmatch('0x[0-9a-f]+', address) for address in (*roles.values(), *sources.values()))
            and len(set(roles.values()) | set(sources.values())) == 9, 'source roles overlap')
    source = root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe'
    files = {str(source): SOURCE, str(context_path): hashlib.sha256(raw).hexdigest()}
    files.update({str(HERE / (name + '.py')): common.digest(HERE / (name + '.py')) for name in TOOLS})
    exports = {}
    require(bool(context.get('exports')), 'whole exports missing')
    for run, sha in context['exports'].items():
        require(re.fullmatch('run-[0-9a-f]+', run) and re.fullmatch('[a-f0-9]{64}', sha),
                'export pointer differs')
        exports[str(root / 'ghidra/request-exports' / SOURCE / run / 'details.json')] = sha
    files.update(exports)
    runtime = {str(path): common.digest(path)
               for path in index.extension('native-publication-v2').runtime_files()}
    require(bool(runtime), 'runtime identity missing')
    files.update(runtime)
    return context, dict(source_sha256=SOURCE, inputs=files, runtime_inputs=runtime, exports=exports)


def validate(report, selected, context):
    require(report.get('schema') == 1 and report.get('recipe') == RECIPE
            and report.get('source_sha256') == SOURCE and report.get('definition') == selected
            and report.get('native_execution') is True and report.get('limits') == LIMITS
            and all(report.get(key) is False for key in FALSE_FIELDS), 'receipt scope differs')
    load(REPLAY).validate(report['result'], context)


def verify(*, root=ROOT, context_path=CONTEXT):
    index = load('knowledge-index').api()
    common = load('verify-quest-loader-current')
    workflow = index.extension('research-workflow')
    root = Path(root).resolve()
    context, selected = definition(index, root, context_path)
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    common.barrier(selected['inputs'])
    if cache.is_file():
        pointer = json.loads(common.read_bounded(cache, 8192))
        report = common.document(pointer, root, 'code-clues/' + RECIPE, budget=2 * 1024 * 1024)
        validate(report, selected, context)
        common.barrier(selected['inputs'])
        return dict(pointer, report=pointer['path'], reused=True)
    result = load(REPLAY).run(index, root, context)
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=selected,
                  result=result, limits=LIMITS, native_execution=True,
                  **{field: False for field in FALSE_FIELDS})
    validate(report, selected, context)
    common.barrier(selected['inputs'])
    path = index.extension('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    pointer = dict(path=str(path), sha256=common.digest(path))
    workflow.atomic(cache, workflow.canonical(pointer))
    return dict(pointer, report=str(path), reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(root=args.root)))
