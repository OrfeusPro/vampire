"""Bounded service lifecycle adapter with one exact published backend parent."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
FAMILY = 'service-lifecycle'
ADAPTER = 'service-lifecycle-v1'
DEPENDENCIES = {'backend', 'backend_check'}


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = module_from_spec(spec); spec.loader.exec_module(value); return value


core = load('portable-native-family')


def dependency(args, sha):
    api = load('update-native-login-backend-wire').select('login-backend-wire')
    registry = load('native-release-registry').read(args.knowledge)
    found = [(path, c) for path, c, _ in api.published_contexts(args.root, registry) if c['source_sha256'] == sha]
    if len(found) != 1: raise ValueError('Lifecycle needs one proved backend publication')
    path, backend = found[0]
    if not backend.get('transfer_proof'): raise ValueError('Lifecycle requires a published backend proof')
    index = json.loads((args.root / 'knowledge' / api.index / 'index.json').read_text('utf-8'))
    selected = [row for row in index['contexts'] if row['context'] == core.pointer(path)]
    if len(selected) != 1: raise ValueError('Lifecycle needs exact published backend report')
    return api, path, backend, selected[0]['check']


def parent_dependencies(args, selected):
    api, path, backend, check = selected
    context_pointer = core.pointer(path)
    if backend.get('family') != 'login-backend-wire' or not backend.get('transfer_proof'):
        raise ValueError('Lifecycle requires proved typed backend parent')
    api.report_valid(core.checked(args.root, check, 'native-adapter-checks'), backend, context_pointer['sha256'])
    return dict(backend=context_pointer, backend_check=copy.deepcopy(check))


def validate_parents(index, args, selected, baseline):
    """Memoize only inside this SourceStore, with ordered parents and lineage."""
    api, _, backend, _ = selected
    dependencies = parent_dependencies(args, selected)
    base = core.checked(args.root, baseline['backend_context'], 'generated-native-contexts')
    report = core.checked(args.root, baseline['backend_check'], 'native-adapter-checks')
    if (base.get('family') != 'login-backend-wire' or not base.get('transfer_proof')
            or base.get('source_sha256') != baseline['source_sha256']):
        raise ValueError('Lifecycle baseline backend lineage differs')
    api.report_valid(report, base, baseline['backend_context']['sha256'])
    ordered = [dict(source=baseline['source_sha256'], backend=baseline['backend_context'],
                    backend_check=baseline['backend_check'], proof=baseline.get('transfer_proof')),
               dict(source=backend['source_sha256'], dependencies=dependencies)]

    def materials():
        values = {}
        for key, category in (('backend', 'generated-native-contexts'), ('backend_check', 'native-adapter-checks')):
            item = dependencies[key]; core.checked(args.root, item, category)
            values.update(core.lineage_inputs(args, item['path']))
        for key, category in (('backend_context', 'generated-native-contexts'), ('backend_check', 'native-adapter-checks')):
            item = baseline[key]; core.checked(args.root, item, category)
            values.update(core.lineage_inputs(args, item['path']))
        if baseline.get('transfer_proof'):
            item = baseline['transfer_proof']; core.checked(args.root, item, 'native-service-lifecycle-proofs')
            values.update(core.lineage_inputs(args, item['path']))
        return values

    inputs, tools = materials(), api.tools()
    key = json.dumps(dict(ordered_parents=ordered, tools=tools, materials=inputs),
                     sort_keys=True, separators=(',', ':'), allow_nan=False)
    store = args.source_store
    memo = getattr(store, '_service_lifecycle_parent_validations', None)
    if memo is None: memo = store._service_lifecycle_parent_validations = {}
    stats = getattr(store, '_service_lifecycle_parent_metrics', None)
    if stats is None: stats = store._service_lifecycle_parent_metrics = dict(validated=0, reused=0)
    if key in memo:
        stats['reused'] += 1
        return
    isolated = SimpleNamespace(root=args.root, knowledge=args.knowledge, source_store=store)
    api.validate(index, isolated, base)
    if baseline['backend_context'] != dependencies['backend']: api.validate(index, isolated, backend)
    if api.tools() != tools or materials() != inputs:
        raise ValueError('Lifecycle parent inputs changed during validation')
    memo[key] = True; stats['validated'] += 1


class Adapter(core.Family):
    family = FAMILY
    adapter = ADAPTER
    proofs = 'native-service-lifecycle-proofs'
    index = 'generated-service-lifecycle'
    scope = 'bounded_native_service_lifecycle'
    verifier = 'verify-service-lifecycle-context'
    layout = dict(abi='win64', executed_roots=12, leaves=1, tail_fragments=0,
        service_bytes=240, backend_bytes=800, control_bytes=24, callback_fixture_bytes=48,
        native_publisher=True, native_assignment=True, native_ref_control=True,
        native_backend_constructor=True, native_primary_destructors=True,
        native_base_reset=True, native_string_ring_clear=True,
        native_allocator=False, native_engine_containers=False, native_vector_storage=False,
        native_callback_lifetime=False, native_socket=False, concurrent_references=False,
        native_writer=False, native_sdk=False, session_executed=False)

    def contexts(self, args):
        rows = super().contexts(args)
        proved = {c['source_sha256'] for _, c, _ in rows if c.get('transfer_proof')}
        return [row for row in rows if row[1].get('transfer_proof') or row[1]['source_sha256'] not in proved]

    def baseline_context(self, args):
        rows = self.contexts(args); proved = [row for row in rows if row[1].get('transfer_proof')]
        if not rows: raise ValueError('No reviewed lifecycle baseline')
        return max(proved or rows, key=lambda row: (row[2], str(row[0])))[:2]

    def roots(self, c): return load('service-lifecycle-rules').roots(c)
    def export_parts(self, c): return [c]

    def export_coverage(self, root, c, native, bindings, image):
        return load('service-lifecycle-rules').export_coverage(root, c, native, bindings, image)

    def validate_report(self, report, context): load('service-lifecycle-case-contracts').validate_report(report, context)

    def tools(self):
        return {**load('update-native-login-backend-wire').select('login-backend-wire').tools(),
            **load('service-lifecycle-rules').tools(), **load('service-lifecycle-case-contracts').tools(),
            **{str(HERE / name): core.digest(HERE / name) for name in
               ('portable-native-family.py', 'update-native-service-lifecycle.py')}}

    def dependencies(self, index, args, sha): return parent_dependencies(args, dependency(args, sha))

    def transfer(self, index, args, baseline, sha):
        self.roots(baseline)
        selected = dependency(args, sha); validate_parents(index, args, selected, baseline)
        native, bindings = load('build-native-entry-code'), load('update-bindings')
        before = args.source_store.image(native, baseline['source_sha256'])
        after = args.source_store.image(native, sha)
        mapping = {}; _, path, backend, check = selected
        c, detail = load('service-lifecycle-rules').transfer(args.root, native, bindings, before, after,
            baseline, mapping, backend, backend_pointer=core.pointer(path), backend_check=check)
        c.update(layout=copy.deepcopy(self.layout), source=str(args.root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'))
        self.roots(c)
        return c, dict(details=detail, mapping={hex(a): hex(b) for a, b in sorted(mapping.items())})


def select(family=FAMILY):
    if family != FAMILY: raise ValueError('Unreviewed lifecycle family')
    return Adapter()
