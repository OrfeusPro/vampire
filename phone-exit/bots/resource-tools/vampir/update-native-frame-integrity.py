"""Automatic source-bound CRC/XOR and direct backend/writer evidence."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
FAMILY = 'frame-integrity'
ADAPTER = 'frame-integrity-v1'
DEPENDENCIES = {'backend', 'backend_check', 'wire', 'wire_check', 'prepare_check'}


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


core = load('portable-native-family')


def dependency(args, sha):
    """Choose only the backend publication; its proof chooses all other parents."""
    api = load('update-native-login-backend-wire').select('login-backend-wire')
    registry = load('native-release-registry').read(args.knowledge)
    found = [(path, c) for path, c, _ in api.published_contexts(args.root, registry)
             if c['source_sha256'] == sha]
    if len(found) != 1:
        raise ValueError('Frame integrity needs one proved backend publication')
    path, context = found[0]
    if not context.get('transfer_proof'):
        raise ValueError('Frame integrity requires a published backend proof')
    value = json.loads((args.root / 'knowledge' / api.index / 'index.json').read_text('utf-8'))
    selected = [row for row in value['contexts'] if row['context'] == core.pointer(path)]
    if len(selected) != 1:
        raise ValueError('Frame integrity needs the exact published backend report')
    return api, path, context, selected[0]['check']


def parent_dependencies(args, selected):
    """Resolve five exact links without independently selecting wire or prepare."""
    _, path, backend, backend_check = selected
    context_pointer = core.pointer(path)
    proof = core.checked(args.root, backend['transfer_proof'], 'native-login-backend-wire-proofs')
    inherited = proof['dependencies']
    if (inherited['wire'] != backend['wire_context']
            or proof.get('target', {}).get('source_sha256') != backend['source_sha256']):
        raise ValueError('Frame integrity backend wire/proof lineage differs')
    result = dict(backend=context_pointer, backend_check=copy.deepcopy(backend_check),
        wire=copy.deepcopy(inherited['wire']), wire_check=copy.deepcopy(inherited['wire_check']),
        prepare_check=copy.deepcopy(inherited['prepare_check']))
    wire = core.checked(args.root, result['wire'], 'generated-native-contexts')
    backend_report = core.checked(args.root, result['backend_check'], 'native-adapter-checks')
    wire_report = core.checked(args.root, result['wire_check'], 'native-adapter-checks')
    prepared = core.checked(args.root, result['prepare_check'], 'native-adapter-checks')
    if (any(item.get('source_sha256') != backend['source_sha256']
            for item in (wire, backend_report, wire_report, prepared))
            or backend_report.get('context_sha256') != context_pointer['sha256']
            or backend_report.get('proof') != backend['transfer_proof']
            or wire_report.get('context_sha256') != result['wire']['sha256']
            or wire_report.get('proof') != wire.get('transfer_proof')
            or not wire.get('transfer_proof')):
        raise ValueError('Frame integrity accepted parent report binding differs')
    return result


def validate_parents(index, args, selected, baseline):
    """Memoize a checked ordered parent pair only inside this SourceStore."""
    api, _, backend, _ = selected
    dependencies = parent_dependencies(args, selected)
    ordered = [dict(source=baseline['source_sha256'],
                    backend=baseline['backend_context'], wire=baseline['wire_context'],
                    proof=baseline.get('transfer_proof')),
               dict(source=backend['source_sha256'], dependencies=dependencies)]

    def materials():
        values = {}
        for item in dependencies.values():
            values.update(core.lineage_inputs(args, item['path']))
        for key in ('backend_context', 'wire_context'):
            item = baseline[key]
            core.checked(args.root, item, 'generated-native-contexts')
            values.update(core.lineage_inputs(args, item['path']))
        if baseline.get('transfer_proof'):
            item = baseline['transfer_proof']
            core.checked(args.root, item, 'native-frame-integrity-proofs')
            values.update(core.lineage_inputs(args, item['path']))
        return values

    inputs, tools = materials(), api.tools()
    key = json.dumps(dict(ordered_parents=ordered, tools=tools, materials=inputs),
                     sort_keys=True, separators=(',', ':'), allow_nan=False)
    store = args.source_store
    memo = getattr(store, '_frame_integrity_parent_validations', None)
    if memo is None:
        memo = store._frame_integrity_parent_validations = {}
    stats = getattr(store, '_frame_integrity_parent_metrics', None)
    if stats is None:
        stats = store._frame_integrity_parent_metrics = dict(validated=0, reused=0)
    if key in memo:
        stats['reused'] += 1
        return
    isolated = SimpleNamespace(root=args.root, knowledge=args.knowledge, source_store=store)
    api.validate(index, isolated, backend)
    if api.tools() != tools or materials() != inputs:
        raise ValueError('Frame integrity parent inputs changed during validation')
    memo[key] = True
    stats['validated'] += 1


class Adapter(core.Family):
    family = FAMILY
    adapter = ADAPTER
    proofs = 'native-frame-integrity-proofs'
    index = 'generated-frame-integrity'
    scope = 'bounded_native_frame_integrity'
    verifier = 'verify-frame-integrity-context'
    layout = dict(abi='win64', executed_roots=16, leaves=9, tail_fragments=2,
        packet_bytes=320, backend_bytes=784, archive_bytes=64,
        native_backend=True, native_writer=True, native_wire=True, native_append=True,
        native_archive_cleanup=True, native_checksum=True, native_transform=True,
        ambient_packet_provider=True, ambient_backend_provider=True,
        native_prepare=False, native_sdk=False, native_metadata=False, native_sender=False,
        native_publisher=False, native_service_getter=False, native_service_thunk=False,
        native_backend_assignment=False, native_transport=False, native_pending_insert=False,
        native_delegate=False, real_services=False, session_executed=False)

    def contexts(self, args):
        rows = super().contexts(args)
        proved = {c['source_sha256'] for _, c, _ in rows if c.get('transfer_proof')}
        return [row for row in rows if row[1].get('transfer_proof')
                or row[1]['source_sha256'] not in proved]

    def baseline_context(self, args):
        rows = self.contexts(args)
        proved = [row for row in rows if row[1].get('transfer_proof')]
        if not rows:
            raise ValueError('No reviewed frame integrity baseline')
        return max(proved or rows, key=lambda row: (row[2], str(row[0])))[:2]

    def roots(self, c):
        return load('frame-integrity-rules').roots(c)

    def export_parts(self, c):
        return [c]

    def export_coverage(self, root, c, native, bindings, image):
        return load('frame-integrity-rules').export_coverage(root, c, native, bindings, image)

    def validate_report(self, report, context):
        root = Path(context['source']).parents[2]
        _, prepared, backend = load('verify-frame-integrity-context').dependencies(context, root, core)
        load('frame-integrity-case-contracts').validate_report(report, context, prepared, backend)

    def tools(self):
        return {**load('update-native-login-backend-wire').select('login-backend-wire').tools(),
            **load('frame-integrity-rules').tools(),
            **load('frame-integrity-case-contracts').tools(),
            **{str(HERE / name): core.digest(HERE / name) for name in
               ('portable-native-family.py', 'update-native-frame-integrity.py')}}

    def dependencies(self, index, args, sha):
        return parent_dependencies(args, dependency(args, sha))

    def transfer(self, index, args, baseline, sha):
        self.roots(baseline)
        selected = dependency(args, sha)
        validate_parents(index, args, selected, baseline)
        native, bindings = load('build-native-entry-code'), load('update-bindings')
        before = args.source_store.image(native, baseline['source_sha256'])
        after = args.source_store.image(native, sha)
        mapping = {}
        _, path, backend, _ = selected
        context, detail = load('frame-integrity-rules').transfer(
            args.root, native, bindings, before, after, baseline, mapping, backend,
            core.checked(args.root, backend['wire_context'], 'generated-native-contexts'),
            backend_pointer=core.pointer(path), wire_pointer=backend['wire_context'])
        context.update(layout=copy.deepcopy(self.layout),
            source=str(args.root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'))
        self.roots(context)
        return context, dict(details=detail,
            mapping={hex(a): hex(b) for a, b in sorted(mapping.items())})


def select(family=FAMILY):
    if family != FAMILY:
        raise ValueError('Unreviewed frame integrity family')
    return Adapter()
