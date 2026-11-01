"""Automatic bounded buffer/queue proof with exact published wire lineage."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
FAMILY = 'buffer-transport'
ADAPTER = 'buffer-transport-v1'
DEPENDENCIES = {'wire', 'wire_check'}


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec); spec.loader.exec_module(module); return module


core = load('portable-native-family')


def dependency(args, sha):
    """Select only a publication; an unproved reference never competes here."""
    api = load('update-native-archive-wire')
    registry = load('native-release-registry').read(args.knowledge)
    found = [(path, c) for path, c, _ in api.published_contexts(args.root, registry)
             if c['source_sha256'] == sha]
    if len(found) != 1: raise ValueError('Buffer transport needs one proved wire publication')
    path, wire = found[0]
    if not wire.get('transfer_proof'): raise ValueError('Buffer transport requires a published wire proof')
    value = json.loads((args.root / 'knowledge' / api.INDEX / 'index.json').read_text('utf-8'))
    selected = [row for row in value['contexts'] if row['context'] == core.pointer(path)]
    if len(selected) != 1: raise ValueError('Buffer transport needs the exact published wire report')
    return api, path, wire, selected[0]['check']


def parent_dependencies(args, selected):
    api, path, wire, check = selected
    context_pointer = core.pointer(path)
    report = core.checked(args.root, check, 'native-adapter-checks')
    if wire.get('family') != 'archive-wire' or not wire.get('transfer_proof'):
        raise ValueError('Buffer transport requires a proved typed wire parent')
    api.report_valid(report, wire, context_pointer['sha256'])
    return dict(wire=context_pointer, wire_check=copy.deepcopy(check))


def validate_parents(index, args, selected, baseline):
    """Validate the ordered parent pair once per SourceStore and exact inputs."""
    api, _, wire, _ = selected
    dependencies = parent_dependencies(args, selected)
    base_wire = core.checked(args.root, baseline['wire_context'], 'generated-native-contexts')
    base_check = core.checked(args.root, baseline['wire_check'], 'native-adapter-checks')
    if (base_wire.get('family') != 'archive-wire' or not base_wire.get('transfer_proof')
            or base_wire.get('source_sha256') != baseline['source_sha256']):
        raise ValueError('Buffer transport baseline wire lineage differs')
    api.report_valid(base_check, base_wire, baseline['wire_context']['sha256'])
    ordered = [dict(source=baseline['source_sha256'], wire=baseline['wire_context'],
                    wire_check=baseline['wire_check'], proof=baseline.get('transfer_proof')),
               dict(source=wire['source_sha256'], dependencies=dependencies)]

    def materials():
        values = {}
        for key, category in (('wire', 'generated-native-contexts'), ('wire_check', 'native-adapter-checks')):
            item = dependencies[key]
            core.checked(args.root, item, category)
            values.update(core.lineage_inputs(args, item['path']))
        for key, category in (('wire_context', 'generated-native-contexts'), ('wire_check', 'native-adapter-checks')):
            item = baseline[key]
            core.checked(args.root, item, category)
            values.update(core.lineage_inputs(args, item['path']))
        if baseline.get('transfer_proof'):
            item = baseline['transfer_proof']
            core.checked(args.root, item, 'native-buffer-transport-proofs')
            values.update(core.lineage_inputs(args, item['path']))
        return values

    inputs, tools = materials(), api.tools()
    key = json.dumps(dict(ordered_parents=ordered, tools=tools, materials=inputs),
                     sort_keys=True, separators=(',', ':'), allow_nan=False)
    store = args.source_store
    memo = getattr(store, '_buffer_transport_parent_validations', None)
    if memo is None: memo = store._buffer_transport_parent_validations = {}
    stats = getattr(store, '_buffer_transport_parent_metrics', None)
    if stats is None: stats = store._buffer_transport_parent_metrics = dict(validated=0, reused=0)
    if key in memo:
        stats['reused'] += 1
        return
    isolated = SimpleNamespace(root=args.root, knowledge=args.knowledge, source_store=store)
    api.validate(index, isolated, base_wire)
    if baseline['wire_context'] != dependencies['wire']:
        api.validate(index, isolated, wire)
    if api.tools() != tools or materials() != inputs:
        raise ValueError('Buffer transport parent inputs changed during validation')
    memo[key] = True
    stats['validated'] += 1


class Adapter(core.Family):
    family = FAMILY
    adapter = ADAPTER
    proofs = 'native-buffer-transport-proofs'
    index = 'generated-buffer-transport'
    scope = 'bounded_native_buffer_transport'
    verifier = 'verify-buffer-transport-context'
    layout = dict(abi='win64', executed_roots=5, leaves=1, tail_fragments=0,
        vector_bytes=24, queue_bytes=32, archive_bytes=64, transport_bytes=400,
        native_resize=True, native_growth=True, native_queue_append=True, native_transport=True,
        native_archive_raw=True, native_set_count=True, native_allocator=False, native_socket=False,
        native_drain=False, native_backend_lifetime=False, native_writer=False,
        native_checksum=False, native_transform=False, session_executed=False)

    def contexts(self, args):
        rows = super().contexts(args)
        proved = {c['source_sha256'] for _, c, _ in rows if c.get('transfer_proof')}
        return [row for row in rows if row[1].get('transfer_proof') or row[1]['source_sha256'] not in proved]

    def baseline_context(self, args):
        rows = self.contexts(args); proved = [row for row in rows if row[1].get('transfer_proof')]
        if not rows: raise ValueError('No reviewed buffer transport baseline')
        return max(proved or rows, key=lambda row: (row[2], str(row[0])))[:2]

    def roots(self, c): return load('buffer-transport-rules').roots(c)
    def export_parts(self, c): return [c]

    def export_coverage(self, root, c, native, bindings, image):
        return load('buffer-transport-rules').export_coverage(root, c, native, bindings, image)

    def validate_report(self, report, context):
        load('buffer-transport-case-contracts').validate_report(report, context)

    def tools(self):
        return {**load('update-native-archive-wire').tools(), **load('buffer-transport-rules').tools(),
            **load('buffer-transport-case-contracts').tools(),
            **{str(HERE / name): core.digest(HERE / name) for name in
               ('portable-native-family.py', 'update-native-buffer-transport.py')}}

    def dependencies(self, index, args, sha): return parent_dependencies(args, dependency(args, sha))

    def transfer(self, index, args, baseline, sha):
        self.roots(baseline)
        selected = dependency(args, sha)
        validate_parents(index, args, selected, baseline)
        native, bindings = load('build-native-entry-code'), load('update-bindings')
        before = args.source_store.image(native, baseline['source_sha256'])
        after = args.source_store.image(native, sha)
        mapping = {}
        _, path, wire, check = selected
        context, detail = load('buffer-transport-rules').transfer(
            args.root, native, bindings, before, after, baseline, mapping, wire,
            wire_pointer=core.pointer(path), wire_check=check)
        context.update(layout=copy.deepcopy(self.layout),
            source=str(args.root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'))
        self.roots(context)
        return context, dict(details=detail, mapping={hex(a): hex(b) for a, b in sorted(mapping.items())})


def select(family=FAMILY):
    if family != FAMILY: raise ValueError('Unreviewed buffer transport family')
    return Adapter()
