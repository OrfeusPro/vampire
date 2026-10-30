"""Portable whole LoginResult handler with an explicit current-layout research rule.

Synthetic services and packets are separate from reader and live admission.
"""
import copy
import json
from pathlib import Path
from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
FAMILY = 'login-full-handler'
ADAPTER = 'login-full-v1'


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = module_from_spec(spec); spec.loader.exec_module(value); return value


core = load('portable-native-family')


def dependency(args, family, sha):
    modules = {'login-handler-early': 'update-native-login-handler', 'result-gate': 'update-native-response',
        'login-nested': 'update-native-login-input'}
    if family not in modules: raise ValueError('Unreviewed whole-handler dependency')
    tool = load(modules[family]).select(family); path, c = tool.at(args, sha)
    if not c.get('transfer_proof'): raise ValueError('Whole-handler dependency needs a target proof: ' + family)
    registry = load('native-release-registry').read(args.knowledge)
    tool.published_contexts(args.root, registry)
    data = json.loads((args.root / 'knowledge' / tool.index / 'index.json').read_text('utf-8'))
    rows = [r for r in data['contexts'] if r['context'] == core.pointer(path)]
    if len(rows) != 1: raise ValueError('Whole-handler dependency needs a published report: ' + family)
    return tool, path, c, rows[0]['check']


class Adapter(core.Family):
    family = FAMILY
    adapter = ADAPTER
    proofs = 'native-login-full-proofs'
    index = 'generated-login-full'
    scope = 'bounded_native_login_full_handler'
    verifier = 'verify-login-full-handler-context'
    layout = dict(abi='win64', executed_roots=2, packet_bytes=352, packet_id=4,
        native_gate=True, native_reader=False, real_services=False, session_executed=False)

    def roots(self, c): return load('login-full-handler-rules').roots(c)

    def tools(self):
        return {**load('login-full-handler-rules').tools(), **load('login-full-handler-case-contracts').tools(),
            **{str(HERE / n): core.digest(HERE / n) for n in ('portable-native-family.py', 'update-native-login-full.py')}}

    def export_parts(self, c): return [c]

    def export_coverage(self, root, c, native, bindings, image):
        return load('login-full-handler-rules').export_coverage(root, c, native, bindings, image)

    def dependencies(self, index, args, sha):
        result = {}
        for key, family in (('early', 'login-handler-early'), ('gate', 'result-gate'), ('packet', 'login-nested')):
            _, path, _, check = dependency(args, family, sha)
            result[key] = core.pointer(path); result[key + '_check'] = check
        return result

    def validate_report(self, r, c): load('login-full-handler-case-contracts').validate_report(r, c)

    def transfer(self, index, args, baseline, sha):
        self.roots(baseline)
        selected = [dependency(args, family, sha) for family in ('login-handler-early', 'result-gate', 'login-nested')]
        # These are independent scopes. Their reports are inputs, not permission
        # to infer successful Login or execute a reader in the handler suite.
        for tool, _, c, _ in selected: tool.validate(index, args, c)
        early, gate, packet = [row[2] for row in selected]
        native, bindings = load('build-native-entry-code'), load('update-bindings')
        before = args.source_store.image(native, baseline['source_sha256'])
        after = args.source_store.image(native, sha); mapping = {}
        previous_gate = None
        if baseline.get('format') == 'login-full-handler-v1':
            previous_gate = core.checked(args.root, baseline['gate_context'], 'generated-native-contexts')
            if previous_gate['source_sha256'] != baseline['source_sha256']:
                raise ValueError('Whole-handler baseline gate source differs')
        current, detail = load('login-full-handler-rules').transfer(
            native, bindings, before, after, baseline, mapping, early, gate, packet, baseline_gate=previous_gate)
        for key in ('exports', 'transfer_proof', 'family', 'layout', 'release_id'): current.pop(key, None)
        current.update(schema=1, family=self.family, format='login-full-handler-v1', packet_bytes=352,
            layout=copy.deepcopy(self.layout), source_sha256=sha,
            source=str(args.root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'),
            gate_context=core.pointer(selected[1][1]), verify_whole_exports=True)
        self.roots(current)
        return current, dict(details=detail, mapping={hex(a): hex(b) for a, b in sorted(mapping.items())})


def select(family=FAMILY):
    if family != FAMILY: raise ValueError('Unreviewed whole Login handler family')
    return Adapter()
