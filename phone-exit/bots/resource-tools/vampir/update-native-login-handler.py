"""Explicit portable continuation and pre-gate LoginResult handler scopes."""
from pathlib import Path
from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
FAMILIES = ('login-continuation', 'login-handler-early')
ADAPTER = 'login-handler-v1'


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = module_from_spec(spec); spec.loader.exec_module(value); return value


core = load('portable-native-family')


class Adapter(core.Family):
    def __init__(self, family):
        if family not in FAMILIES: raise ValueError('Unreviewed Login handler family')
        self.family = family; self.adapter = ADAPTER; self.proofs = 'native-login-handler-proofs'
        self.scope = 'bounded_native_' + family.replace('-', '_')
        self.index = 'generated-login-handlers/' + family
        continuation = family == FAMILIES[0]
        self.layout = dict(abi='win64', executed_roots=2 if continuation else 1,
            object_bytes=1024 if continuation else None, packet_bytes=None if continuation else 352,
            gate_executed=False, successful_login_executed=False, real_services=False)
        self.verifier = load('login-handler-case-contracts').verifier(family)

    def roots(self, c): return load('login-handler-transfer-rules').roots(self.family, c)

    def tools(self):
        return {**load('login-handler-transfer-rules').tools(), **load('login-handler-case-contracts').tools(),
            **{str(HERE / n): core.digest(HERE / n) for n in ('portable-native-family.py', 'update-native-login-handler.py')}}

    def export_parts(self, c): return [c]

    def dependencies(self, index, args, sha): return {}

    def validate_report(self, r, c): load('login-handler-case-contracts').validate_report(self.family, r, c)

    def transfer(self, index, args, baseline, sha):
        self.roots(baseline)
        native, bindings = load('build-native-entry-code'), load('update-bindings')
        before = args.source_store.image(native, baseline['source_sha256'])
        after = args.source_store.image(native, sha); mapping = {}
        current, detail = load('login-handler-transfer-rules').transfer(
            self.family, native, bindings, before, after, baseline, mapping)
        for key in ('exports', 'transfer_proof', 'family', 'layout', 'release_id'): current.pop(key, None)
        current.update(schema=1, family=self.family, layout=self.layout, source_sha256=sha,
            source=str(args.root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'), verify_whole_exports=True)
        self.roots(current)
        return current, dict(details=detail, mapping={hex(a): hex(b) for a, b in sorted(mapping.items())})


def select(family): return Adapter(family)
