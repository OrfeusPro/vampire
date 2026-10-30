"""Separate portable result-gate and post-state scopes; no full login admission."""
from pathlib import Path
from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
FAMILIES = ('result-gate', 'login-post-state')
ADAPTER = 'response-v1'


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = module_from_spec(spec); spec.loader.exec_module(value); return value


core = load('portable-native-family')


class Adapter(core.Family):
    def __init__(self, family):
        if family not in FAMILIES: raise ValueError('Unreviewed response family')
        self.family = family; self.adapter = ADAPTER
        self.proofs = 'native-response-proofs'; self.index = 'generated-responses/' + family
        self.scope = 'bounded_native_' + family.replace('-', '_')
        gate = family == FAMILIES[0]
        self.layout = (dict(abi='win64', executed_roots=1, code_instructions=251, code_bytes=1047,
            inline_padding_bytes=1, rva_entries=4, index_bytes=227, full_handler=False)
            if gate else dict(abi='win64', executed_roots=2, returning_leaves=1,
            service_bytes=768, actor_bytes=832, class_bytes=64, full_handler=False))
        self.rule = 'result-gate-transfer-rules' if gate else 'post-state-transfer-rules'
        self.contract = 'result-gate-case-contracts' if gate else 'post-state-case-contracts'
        self.verifier = 'verify-result-gate-context' if gate else 'verify-post-state-context'

    def roots(self, c): return load(self.rule).roots(c)

    def tools(self):
        return {**load(self.rule).tools(), **load(self.contract).tools(),
            **{str(HERE / n): core.digest(HERE / n) for n in ('portable-native-family.py', 'update-native-response.py')}}

    def export_parts(self, c): return [c]

    def export_coverage(self, root, c, native, bindings, image):
        if self.family == FAMILIES[0]: return load(self.rule).export_coverage(root, c, native, bindings, image)
        return super().export_coverage(root, c, native, bindings, image)

    def dependencies(self, index, args, sha): return {}

    def validate_report(self, r, c): load(self.contract).validate_report(r, c)

    def transfer(self, index, args, baseline, sha):
        self.roots(baseline)
        native, bindings = load('build-native-entry-code'), load('update-bindings')
        before = args.source_store.image(native, baseline['source_sha256'])
        after = args.source_store.image(native, sha); mapping = {}
        current, detail = load(self.rule).transfer(native, bindings, before, after, baseline, mapping)
        for key in ('exports', 'transfer_proof', 'family', 'layout', 'release_id'): current.pop(key, None)
        current.update(schema=1, family=self.family, layout=self.layout, source_sha256=sha,
            source=str(args.root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'), verify_whole_exports=True)
        self.roots(current)
        return current, dict(details=detail, mapping={hex(a): hex(b) for a, b in sorted(mapping.items())})


def select(family): return Adapter(family)
