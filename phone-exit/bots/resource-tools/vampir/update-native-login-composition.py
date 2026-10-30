"""Portable same-packet LoginResult reader/handler composition, separate from dispatch."""
import copy
import json
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
FAMILY = 'login-response-composition'
ADAPTER = 'login-composition-v1'


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = module_from_spec(spec); spec.loader.exec_module(value); return value


core = load('portable-native-family')
CHILDREN = {'reader': ('update-native-login-input', 'login-strings-buffer'),
            'handler': ('update-native-login-full', 'login-full-handler')}


def dependency(args, role, sha):
    if role not in CHILDREN: raise ValueError('Unreviewed Login composition dependency')
    name, family = CHILDREN[role]; tool = load(name).select(family)
    path, c = tool.at(args, sha)
    if not c.get('transfer_proof'): raise ValueError('Composition dependency needs a target proof')
    tool.published_contexts(args.root, load('native-release-registry').read(args.knowledge))
    data = json.loads((args.root / 'knowledge' / tool.index / 'index.json').read_text('utf-8'))
    rows = [row for row in data['contexts'] if row['context'] == core.pointer(path)]
    if len(rows) != 1: raise ValueError('Composition dependency needs a published semantic report')
    return tool, path, c, rows[0]['check']


class Adapter(core.Family):
    family = FAMILY
    adapter = ADAPTER
    proofs = 'native-login-composition-proofs'
    index = 'generated-login-composition'
    scope = 'bounded_native_login_same_packet_composition'
    verifier = 'verify-login-composition-context'
    layout = dict(abi='win64', executed_roots=22, packet_bytes=352, native_reader=True,
        native_handler=True, native_gate=True, native_dispatch=False, native_post_state=False,
        native_continuation=False, real_services=False, session_executed=False)

    def baseline_context(self, args):
        found = self.contexts(args)
        if not found: raise ValueError('No reviewed Login composition baseline')
        # The initial same-source projection has no composition report. Once
        # published, the proved role always replaces that bootstrap input.
        proved = [row for row in found if row[1].get('transfer_proof')]
        return max(proved or found, key=lambda row: (row[2], str(row[0])))[:2]

    def roots(self, c): return load('login-composition-rules').roots(c)

    def tools(self):
        children = {path: sha for name, family in CHILDREN.values() for path, sha in load(name).select(family).tools().items()}
        return {**children, **load('login-composition-rules').tools(), **load('login-composition-case-contracts').tools(),
            **{str(HERE / n): core.digest(HERE / n) for n in ('portable-native-family.py', 'update-native-login-composition.py')}}

    def dependencies(self, index, args, sha):
        result = {}
        for role in CHILDREN:
            _, path, _, check = dependency(args, role, sha)
            result[role] = core.pointer(path); result[role + '_check'] = check
        return result

    def export_parts(self, c): return [c]

    def export_coverage(self, root, c, native, bindings, image):
        return load('login-composition-rules').export_coverage(root, c, native, bindings, image)

    def validate_report(self, r, c): load('login-composition-case-contracts').validate_report(r, c)

    def transfer(self, index, args, baseline, sha):
        self.roots(baseline)
        old = {role: core.checked(args.root, baseline[role + '_context'], 'generated-native-contexts') for role in CHILDREN}
        selected = {role: dependency(args, role, sha) for role in CHILDREN}
        relations = {}; mapping = {}; link = load('update-native-archive-wire').add_link
        for role, (tool, path, target, check) in selected.items():
            if old[role]['source_sha256'] != baseline['source_sha256']:
                raise ValueError('Composition baseline child source differs')
            # Existing child semantic reports stay independent. They admit the
            # static inputs; only this family's new report proves composition.
            tool.validate(index, args, target)
            target_pointer = core.pointer(path)
            if target_pointer == baseline[role + '_context']:
                # No relocation occurs when the immutable child is identical.
                # The published report and full proof validation above are
                # still mandatory; a matching address alone cannot enter here.
                relations[role] = dict(method='reuse_identical_checked_context',
                    context=target_pointer, semantic_check=check, mapping={})
                continue
            else:
                tool.validate(index, args, old[role])
            # Frozen input recipes memoize a union of transitive files, which
            # can be equal for different ordered source pairs. A fresh local
            # mapping memo prevents borrowing another pair's relocation while
            # preserving the frozen SourceStore and all published/native caches.
            transfer_args = SimpleNamespace(**{key: value for key, value in vars(args).items() if key != '_login_input_seed'})
            moved, relation = tool.transfer(index, transfer_args, old[role], sha)
            if core.plain(moved) != core.plain(target):
                raise ValueError('Composition relocated child differs from independent target: ' + role)
            for before, after in relation['mapping'].items(): link(mapping, int(before, 16), int(after, 16))
            relations[role] = relation
        result = load('login-composition-rules').compose(selected['reader'][2], selected['handler'][2],
            core.pointer(selected['reader'][1]), core.pointer(selected['handler'][1]))
        result.pop('exports', None)
        result.update(layout=copy.deepcopy(self.layout), verify_whole_exports=True)
        self.roots(result)
        return result, dict(method='independently_proved_children_same_packet_contract', children=relations,
            mapping={hex(before): hex(after) for before, after in sorted(mapping.items())},
            orchestration='Direct Python-coordinated reader success gating; native dispatch and online admission separate')


def select(family=FAMILY):
    if family != FAMILY: raise ValueError('Unreviewed Login composition family')
    return Adapter()
