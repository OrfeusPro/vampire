"""Portable registration helper and static owner window, separate from native dispatch."""
import copy
import json
from pathlib import Path
from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
FAMILY = 'login-registration'
ADAPTER = 'registration-v1'


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    value = module_from_spec(spec); spec.loader.exec_module(value); return value


core = load('portable-native-family')
CHILDREN = {'nested': ('update-native-login-input', 'login-nested'),
            'full_handler': ('update-native-login-full', 'login-full-handler')}


def dependency(args, role, sha):
    if role not in CHILDREN: raise ValueError('Unreviewed registration dependency')
    module, family = CHILDREN[role]; api = load(module).select(family)
    path, c = api.at(args, sha)
    if not c.get('transfer_proof'): raise ValueError('Registration dependency needs a target proof')
    api.published_contexts(args.root, load('native-release-registry').read(args.knowledge))
    value = json.loads((args.root/'knowledge'/api.index/'index.json').read_text('utf-8'))
    rows = [row for row in value['contexts'] if row['context'] == core.pointer(path)]
    if len(rows) != 1: raise ValueError('Registration dependency needs a published semantic report')
    return api, path, c, rows[0]['check']


class Adapter(core.Family):
    family = FAMILY
    adapter = ADAPTER
    proofs = 'native-login-registration-proofs'
    index = 'generated-login-registration'
    scope = 'bounded_native_login_registration_helper'
    verifier = 'verify-login-registration-context'
    layout = dict(abi='win64', executed_roots=1, packet_bytes=352, packet_allocation_bytes=344,
        native_id=True, native_owner=False, native_packet_constructor=False, native_handler=False,
        native_insert=False, native_dispatch=False, real_services=False, session_executed=False)

    def roots(self, c): return load('login-registration-rules').roots(c)

    def tools(self):
        return {**load('login-registration-rules').tools(), **load('login-registration-case-contracts').tools(),
            **{path: sha for module, family in CHILDREN.values() for path, sha in load(module).select(family).tools().items()},
            **{str(HERE/n): core.digest(HERE/n) for n in ('portable-native-family.py', 'update-native-login-registration.py')}}

    def dependencies(self, index, args, sha):
        result = {}
        for role in CHILDREN:
            _, path, _, check = dependency(args, role, sha)
            result[role] = core.pointer(path); result[role+'_check'] = check
        return result

    def export_parts(self, c): return [c]

    def export_coverage(self, root, c, native, bindings, image):
        return load('login-registration-rules').export_coverage(root, c, native, bindings, image)

    def validate_report(self, r, c): load('login-registration-case-contracts').validate_report(r, c)

    def transfer(self, index, args, baseline, sha):
        self.roots(baseline)
        selected = {role: dependency(args, role, sha) for role in CHILDREN}
        for api, _, c, _ in selected.values(): api.validate(index, args, c)
        native, bindings = load('build-native-entry-code'), load('update-bindings')
        before = args.source_store.image(native, baseline['source_sha256'])
        after = args.source_store.image(native, sha); mapping = {}
        current, detail = load('login-registration-rules').transfer(native, bindings, before, after, baseline, mapping,
            selected['nested'][2], selected['full_handler'][2],
            nested_pointer=core.pointer(selected['nested'][1]), handler_pointer=core.pointer(selected['full_handler'][1]))
        for key in ('exports', 'transfer_proof', 'family', 'layout', 'release_id', 'provenance'): current.pop(key, None)
        current.update(schema=1, family=FAMILY, format='login-registration-v1', source_sha256=sha,
            source=str(args.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'), layout=copy.deepcopy(self.layout))
        self.roots(current)
        return current, dict(details=detail, mapping={hex(a): hex(b) for a,b in sorted(mapping.items())})


def select(family=FAMILY):
    if family != FAMILY: raise ValueError('Unreviewed registration family')
    return Adapter()
