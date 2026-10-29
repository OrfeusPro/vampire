"""Portable LoginResult nested layout and complete bounded string/buffer input.

The already proved VersionResult input closure seeds relocation, not LoginResult
semantic admission. Each role owns its new proof, scenario report and cache.
"""
import copy
import json
from pathlib import Path
from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
FAMILIES = ('login-nested', 'login-strings-buffer')
ADAPTER = 'login-input-v1'
PACKET_NAMES = {'constructor', 'reader', 'time_constructor', 'period_constructor', 'time_reader', 'period_reader'}


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = module_from_spec(spec); spec.loader.exec_module(value); return value


core = load('portable-native-family')


def result_at(args, sha):
    api = load('update-native-version-result'); registry = load('native-release-registry').read(args.knowledge)
    found = core.historical(args.knowledge, 'version-result', registry) + api.published_contexts(args.root, registry)
    found = [(p, c) for p, c, _ in found if c['source_sha256'] == sha]
    if len(found) != 1: raise ValueError('Missing or ambiguous source-specific VersionResult input')
    return found[0]


def result_receipt(args, sha):
    api = load('update-native-version-result'); registry = load('native-release-registry').read(args.knowledge)
    api.published_contexts(args.root, registry)
    value = json.loads((args.root / 'knowledge/generated-version-results/index.json').read_text('utf-8'))
    rows = [r for r in value['contexts'] if core.checked(args.root, r['context'], 'generated-native-contexts')['source_sha256'] == sha]
    if len(rows) != 1: raise ValueError('Target input needs a published VersionResult semantic proof')
    return rows[0]


def seed(index, args, baseline_sha, sha):
    api = load('update-native-version-result'); old_path, old = result_at(args, baseline_sha)
    target_path, target = result_at(args, sha); publication = result_receipt(args, sha)
    memo = getattr(args, '_login_input_seed', None)
    if memo is None or memo['store'] is not args.source_store:
        memo = dict(store=args.source_store, values={}); args._login_input_seed = memo
    lineage = {**core.lineage_inputs(args, old_path), **core.lineage_inputs(args, target_path)}
    key = (json.dumps(lineage, sort_keys=True), json.dumps(api.tools(), sort_keys=True), publication['check']['sha256'])
    if key not in memo['values']:
        if old.get('transfer_proof'): api.validate(index, args, old)
        api.validate(index, args, target)
        native, bindings = load('build-native-entry-code'), load('update-bindings')
        before = args.source_store.image(native, baseline_sha); after = args.source_store.image(native, sha)
        api.export_coverage(args.root, old, native, bindings, before)
        current, relation = api.transfer(native, bindings, before, after, old, sha,
            args.root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe')
        if api.plain(current) != api.plain(target): raise ValueError('Input seed differs from independent VersionResult proof')
        memo['values'][key] = (target, {int(a, 16): int(b, 16) for a, b in relation['mapping'].items()},
            dict(baseline_result=core.pointer(old_path), target_result=core.pointer(target_path), target_result_check=publication['check']))
    return copy.deepcopy(memo['values'][key])


def scoped_roots(family, c):
    if family not in FAMILIES: raise ValueError('Unreviewed Login input family')
    if any(k in c for k in ('native_metadata', 'native_sdk', 'native_input', 'native_handler', 'native_admission')):
        raise ValueError('Login input has an unreviewed optional native scope')
    if set(c.get('functions', {})) != PACKET_NAMES or set(c.get('helpers', {})) != {'memcpy'}:
        raise ValueError('Login packet/helper roles differ')
    roots = {int(at, 16) for at in c['functions'].values()}
    if len(roots) != 6: raise ValueError('Login nested roots alias')
    leaves = {int(at, 16) for at in c.get('leaves', {})}
    hooks = {int(c['string_constructor'], 16), int(c['helpers']['memcpy'], 16)}
    if family == FAMILIES[0]:
        if any(k in c for k in ('input', 'native_strings', 'function_budget', 'budget_scope', 'native_input', 'native_handler')):
            raise ValueError('Nested Login optional native scope differs')
        hooks.add(int(c['string_reader'], 16))
        if len(leaves) != 3 or len(hooks) != 3: raise ValueError('Nested Login leaf/fixture partition differs')
    else:
        input_ = c.get('input', {})
        names = load('update-native-version-result').INPUT_NAMES
        if (c.get('native_strings') is not True or type(c.get('function_budget')) is not int
                or c['function_budget'] != 20 or c.get('budget_scope') != 'login-result-buffer'
                or set(input_.get('functions', {})) != names
                or any(k in c for k in ('native_input', 'native_handler'))):
            raise ValueError('Login string/input native scope differs')
        native_input = {int(at, 16) for at in input_['functions'].values()}
        if len(native_input) != 14 or roots & native_input: raise ValueError('Login input roots alias')
        roots |= native_input
        if input_.get('source_sha256') != c['source_sha256'] or ('source' in input_ and Path(input_['source']).resolve() != Path(c['source']).resolve()):
            raise ValueError('Login input nested source differs')
        if c['string_reader'] != input_['functions']['string']: raise ValueError('Login string reader linkage differs')
        storage = input_.get('string_fixtures', {})
        if set(storage) != {'growth', 'utf16_allocate', 'assign', 'free', 'cpp_free', 'security'}:
            raise ValueError('Login string storage fixture roles differ')
        storage_values = {int(at, 16) for at in storage.values()}
        if len(storage_values) != 6 or hooks & storage_values: raise ValueError('Login string fixture roles alias')
        hooks |= storage_values
        inner_leaves = input_.get('leaves', {})
        if len(leaves) != 6 or len(inner_leaves) != 3: raise ValueError('Login input leaf partition differs')
        for at, spec in inner_leaves.items():
            if at not in c['leaves'] or spec.get('bytes') != c['leaves'][at]:
                raise ValueError('Login nested leaf bytes differ')
    if roots & leaves or hooks & (roots | leaves): raise ValueError('Login fixture shadows executed root or leaf')
    if c.get('verify_whole_exports') is not True: raise ValueError('Login whole export validation is required')
    if load('login-input-transfer-rules').roots(family, c) != roots:
        raise ValueError('Login transfer and execution roots differ')
    return roots


def nested_projection(c):
    keys = ('helpers', 'functions', 'packet_table', 'time_table', 'period_table', 'id_getter', 'string_reader', 'string_constructor', 'constructor_defaults')
    result = {key: copy.deepcopy(c[key]) for key in keys}
    result['leaves'] = {at: c['leaves'][at] for at in (c['id_getter'],) if at in c['leaves']}
    return result


class Adapter(core.Family):
    def __init__(self, family):
        if family not in FAMILIES: raise ValueError('Unreviewed Login input family')
        self.family = family; self.adapter = ADAPTER; self.proofs = 'native-login-input-proofs'
        self.scope = 'bounded_native_' + family.replace('-', '_'); self.index = 'generated-login-input/' + family
        strings = family == FAMILIES[1]
        self.layout = dict(abi='win64', executed_roots=20 if strings else 6, packet_bytes=352,
            native_strings=strings, native_buffer_construction=strings, max_buffer=4096, handler_executed=False)
        self.verifier = load('login-input-case-contracts').verifier(family)

    def roots(self, c): return scoped_roots(self.family, c)

    def tools(self):
        return {**load('update-native-version-result').tools(), **load('login-input-transfer-rules').tools(),
            **load('login-input-case-contracts').tools(),
            **{str(HERE / n): core.digest(HERE / n) for n in ('portable-native-family.py', 'update-native-login-input.py')}}

    def export_parts(self, c):
        result = [c]
        if self.family == FAMILIES[1]:
            part = copy.deepcopy(c['input']); part.setdefault('source', c['source']); result.append(part)
        return result

    def dependencies(self, index, args, sha):
        p, _ = result_at(args, sha); row = result_receipt(args, sha)
        result = dict(input=core.pointer(p), input_check=row['check'])
        if self.family == FAMILIES[1]:
            adapter = Adapter(FAMILIES[0]); path, c = adapter.at(args, sha)
            if not c.get('transfer_proof'): raise ValueError('Target nested Login needs a portable proof')
            registry = load('native-release-registry').read(args.knowledge); adapter.published_contexts(args.root, registry)
            data = json.loads((args.root / 'knowledge' / adapter.index / 'index.json').read_text('utf-8'))
            rows = [r for r in data['contexts'] if r['context'] == core.pointer(path)]
            if len(rows) != 1: raise ValueError('Target nested Login needs a published semantic proof')
            result.update(nested=core.pointer(path), nested_check=rows[0]['check'])
        return result

    def input_materials(self, args, path, baseline, sha):
        result = core.lineage_inputs(args, path); p, _ = result_at(args, baseline['source_sha256'])
        result.update(core.lineage_inputs(args, p))
        return result

    def validate_report(self, r, c): load('login-input-case-contracts').validate_report(self.family, r)

    def transfer(self, index, args, baseline, sha):
        self.roots(baseline); target_input, mapping, seed_proof = seed(index, args, baseline['source_sha256'], sha)
        native, bindings = load('build-native-entry-code'), load('update-bindings')
        before = args.source_store.image(native, baseline['source_sha256']); after = args.source_store.image(native, sha)
        result, detail = load('login-input-transfer-rules').transfer(self.family, native, bindings, before, after, baseline, mapping)
        if self.family == FAMILIES[1]:
            result['input']['source_sha256'] = sha
            adapter = Adapter(FAMILIES[0]); p, target_nested = adapter.at(args, sha); adapter.validate(index, args, target_nested)
            if nested_projection(result) != nested_projection(target_nested): raise ValueError('Login input integration differs from target nested proof')
            if any(result['leaves'].get(at) != data for at, data in target_nested['leaves'].items()):
                raise ValueError('Login input integration nested leaf closure differs')
            # The seed is an independently validated static input closure. This
            # family executes those strings anew; no old semantic report is widened.
            input_ = {k: v for k, v in result['input'].items() if k not in ('source', 'exports', 'portable_buffer_proof')}
            expected = {k: v for k, v in target_input['native_input'].items() if k not in ('source', 'exports', 'portable_buffer_proof')}
            for value in (input_, expected):
                value['leaves'] = {at: spec['bytes'] for at, spec in value['leaves'].items()}
            if input_ != expected: raise ValueError('Login input closure differs from target VersionResult proof')
            detail['target_nested'] = core.pointer(p)
        for key in ('exports', 'transfer_proof', 'family', 'layout', 'release_id', 'provenance'): result.pop(key, None)
        result.update(schema=1, family=self.family, source_sha256=sha,
            source=str(args.root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'),
            layout=self.layout, verify_whole_exports=True)
        if self.family == FAMILIES[1]: result['input']['source'] = result['source']
        self.roots(result)
        return result, dict(seed=seed_proof, details=detail, mapping={hex(a): hex(b) for a, b in sorted(mapping.items())})


def select(family): return Adapter(family)
