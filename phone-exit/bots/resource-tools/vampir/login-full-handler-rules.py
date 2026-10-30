"""Explicit legacy import and later whole-shape transfer of current Login handler.

The legacy branch imports fixture role identities, not an unchanged-handler
claim. New trailing-field branches require a new source-bound native report.
"""
import copy
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
LEGACY_SHA = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
LEGACY = 'legacy-reviewed-handler'
CURRENT = 'login-full-handler-v1'
META = {'schema', 'source', 'source_sha256', 'exports', 'family', 'layout', 'transfer_proof', 'release_id', 'provenance'}
BASE = {'helpers', 'functions', 'leaves', 'packet_table', 'id_getter', 'fixtures', 'globals', 'call_sites', 'verify_whole_exports', 'format'}
ADDED = {820: 'trailing_predicate', 836: 'trailing_apply', 855: 'trailing_apply', 869: 'free'}
BOUNDED = {'log': 3, 'localizer': 8, 'state': 8, 'controller': 8, 'peer': 8, 'peer_flag': 12,
    'selected_server': 11, 'exit_service': 8, 'view_service': 8, 'sdk_manager': 8, 'clock_service': 8,
    'clock': 9, 'time_service': 8, 'time_pair': 111, 'post_predicate': 15, 'sdk_service': 8,
    'disconnect': 9, 'gate_state': 8, 'predicate_service': 8, 'unsupported_1455be460': 8,
    'unsupported_141488490': 5}
GLOBAL_REFS = {'sdk_enabled': (648, 982, 1189), 'special22': (417,), 'derived': (766,)}
NEW_REGION = (
    (795, '448b8e54010000'), (802, '488d8e40010000'), (809, '448b8650010000'),
    (816, '488b5658'), (825, '84c0'), (827, '740e'), (829, '488d8e40010000'),
    (841, 'eb1f'), (843, '488d4de7'), (847, '4c8975e7'), (851, '4c8975ef'),
    (860, '488b4de7'), (864, '4885c9'), (867, '7405'))


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = module_from_spec(spec);spec.loader.exec_module(value);return value


def tools():
    return {**load('login-handler-transfer-rules').tools(), **load('result-gate-transfer-rules').tools(),
        str(HERE / 'login-full-handler-rules.py'): hashlib.sha256((HERE / 'login-full-handler-rules.py').read_bytes()).hexdigest(),
        str(HERE / 'version-gate-switch-11318.py'): hashlib.sha256((HERE / 'version-gate-switch-11318.py').read_bytes()).hexdigest()}


def address(value): return load('version-system-transfer-rules').address(value)


def functional(c):
    legacy = c.get('format') == LEGACY
    required = BASE | {'packet_bytes'} | ({'switch_gate'} if legacy else {'gate_context', 'fixture_boundaries'})
    if (c.get('format') not in (LEGACY, CURRENT) or set(c) - META != required
            or c.get('verify_whole_exports') is not True or set(c.get('helpers', {})) != {'memcpy'}
            or set(c.get('functions', {})) != {'handler', 'gate'} or set(c.get('call_sites', {})) != {'handler', 'gate'}
            or set(c.get('globals', {})) != set(GLOBAL_REFS)):
        raise ValueError('Full Login handler fields or native scope differ')
    if legacy:
        if (c.get('source_sha256') != LEGACY_SHA or c['switch_gate'] != 'version-gate-11318'
                or type(c['packet_bytes']) is not int or c['packet_bytes'] != 320):
            raise ValueError('Legacy full-handler import requires its exact reviewed source')
        expected_count = 62
    else:
        if type(c['packet_bytes']) is not int or c['packet_bytes'] != 352:
            raise ValueError('Current full-handler packet byte layout differs')
        expected_count = 64
        gate = c['gate_context']
        if (not isinstance(gate, dict) or set(gate) != {'path', 'sha256'} or not isinstance(gate['path'], str)
                or not isinstance(gate['sha256'], str) or len(gate['sha256']) != 64
                or any(char not in '0123456789abcdef' for char in gate['sha256'])):
            raise ValueError('Full-handler independent gate pointer differs')
        if set(c['fixture_boundaries']) != set(c['fixtures']): raise ValueError('Full-handler fixture boundary inventory differs')
    if len(c['fixtures']) != expected_count: raise ValueError('Full-handler fixture role count differs')
    if (not {'string_init', 'free', 'log', 'localizer', 'localized', 'gate_state', 'gate_error'} <= set(c['fixtures'])
            or (legacy and set(ADDED.values()) - {'free'} & set(c['fixtures']))
            or (not legacy and not {'trailing_predicate', 'trailing_apply'} <= set(c['fixtures']))):
        raise ValueError('Full-handler fixture labels differ')
    for text in (*c['functions'].values(), *c['helpers'].values(), *c['globals'].values(), *c['fixtures'].values(), c['packet_table'], c['id_getter']): address(text)
    if c['leaves'] != {c['id_getter']: 'b804000000c3'}: raise ValueError('Full-handler packet ID leaf differs')
    return {key: copy.deepcopy(c[key]) for key in required}


def roots(c):
    functional(c);values = [address(value) for value in c['functions'].values()]
    hooks = [address(value) for value in c['fixtures'].values()];leaf = address(c['id_getter']);copy_ = address(c['helpers']['memcpy'])
    if (len(set(values)) != 2 or len(set(hooks)) != len(hooks) or set(values) & set(hooks)
            or leaf in set(values) | set(hooks) or copy_ in set(values) | set(hooks) | {leaf}):
        raise ValueError('Full-handler roots, ID leaf or fixture roles alias')
    return set(values)


def calls(rr):
    return {hex(row['address']): hex(row['direct_target']) if row['direct_target'] is not None else row['operands'] for row in rr if row['call']}


def trailing_calls(): return {str(offset): role for offset, role in ADDED.items()}


def link_call_roles(old, new, mapping):
    a, b = [r for r in old if r['call']], [r for r in new if r['call']]
    if len(a) != len(b): raise ValueError('Full-handler role import call inventory changed')
    add = load('update-native-archive-wire').add_link
    for before, after in zip(a, b):
        if (before['direct_target'] is None) != (after['direct_target'] is None):
            raise ValueError('Full-handler direct/virtual call topology changed')
        if before['direct_target'] is None:
            if before['operands'] != after['operands'] or before['rip_references'] or after['rip_references']:
                raise ValueError('Full-handler virtual call role changed')
        else: add(mapping, before['direct_target'], after['direct_target'])
    old_targets = [r['direct_target'] for r in a if r['direct_target'] is not None]
    new_targets = [r['direct_target'] for r in b if r['direct_target'] is not None]
    if any((x == y) != (new_targets[i] == new_targets[j]) for i, x in enumerate(old_targets) for j, y in enumerate(old_targets[:i])):
        raise ValueError('Full-handler callee alias partition changed')


def current_handler(native, bindings, image, at, fixtures, gate):
    rr = bindings.rows(native, image, at)
    if len(rr) != 356 or sum(len(bytes.fromhex(r['bytes'])) for r in rr) != 1557:
        raise ValueError('Current full-handler whole instruction/byte boundary differs')
    locations = {r['address'] for r in rr};parts = {r['address'] - at: r for r in rr};cc = [r for r in rr if r['call']]
    if len(cc) != 85 or parts.get(213, {}).get('direct_target') != gate:
        raise ValueError('Current full-handler gate/call inventory differs')
    for offset, role in ADDED.items():
        row = parts.get(offset, {})
        if row.get('call') is not True or row.get('direct_target') != address(fixtures[role]):
            raise ValueError('Current trailing-field callee role differs')
    for offset, expected in NEW_REGION:
        if parts.get(offset, {}).get('bytes') != expected: raise ValueError('Current trailing-field argument/control slice changed')
    for r in rr:
        if r['branch'] and (r['direct_target'] is None or r['direct_target'] not in locations):
            raise ValueError('Current handler branch leaves its exact body')
    return rr


def dependencies(early, gate, nested):
    sha = early['source_sha256'];path = Path(early['source']).resolve()
    if any(c['source_sha256'] != sha or Path(c['source']).resolve() != path for c in (gate, nested)):
        raise ValueError('Full-handler independent dependency source differs')
    if early['gate'] != gate['function'] or any(c['helpers'] != early['helpers'] for c in (gate, nested)):
        raise ValueError('Full-handler independent dependency helper/gate differs')
    if nested['leaves'].get(nested['id_getter']) != 'b804000000c3': raise ValueError('Full-handler independent packet ID differs')


def decode_boundary(native, image, at, size, *, tail=False):
    utility = load('version-system-transfer-rules');raw = utility.image_bytes(image, at, size)
    cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64);cs.detail = True
    ins = list(cs.disasm(raw, at));locations = {r.address for r in ins}
    if not ins or sum(r.size for r in ins) != size or ins[-1].mnemonic != ('jmp' if tail else 'ret'):
        raise ValueError('Full-handler bounded fixture boundary changed')
    result = []
    for r in ins:
        call, branch = r.group(native.capstone.CS_GRP_CALL), r.group(native.capstone.CS_GRP_JUMP)
        target = r.operands[0].imm if (call or branch) and r.operands and r.operands[0].type == native.X86_OP_IMM else None
        if call or (branch and target not in locations and not (tail and r is ins[-1] and r.mnemonic == 'jmp' and target is not None)):
            raise ValueError('Full-handler fixture contains an unreviewed external edge')
        if tail and r is ins[-1]: utility.concrete(image, target)
        result.append(dict(address=r.address, bytes=r.bytes.hex(), mnemonic=r.mnemonic, operands=r.op_str,
            call=call, branch=branch, direct_target=target, rip_references=[r.address + r.size + op.mem.disp for op in r.operands
                if op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP]))
    return result


def boundary_pair(native, before, after, old, new, role, mapping):
    utility = load('version-system-transfer-rules')
    if role in BOUNDED:
        size = BOUNDED[role];a = decode_boundary(native, before, old, size, tail=role in ('clock', 'disconnect'))
        b = decode_boundary(native, after, new, size, tail=role in ('clock', 'disconnect'))
        load('login-handler-transfer-rules').pair_static(native, a, b, mapping)
        inputs = []
        for row in a:
            for ref in row['rip_references']:
                width = 8
                x, y = utility.data_input(before, ref, width), utility.data_input(after, mapping[ref], width)
                if x != y: raise ValueError('Full-handler fixture RIP input changed: ' + role)
                inputs.append(dict(address=hex(mapping[ref]), size=width, input=y))
        return dict(kind='bounded-tail-fixture' if role in ('clock', 'disconnect') else 'bounded-returning-fixture',
            size=size, bytes=utility.image_bytes(after, new, size).hex(), inputs=inputs)
    utility.concrete(before, old);utility.concrete(after, new)
    return dict(kind='unwind-fixture')


def transfer(native, bindings, before, after, baseline, mapping, early, gate, nested, baseline_gate=None):
    legacy = baseline.get('format') == LEGACY;functional(baseline);roots(baseline);dependencies(early, gate, nested)
    utility = load('version-system-transfer-rules');common = load('update-native-archive-wire');gate_rule = load('result-gate-transfer-rules')
    target = address(early['functions']['handler']);old_handler = address(baseline['functions']['handler'])
    old_gate = address(baseline['functions']['gate']);target_gate = address(gate['function'])
    common.add_link(mapping, old_handler, target);common.add_link(mapping, old_gate, target_gate)
    old_rows = bindings.rows(native, before, old_handler);new_rows = bindings.rows(native, after, target)
    if calls(old_rows) != baseline['call_sites']['handler'] or calls(new_rows) != early['call_sites']['handler']:
        raise ValueError('Full-handler source call inventory differs from checked material')
    gate_rows = gate_rule.rows(native, after, gate)
    if legacy:
        old_gate_rows = load('version-gate-switch-11318').rows(native, before, LEGACY_SHA)
        if calls(old_gate_rows) != baseline['call_sites']['gate']: raise ValueError('Legacy full-handler gate calls differ')
        if len([r for r in old_rows if r['call']]) != 81: raise ValueError('Legacy full-handler requires 81 reviewed calls')
        filtered = [r for r in new_rows if not r['call'] or r['address'] - target not in ADDED]
        link_call_roles(old_rows, filtered, mapping);link_call_roles(old_gate_rows, gate_rows, mapping)
    else:
        if (not isinstance(baseline_gate, dict) or baseline_gate.get('source_sha256') != baseline.get('source_sha256')
                or Path(baseline_gate.get('source', '')).resolve() != Path(baseline.get('source', '')).resolve()
                or baseline_gate.get('function') != baseline['functions']['gate']):
            raise ValueError('Full-handler baseline independent gate source/linkage differs')
        current_handler(native, bindings, before, old_handler, baseline['fixtures'], old_gate)
        common.pair_rows(native, old_rows, new_rows, mapping)
        moved_gate, relation = gate_rule.transfer(native, bindings, before, after, baseline_gate, mapping)
        if gate_rule.functional(moved_gate) != gate_rule.functional(gate): raise ValueError('Full-handler relocated gate differs from independent target proof')
    fixtures = {role: hex(mapping[address(at)]) for role, at in baseline['fixtures'].items()}
    parts = {r['address'] - target: r for r in new_rows}
    if legacy:
        for offset, role in ADDED.items():
            found = parts.get(offset, {}).get('direct_target')
            if found is None: raise ValueError('Missing explicit new trailing-field call')
            if role in fixtures and fixtures[role] != hex(found): raise ValueError('New trailing branch callee alias differs')
            fixtures[role] = hex(found)
    current_handler(native, bindings, after, target, fixtures, target_gate)
    if any(fixtures.get(name) != at for name, at in early['fixtures'].items()):
        raise ValueError('Full-handler imported early fixture differs from independent target proof')
    if any(fixtures.get(name) != at for name, at in gate['fixtures'].items()):
        raise ValueError('Full-handler imported gate fixture differs from independent target proof')
    # Reuse the exact whole-handler static inputs of the independently proved
    # early role. Identity transfer validates every current RIP/literal/table.
    static_mapping = {};common.pair_rows(native, new_rows, new_rows, static_mapping)
    checked_early = copy.deepcopy(early)
    static = load('login-handler-transfer-rules').early(native, bindings, after, after, early, checked_early, static_mapping, {'handler': new_rows})
    refs = {r['address'] - target: r['rip_references'] for r in new_rows if r['rip_references']}
    globals_ = {}
    for role, offsets in GLOBAL_REFS.items():
        values = [refs[offset] for offset in offsets]
        if any(len(value) != 1 for value in values) or len({value[0] for value in values}) != 1:
            raise ValueError('Full-handler named global RIP role differs')
        globals_[role] = hex(values[0][0]);common.add_link(mapping, address(baseline['globals'][role]), values[0][0])
    boundaries = {}
    for role, old_text in baseline['fixtures'].items():
        boundaries[role] = boundary_pair(native, before, after, address(old_text), address(fixtures[role]), role, mapping)
    for role in ('trailing_predicate', 'trailing_apply'):
        utility.concrete(after, address(fixtures[role]));boundaries[role] = dict(kind='unwind-fixture')
    common.add_link(mapping, address(baseline['packet_table']), address(nested['packet_table']))
    common.add_link(mapping, address(baseline['id_getter']), address(nested['id_getter']))
    if utility.image_bytes(before, address(baseline['id_getter']), 6) != bytes.fromhex('b804000000c3'):
        raise ValueError('Legacy/current full-handler baseline packet ID bytes differ')
    if struct.unpack('<Q', utility.image_bytes(after, address(nested['packet_table']) + 0x28, 8))[0] != address(nested['id_getter']):
        raise ValueError('Full-handler target packet table ID slot differs')
    if struct.unpack('<Q', utility.image_bytes(before, address(baseline['packet_table']) + 0x28, 8))[0] != address(baseline['id_getter']):
        raise ValueError('Full-handler baseline packet table ID slot differs')
    thunk = utility.import_thunk(before, after, address(baseline['helpers']['memcpy']), address(early['helpers']['memcpy']), 'memcpy', mapping)
    common.add_link(mapping, address(baseline['helpers']['memcpy']), address(early['helpers']['memcpy']))
    current = dict(format=CURRENT, packet_bytes=352, functions=dict(handler=hex(target), gate=hex(target_gate)),
        helpers=copy.deepcopy(early['helpers']), packet_table=nested['packet_table'], id_getter=nested['id_getter'],
        leaves={nested['id_getter']: 'b804000000c3'}, fixtures=fixtures, globals=globals_,
        call_sites=dict(handler=calls(new_rows), gate=calls(gate_rows)),
        fixture_boundaries=boundaries, verify_whole_exports=True)
    # The owning adapter attaches the exact immutable gate_context pointer and
    # outer source/layout metadata before roots()/publication admission.
    return current, dict(method='legacy_role_import_new_branch_requires_semantic_proof' if legacy else 'whole_current_handler_transfer',
        old_handler_calls=81 if legacy else 85, current_handler_calls=85, gate_calls=44, new_trailing_calls=trailing_calls(),
        static_inputs=static, fixture_boundaries=boundaries, memcpy=thunk,
        remaining_scope='Synthetic352-byte packet; backend/UI/SDK/clock/storage/post-state services and all unsupported gate helpers remain explicit fixtures; reader integration and runtime separate')


def export_coverage(root, c, native, bindings, image):
    """Exact ordinary handler and explicitly partitioned inline-data gate."""
    roots(c);common = load('update-native-contexts');legacy = c['format'] == LEGACY
    gate = None if legacy else common.checked(root, c['gate_context'], 'generated-native-contexts')
    if gate is not None:
        if (gate['source_sha256'] != c['source_sha256'] or Path(gate['source']).resolve() != Path(c['source']).resolve()
                or gate['function'] != c['functions']['gate']): raise ValueError('Full-handler export gate source/linkage differs')
        load('result-gate-transfer-rules').export_coverage(root, gate, native, bindings, image)
    wanted = {'handler': bindings.rows(native, image, address(c['functions']['handler'])),
        'gate': load('version-gate-switch-11318').rows(native, image, LEGACY_SHA) if legacy else load('result-gate-transfer-rules').rows(native, image, gate)}
    if calls(wanted['handler']) != c['call_sites']['handler'] or calls(wanted['gate']) != c['call_sites']['gate']:
        raise ValueError('Full-handler export call inventory differs')
    available = {};records = {}
    for run, expected in c.get('exports', {}).items():
        if not isinstance(run, str) or Path(run).name != run or not run.startswith('run-'):
            raise ValueError('Full-handler export name differs')
        path = Path(root) / 'ghidra/request-exports' / c['source_sha256'] / run / 'details.json'
        if common.digest(path) != expected: raise ValueError('Full-handler export hash changed')
        value = json.loads(path.read_text('utf-8'))
        if value.get('new_source_sha256', value.get('source_sha256')) != c['source_sha256']:
            raise ValueError('Full-handler export source differs')
        for function in value.get('functions', []):
            role = next((name for name, at in c['functions'].items() if address(at) == address(function['address'])), None)
            if role is None: continue
            if any(function.get(key) is not True for key in ('decompilation_completed', 'block_coverage_complete', 'direct_flow_coverage_complete')):
                raise ValueError('Full-handler export whole coverage differs')
            actual = [(address(r['address']), r['bytes'].lower()) for r in function['instructions']]
            exact = [(r['address'], r['bytes'].lower()) for r in wanted[role]]
            if len(actual) != len(set(at for at, _ in actual)) or sorted(actual) != sorted(exact):
                raise ValueError('Full-handler export exact code/data separation differs')
            if role in records and records[role] != sorted(actual): raise ValueError('Conflicting full-handler complete exports')
            records[role] = sorted(actual);available[role] = function
    if set(available) != {'handler', 'gate'}: raise ValueError('Full-handler exports lack both complete roots')
    load('audit-launcher-shape-11318').normalize_function(native, image, available['handler'])
    if legacy:
        load('version-gate-switch-11318').validate(native, type('GateView', (), dict(image=image, sha=c['source_sha256'], raw=image.data,
            fragments=[available['gate']]))())
