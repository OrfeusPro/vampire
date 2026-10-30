"""Typed relocation of the explicit Login post-state wrapper/tail pair.

No backend service or actor virtual method is admitted by this rule. They remain
fixtures even when their source entry/returning body is pinned below.
"""
import copy
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
FAMILY = 'login-post-state'
METADATA = {'schema', 'source', 'source_sha256', 'exports', 'family', 'layout', 'transfer_proof', 'release_id', 'provenance'}
FIELDS = {'helpers', 'functions', 'leaves', 'service_getter', 'globals', 'fixtures', 'call_sites', 'tail_calls', 'verify_whole_exports'}
FIXTURES = {'class', 'lookup', 'occupied', 'assign', 'mode', 'predicate', 'fallback', 'hide', 'list_match', 'settle', 'eligible', 'mark'}
CALL_ROLES = {
    'wrapper': {6: 'service_getter', 14: 'class', 25: 'lookup', 38: 'class', 70: 'service_getter'},
    'target': {75: 'occupied', 94: 'assign', 102: 'mode', 114: 'predicate', 126: 'fallback', 154: 'hide',
        174: 'list_match', 189: 'qword ptr [rax + 0x2e8]', 201: 'qword ptr [rax + 0x540]', 232: 'settle',
        240: 'eligible', 257: 'qword ptr [rax + 0x4c8]', 269: 'qword ptr [rax + 0x540]',
        281: 'qword ptr [rax + 0x2e8]', 331: 'mark', 351: 'mark'}}
ROOT_SHAPES = {'wrapper': (30, 100), 'target': (103, 386)}
BOUNDED_FIXTURES = {'mode': 8, 'fallback': 15, 'eligible': 79}
EXACT_FIXTURES = {'mode': bytes.fromhex('0fb68180030000c3'), 'fallback': bytes.fromhex('488b41304885c07405488b4028c3c3')}


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = module_from_spec(spec);spec.loader.exec_module(value);return value


def tools():
    names = ('post-state-transfer-rules.py', 'update-native-contexts.py', 'update-native-archive-wire.py',
        'update-native-version-result.py', 'update-bindings.py', 'build-native-entry-code.py',
        'version-system-transfer-rules.py', 'build-object-zero-init-code.py', 'extract-native-enums.py',
        'update-native-harness.py', 'audit-launcher-shape-11318.py', 'native-release-registry.py',
        'research-workflow.py', 'knowledge-index.py', 'knowledge-context.py')
    return {str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in names}


def address(value): return load('version-system-transfer-rules').address(value)


def functional(c):
    if (set(c) - METADATA != FIELDS or c.get('verify_whole_exports') is not True
            or set(c.get('functions', {})) != {'wrapper', 'target'} or set(c.get('helpers', {})) != {'memcpy'}
            or set(c.get('fixtures', {})) != FIXTURES or set(c.get('globals', {})) != {'service', 'count', 'chunks'}
            or set(c.get('call_sites', {})) != {'wrapper', 'target'}):
        raise ValueError('Post-state fields or native/fixture roles differ')
    for value in (*c['functions'].values(), *c['fixtures'].values(), *c['helpers'].values(), *c['globals'].values(), c['service_getter']): address(value)
    if set(c['leaves']) != {c['service_getter']}: raise ValueError('Post-state executed leaf scope differs')
    getter = address(c['service_getter']);raw = bytes.fromhex(c['leaves'][c['service_getter']])
    if (len(raw) != 8 or raw[:3] != b'\x48\x8b\x05' or raw[7:] != b'\xc3'
            or getter + 7 + struct.unpack_from('<i', raw, 3)[0] != address(c['globals']['service'])):
        raise ValueError('Post-state singleton getter linkage differs')
    tails = c['tail_calls']
    if not isinstance(tails, list) or len(tails) != 1 or set(tails[0]) != {'address', 'target', 'bytes'}:
        raise ValueError('Post-state exact tail declaration differs')
    tail = tails[0];where = address(tail['address']);raw = bytes.fromhex(tail['bytes'])
    if (where != address(c['functions']['wrapper']) + 89 or tail['target'] != c['functions']['target']
            or len(raw) != 5 or raw[:1] != b'\xe9' or where + 5 + struct.unpack_from('<i', raw, 1)[0] != address(tail['target'])):
        raise ValueError('Post-state E9 tail linkage differs')
    for calls in c['call_sites'].values():
        if not isinstance(calls, dict): raise ValueError('Post-state call-site declaration differs')
        for at, target in calls.items():
            address(at)
            if not isinstance(target, str): raise ValueError('Post-state call target differs')
    return {key: copy.deepcopy(c[key]) for key in FIELDS}


def roots(c):
    functional(c);values = [address(value) for value in c['functions'].values()]
    leaves = {address(c['service_getter'])};fixtures = [address(value) for value in c['fixtures'].values()]
    memcpy = address(c['helpers']['memcpy']);globals_ = [address(value) for value in c['globals'].values()]
    if (len(set(values)) != 2 or len(set(fixtures)) != 12 or len(set(globals_)) != 3
            or set(values) & (leaves | set(fixtures)) or leaves & set(fixtures)
            or memcpy in set(values) | leaves | set(fixtures) or set(globals_) & (set(values) | leaves | set(fixtures) | {memcpy})):
        raise ValueError('Post-state native roots, fixtures or globals alias')
    spans = [(address(at), address(at) + (4 if name == 'count' else 8)) for name, at in c['globals'].items()]
    if any(max(a, b) < min(end_a, end_b) for i, (a, end_a) in enumerate(spans) for b, end_b in spans[:i]):
        raise ValueError('Post-state typed global storage overlaps')
    return set(values)


def calls(rows):
    return {role: {hex(row['address']): hex(row['direct_target']) if row['direct_target'] is not None else row['operands']
        for row in rr if row['call']} for role, rr in rows.items()}


def check_rows(c, rows):
    """Typed offsets derive roles; no first-call or name-based inference."""
    for role, expected in ROOT_SHAPES.items():
        rr = rows[role];origin = address(c['functions'][role]);locations = {r['address'] for r in rr}
        if len(rr) != expected[0] or sum(len(bytes.fromhex(r['bytes'])) for r in rr) != expected[1] or rr[0]['address'] != origin:
            raise ValueError('Post-state whole root byte/instruction boundary differs')
        declared = {r['address'] - origin: r for r in rr if r['call']}
        if set(declared) != set(CALL_ROLES[role]): raise ValueError('Post-state call-site role offsets differ')
        for offset, name in CALL_ROLES[role].items():
            row = declared[offset]
            if name.startswith('qword ptr'):
                if row['direct_target'] is not None or row['rip_references'] or row['operands'] != name:
                    raise ValueError('Post-state virtual dispatch role differs')
            else:
                target = address(c['service_getter'] if name == 'service_getter' else c['fixtures'][name])
                if row['direct_target'] != target: raise ValueError('Post-state direct fixture/getter role differs')
        external = [r for r in rr if r['branch'] and r['direct_target'] not in locations]
        if role == 'wrapper':
            tails = [dict(address=hex(r['address']), target=hex(r['direct_target']) if r['direct_target'] is not None else None, bytes=r['bytes']) for r in external]
            if tails != c['tail_calls'] or external[0]['mnemonic'] != 'jmp':
                raise ValueError('Post-state undeclared wrapper external branch')
        elif external: raise ValueError('Post-state callee external branch is not admitted')
        refs = {r['address'] - origin: r['rip_references'] for r in rr if r['rip_references']}
        wanted = {} if role == 'wrapper' else {290: [address(c['globals']['count'])], 311: [address(c['globals']['chunks'])]}
        if refs != wanted: raise ValueError('Post-state typed global RIP roles differ')
    if calls(rows) != c['call_sites']: raise ValueError('Post-state complete call-site declaration differs')


def pair(native, before, after, mapping):
    common = load('update-native-archive-wire')
    if load('update-native-contexts').signature(native, before) != load('update-native-contexts').signature(native, after):
        raise ValueError('Post-state whole instruction/control shape changed')
    for a, b in zip(before, after):
        if ((a['call'] or a['branch']) and a['direct_target'] is None and not a['rip_references']
                and a['operands'] != b['operands']): raise ValueError('Post-state indirect dispatch changed')
        common.add_link(mapping, a['address'], b['address'])
        if a['direct_target'] is not None: common.add_link(mapping, a['direct_target'], b['direct_target'])
        if len(a['rip_references']) != len(b['rip_references']): raise ValueError('Post-state data edge count differs')
        for old, new in zip(a['rip_references'], b['rip_references']): common.add_link(mapping, old, new)


def resolve(native, bindings, before, after, c, mapping):
    version = load('update-native-version-result');common = load('update-native-archive-wire')
    addresses = roots(c);candidates = {at: version.candidates(native, bindings, before, after, at) for at in sorted(addresses)}
    pending = set(addresses)
    while pending:
        progress = False
        for at in sorted(pending):
            hits = [hit for hit in candidates[at] if at not in mapping or mapping[at] == hit]
            if len(hits) != 1: continue
            common.add_link(mapping, at, hits[0]);pair(native, bindings.rows(native, before, at), bindings.rows(native, after, hits[0]), mapping)
            pending.remove(at);progress = True
        if not progress: raise ValueError('Post-state missing or ambiguous caller-constrained roots')


def decode(native, image, at, size):
    raw = load('version-system-transfer-rules').image_bytes(image, at, size)
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64);decoder.detail = True
    ins = list(decoder.disasm(raw, at))
    if not ins or sum(row.size for row in ins) != size or ins[-1].mnemonic != 'ret':
        raise ValueError('Post-state bounded returning body boundary differs')
    rows = [];locations = {row.address for row in ins}
    for row in ins:
        call, branch = row.group(native.capstone.CS_GRP_CALL), row.group(native.capstone.CS_GRP_JUMP)
        target = row.operands[0].imm if (call or branch) and row.operands and row.operands[0].type == native.X86_OP_IMM else None
        if call or (branch and target not in locations): raise ValueError('Post-state bounded fixture/leaf has external edge')
        rows.append(dict(address=row.address, bytes=row.bytes.hex(), mnemonic=row.mnemonic, operands=row.op_str,
            call=call, branch=branch, direct_target=target, rip_references=[row.address + row.size + op.mem.disp for op in row.operands
                if op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP]))
    return rows


def transfer(native, bindings, before, after, baseline, mapping):
    current = functional(baseline);roots(baseline)
    utility, common = load('version-system-transfer-rules'), load('update-native-archive-wire')
    resolve(native, bindings, before, after, baseline, mapping)
    old_rows = {role: bindings.rows(native, before, address(at)) for role, at in baseline['functions'].items()}
    check_rows(baseline, old_rows)
    for role, old in baseline['functions'].items():
        utility.concrete(before, address(old));utility.concrete(after, mapping[address(old)])
    def mapped(text):
        at = address(text)
        if at not in mapping: raise ValueError('Post-state undeclared relocated address: ' + text)
        return hex(mapping[at])
    getter = address(baseline['service_getter']);target_getter = mapping[getter]
    if utility.image_bytes(before, getter, 8).hex() != baseline['leaves'][baseline['service_getter']]:
        raise ValueError('Post-state baseline singleton leaf bytes differ')
    pair(native, decode(native, before, getter, 8), decode(native, after, target_getter, 8), mapping)
    current['service_getter'] = hex(target_getter)
    current['leaves'] = {hex(target_getter): utility.image_bytes(after, target_getter, 8).hex()}
    current['globals'] = {key: mapped(at) for key, at in baseline['globals'].items()}
    typed = []
    for name, text in baseline['globals'].items():
        size = 4 if name == 'count' else 8;old = address(text);new = mapping[old]
        a, b = utility.data_input(before, old, size), utility.data_input(after, new, size)
        if a != b or a.get('storage') != 'pe-zero-fill': raise ValueError('Post-state typed global zero-fill storage changed')
        typed.append(dict(role=name, address=hex(new), size=size, input=b))
    fixtures = []
    for name, text in baseline['fixtures'].items():
        old = address(text);new = mapping[old]
        if name in BOUNDED_FIXTURES:
            size = BOUNDED_FIXTURES[name];a = utility.image_bytes(before, old, size);b = utility.image_bytes(after, new, size)
            if name in EXACT_FIXTURES and (a != EXACT_FIXTURES[name] or b != a):
                raise ValueError('Post-state exact returning fixture body changed: ' + name)
            aa, bb = decode(native, before, old, size), decode(native, after, new, size);pair(native, aa, bb, mapping)
            refs = {r['address'] - old: r['rip_references'] for r in aa if r['rip_references']}
            wanted = {23: [address(baseline['globals']['count'])], 48: [address(baseline['globals']['chunks'])]} if name == 'eligible' else {}
            if refs != wanted: raise ValueError('Post-state fixture global role differs')
            record = dict(role=name, address=hex(new), kind='bounded-returning-fixture', size=size, bytes_sha256=hashlib.sha256(b).hexdigest())
        else:
            utility.concrete(before, old);utility.concrete(after, new)
            record = dict(role=name, address=hex(new), kind='unwind-fixture')
        record['scope'] = 'Explicit fixture; backend body is not executed or semantically admitted';fixtures.append(record)
    current['fixtures'] = {key: mapped(at) for key, at in baseline['fixtures'].items()}
    current['functions'] = {key: mapped(at) for key, at in baseline['functions'].items()}
    current['call_sites'] = calls({role: bindings.rows(native, after, address(at)) for role, at in current['functions'].items()})
    current['tail_calls'] = [dict(address=mapped(t['address']), target=mapped(t['target']), bytes=utility.image_bytes(after, mapping[address(t['address'])], 5).hex()) for t in baseline['tail_calls']]
    memcpy = address(baseline['helpers']['memcpy'])
    if memcpy not in mapping: common.add_link(mapping, memcpy, load('update-native-contexts').find_memcpy(native, before, after, memcpy))
    current['helpers'] = dict(memcpy=mapped(baseline['helpers']['memcpy']))
    thunk = utility.import_thunk(before, after, memcpy, mapping[memcpy], 'memcpy', mapping)
    roots(current);check_rows(current, {role: bindings.rows(native, after, address(at)) for role, at in current['functions'].items()})
    return current, dict(typed_inputs=typed, fixtures=fixtures, memcpy=thunk,
        executed_leaf=dict(address=current['service_getter'], bytes=current['leaves'][current['service_getter']]), tail_calls=current['tail_calls'],
        scope='Two complete native roots and singleton getter; backend services, actor/class/object tables and virtual callbacks remain fixtures')
