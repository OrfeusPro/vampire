"""Source-bound registration window and complete helper relocation.

The large registration owner and container insertion are never executed here.
Packet storage extent and the actual allocation immediate are distinct inputs.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
FAMILY = 'login-registration'
LEGACY = 'legacy-reviewed-registration'
CURRENT = 'login-registration-v1'
LEGACY_SHA = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
BINDINGS = {'owner', 'allocate', 'packet_constructor', 'packet_table', 'id_getter', 'handler_table',
            'handler', 'register', 'insert', 'name_getter'}
FIXTURES = {'insert', 'name_getter', 'utf8_length', 'diagnostic_allocate', 'utf8_convert', 'log', 'free', 'security'}
CALL_ROLES = {91: 'insert', 193: 'utf8_length', 241: 'diagnostic_allocate', 275: 'utf8_convert',
              321: 'log', 343: 'free', 358: 'free', 370: 'security'}
LITERALS = {'empty_utf16': (158, b'\0\0'),
            'log_format': (293, b'invalid packetId( %d ), packetName( %s )\0'),
            'log_owner': (309, b'PacketDispatcher::_AddPacketHandler\0')}
META = {'schema', 'source', 'source_sha256', 'family', 'format', 'layout', 'exports', 'transfer_proof', 'release_id', 'provenance'}
BASE = {'bindings', 'window', 'functions', 'leaves', 'fixtures', 'fixture_boundaries', 'globals', 'literals',
        'call_sites', 'packet_bytes', 'packet_allocation_bytes', 'verify_whole_exports'}


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = module_from_spec(spec); spec.loader.exec_module(value); return value


def tools():
    return {**load('update-native-version-result').tools(), **{str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in (
        'login-registration-rules.py', 'update-native-archive-wire.py', 'update-native-contexts.py',
        'update-bindings.py', 'build-native-entry-code.py', 'extract-native-enums.py',
        'version-system-transfer-rules.py', 'audit-launcher-shape-11318.py')}}


def address(text):
    if not isinstance(text, str) or not re.fullmatch('0x[0-9a-f]+', text): raise ValueError('Registration address differs')
    return int(text, 16)


def pointer(p):
    if (not isinstance(p, dict) or set(p) != {'path', 'sha256'} or not isinstance(p['path'], str) or not p['path']
            or not isinstance(p['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', p['sha256'])):
        raise ValueError('Registration dependency pointer differs')
    return p


def functional(c):
    legacy = c.get('format') == LEGACY
    required = BASE | (set() if legacy else {'nested_context', 'full_handler_context'})
    if (set(c) - META != required or type(c.get('schema')) is not int or c['schema'] != 1
            or c.get('family') != FAMILY or c.get('format') not in (LEGACY, CURRENT)
            or not isinstance(c.get('source_sha256'), str) or not re.fullmatch('[0-9a-f]{64}', c['source_sha256'])
            or not isinstance(c.get('source'), str) or not c['source'] or c.get('verify_whole_exports') is not True
            or set(c.get('bindings', {})) != BINDINGS or set(c.get('functions', {})) != {'register'}
            or set(c.get('fixtures', {})) != FIXTURES or set(c.get('fixture_boundaries', {})) != FIXTURES
            or set(c.get('globals', {})) != {'cookie'} or set(c.get('literals', {})) != set(LITERALS)
            or set(c.get('call_sites', {})) != {'register'}):
        raise ValueError('Registration fields or bounded scope differ')
    if (type(c.get('packet_bytes')) is not int or type(c.get('packet_allocation_bytes')) is not int
            or (c['packet_bytes'], c['packet_allocation_bytes']) != ((320, 320) if legacy else (352, 344))
            or legacy and c['source_sha256'] != LEGACY_SHA):
        raise ValueError('Registration packet extent/allocation or legacy source differs')
    b = c['bindings']
    for at in (*b.values(), *c['functions'].values(), *c['fixtures'].values(), *c['globals'].values()): address(at)
    if (c['functions']['register'] != b['register'] or c['fixtures']['insert'] != b['insert']
            or c['fixtures']['name_getter'] != b['name_getter'] or c['leaves'] != {b['id_getter']: 'b804000000c3'}):
        raise ValueError('Registration source roles or ID leaf differ')
    window = c['window']
    if (set(window) != {'address', 'bytes', 'sha256'} or not isinstance(window['bytes'], str)
            or not re.fullmatch('[0-9a-f]{150}', window['bytes'])
            or hashlib.sha256(bytes.fromhex(window['bytes'])).hexdigest() != window['sha256']):
        raise ValueError('Registration window byte extent/hash differs')
    address(window['address'])
    for name, (_, expected) in LITERALS.items():
        if set(c['literals'][name]) != {'address', 'bytes'} or c['literals'][name]['bytes'] != expected.hex():
            raise ValueError('Registration typed literal differs')
        address(c['literals'][name]['address'])
    if not legacy:
        pointer(c['nested_context']); pointer(c['full_handler_context'])
        if c['nested_context'] == c['full_handler_context']: raise ValueError('Registration dependencies alias')
    return {key: copy.deepcopy(c[key]) for key in required}


def roots(c):
    functional(c); root = address(c['functions']['register']); leaf = address(c['bindings']['id_getter'])
    hooks = [address(at) for at in c['fixtures'].values()]
    if len(set(hooks)) != len(hooks) or root == leaf or {root, leaf} & set(hooks):
        raise ValueError('Registration fixture shadows native helper or ID leaf')
    return {root}


def data(image, at, size): return load('version-system-transfer-rules').image_bytes(image, at, size)


def calls(rows):
    return {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands'] for r in rows if r['call']}


def window(native, image, at, expected=None):
    """Verify the exact 75-byte owner slice, without executing the owner."""
    raw = data(image, at, 75); cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64); cs.detail = True
    rr = list(cs.disasm(raw, at))
    if len(rr) != 21 or sum(r.size for r in rr) != 75: raise ValueError('Registration window instruction boundary differs')
    target = lambda i: rr[i].operands[0].imm
    alloc, ctor, register = target(1), target(14), target(20)
    allocation = rr[9].operands[1].imm if len(rr[9].operands) == 2 else None
    shape = [(r.mnemonic, r.op_str) for r in rr]
    wanted = [('mov', 'ecx, 8'), ('call', hex(alloc)), ('mov', 'rdi, rax'), ('test', 'rax, rax'),
        ('je', hex(at+30)), ('lea', 'rax, [rip + ' + hex(rr[5].operands[1].mem.disp) + ']'),
        ('mov', 'qword ptr [rdi], rax'), ('jmp', hex(at+33)), ('mov', 'rdi, rbx'),
        ('mov', 'ecx, ' + hex(allocation) if allocation is not None else ''), ('call', hex(alloc)),
        ('test', 'rax, rax'), ('je', hex(at+58)), ('mov', 'rcx, rax'), ('call', hex(ctor)),
        ('jmp', hex(at+61)), ('mov', 'rax, rbx'), ('mov', 'r8, rdi'), ('mov', 'rdx, rax'), ('mov', 'rcx, rsi'), ('call', hex(register))]
    if shape != wanted: raise ValueError('Registration window argument/control shape differs')
    table = rr[5].address + rr[5].size + rr[5].operands[1].mem.disp
    part = image.containing(at)
    if part is None or image.containing(at+74) != part: raise ValueError('Registration window crosses its owner range')
    owner = image.pe.base + image.roots[part][0]
    value = dict(owner=hex(owner), allocate=hex(alloc), packet_constructor=hex(ctor), register=hex(register),
        handler_table=hex(table), handler=hex(struct.unpack('<Q', data(image, table+0x10, 8))[0]), packet_allocation_bytes=allocation)
    for name in ('packet_constructor', 'register'): load('version-system-transfer-rules').concrete(image, address(value[name]))
    # The allocation entry is a frameless leaf in the reviewed source. Its
    # caller identity is pinned, but neither allocation nor OOM is executed.
    fixture_boundary(image, alloc)
    if expected is not None and any(value[key] != expected[key] for key in value):
        raise ValueError('Registration window source binding/allocation differs')
    return value, dict(address=hex(at), bytes=raw.hex(), sha256=hashlib.sha256(raw).hexdigest())


def find_window(native, image, constructor):
    hits = []
    for section in image.pe.sections:
        if section['name'] != '.text': continue
        start, end = section['raw'], section['raw'] + section['raw_size']; cursor = start
        while True:
            cursor = image.data.find(b'\xe8', cursor, end)
            if cursor < 0: break
            if cursor + 5 <= end:
                at = image.pe.address(cursor)
                if at + 5 + struct.unpack_from('<i', image.data, cursor+1)[0] == constructor:
                    # A byte occurrence becomes a candidate only after all 21
                    # instructions, internal branches and source bindings pass.
                    try: value, span = window(native, image, at-51)
                    except (ValueError, IndexError, struct.error): pass
                    else: hits.append((value, span))
            cursor += 1
    if len(hits) != 1: raise ValueError('Registration constructor window missing or ambiguous')
    return hits[0]


def fixture_boundary(image, at):
    """Pin an unexecuted callee entry; its effects remain explicit fixtures."""
    utility = load('version-system-transfer-rules'); prefix = data(image, at, 16)
    section = next((s['name'] for s in image.pe.sections if s['rva'] <= at-image.pe.base < s['rva']+s['raw_size']), None)
    if section != '.text': raise ValueError('Registration fixture is not file-backed executable code')
    result = dict(kind='unexecuted-code-entry-fixture', prefix_bytes=prefix.hex(), section=section)
    part = image.containing(at)
    if part is not None:
        root = image.roots[part]
        if image.pe.base + root[0] != at: raise ValueError('Registration fixture enters an unwind interior')
        result['unwind'] = dict(begin=hex(image.pe.base+root[0]), end=hex(image.pe.base+root[1]))
    return result


def helper_parts(native, bindings, image, helper, packet_table, id_getter):
    rr = bindings.rows(native, image, helper)
    if len(rr) != 101 or sum(len(bytes.fromhex(r['bytes'])) for r in rr) != 395:
        raise ValueError('Registration helper whole instruction/byte boundary differs')
    by = {r['address']-helper: r for r in rr}; cc = [r for r in rr if r['call']]
    if len(cc) != 11: raise ValueError('Registration helper call inventory differs')
    for offset, operand in ((59, 'qword ptr [rax + 0x28]'), (126, 'qword ptr [rax + 0x38]'), (290, 'qword ptr [rax + 0x28]')):
        row = by.get(offset, {})
        if row.get('direct_target') is not None or row.get('call') is not True or row.get('operands') != operand:
            raise ValueError('Registration helper virtual ID/name slot differs')
    fixtures = {}
    for offset, role in CALL_ROLES.items():
        row = by.get(offset, {}); target = row.get('direct_target')
        if row.get('call') is not True or target is None or role in fixtures and fixtures[role] != hex(target):
            raise ValueError('Registration helper direct callee role differs')
        fixtures[role] = hex(target)
    fixtures['name_getter'] = hex(struct.unpack('<Q', data(image, packet_table+0x38, 8))[0])
    if struct.unpack('<Q', data(image, packet_table+0x28, 8))[0] != id_getter or data(image, id_getter, 6) != bytes.fromhex('b804000000c3'):
        raise ValueError('Registration packet table/ID source link differs')
    if set(r['address']-helper for r in rr if r['rip_references']) != {21, 158, 293, 309}:
        raise ValueError('Registration helper undeclared RIP input')
    if by.get(316, {}).get('bytes') != 'ba270b0000': raise ValueError('Registration logger source-line constant differs')
    cookie_row = by[21]
    if len(cookie_row['rip_references']) != 1: raise ValueError('Registration cookie RIP differs')
    cookie = cookie_row['rip_references'][0]
    if load('update-native-version-result').cookie_address(image) != cookie: raise ValueError('Registration load-config cookie link differs')
    literals = {}
    for role, (offset, expected) in LITERALS.items():
        refs = by[offset]['rip_references']
        if len(refs) != 1 or data(image, refs[0], len(expected)) != expected:
            raise ValueError('Registration logger/empty typed literal differs: ' + role)
        literals[role] = dict(address=hex(refs[0]), bytes=expected.hex())
    return rr, fixtures, dict(cookie=hex(cookie)), literals, {name: fixture_boundary(image, address(at)) for name, at in fixtures.items()}


def validate_static(native, bindings, image, c):
    roots(c); b = c['bindings']; expected = {key:b[key] for key in ('owner','allocate','packet_constructor','register','handler_table','handler')}
    expected['packet_allocation_bytes'] = c['packet_allocation_bytes']
    _, span = window(native, image, address(c['window']['address']), expected)
    if span != c['window']: raise ValueError('Registration stored window differs from source')
    rr, fixtures, globals_, literals, boundaries = helper_parts(native, bindings, image, address(b['register']), address(b['packet_table']), address(b['id_getter']))
    if (fixtures != c['fixtures'] or globals_ != c['globals'] or literals != c['literals'] or boundaries != c['fixture_boundaries']
            or calls(rr) != c['call_sites']['register']): raise ValueError('Registration helper typed source projection differs')
    return rr


def legacy(native, bindings, image, reviewed):
    """Create a provenance projection; this does not claim legacy native replay."""
    if reviewed['source_sha256'] != LEGACY_SHA: raise ValueError('Registration legacy projection source differs')
    b = copy.deepcopy(reviewed['bindings']); rr, fixtures, globals_, literals, boundaries = helper_parts(native, bindings, image, address(b['register']), address(b['packet_table']), address(b['id_getter']))
    b.update(insert=fixtures['insert'], name_getter=fixtures['name_getter'])
    c = dict(schema=1, family=FAMILY, format=LEGACY, source=reviewed['source'], source_sha256=LEGACY_SHA,
        bindings=b, window=copy.deepcopy(reviewed['window']), functions=dict(register=b['register']), leaves={b['id_getter']:'b804000000c3'},
        fixtures=fixtures, fixture_boundaries=boundaries, globals=globals_, literals=literals, call_sites=dict(register=calls(rr)),
        packet_bytes=320, packet_allocation_bytes=320, verify_whole_exports=True, exports=copy.deepcopy(reviewed['exports']))
    validate_static(native, bindings, image, c); return c


def transfer(native, bindings, before, after, baseline, mapping, nested, handler, *, nested_pointer, handler_pointer):
    old_rows = validate_static(native, bindings, before, baseline)
    if (nested.get('family') != 'login-nested' or handler.get('family') != 'login-full-handler'
            or nested['source_sha256'] != handler['source_sha256'] or Path(nested['source']).resolve() != Path(handler['source']).resolve()
            or nested.get('layout', {}).get('packet_bytes') != 352 or handler.get('packet_bytes') != 352
            or nested['packet_table'] != handler['packet_table'] or nested['id_getter'] != handler['id_getter']):
        raise ValueError('Registration independent packet/handler target differs')
    pointer(nested_pointer); pointer(handler_pointer)
    found, span = find_window(native, after, address(nested['functions']['constructor']))
    if found['handler'] != handler['functions']['handler'] or found['packet_allocation_bytes'] != 344:
        raise ValueError('Registration target handler table or actual allocation differs')
    b = {key:found[key] for key in ('owner','allocate','packet_constructor','register','handler_table','handler')}
    b.update(packet_table=nested['packet_table'], id_getter=nested['id_getter'])
    new_rows, fixtures, globals_, literals, boundaries = helper_parts(native, bindings, after, address(b['register']), address(b['packet_table']), address(b['id_getter']))
    b.update(insert=fixtures['insert'], name_getter=fixtures['name_getter'])
    common = load('update-native-archive-wire'); common.pair_rows(native, old_rows, new_rows, mapping)
    for key, value in baseline['bindings'].items(): common.add_link(mapping, address(value), address(b[key]))
    # Fixture roles are constrained by checked calls/table slots. Their entry
    # bytes are pinned to the target; their unexecuted effects are not equated.
    for role in FIXTURES: common.add_link(mapping, address(baseline['fixtures'][role]), address(fixtures[role]))
    cookie_before = data(before, address(baseline['globals']['cookie']), 8); cookie_after = data(after, address(globals_['cookie']), 8)
    if cookie_before != cookie_after: raise ValueError('Registration source security cookie initial bytes differ')
    c = dict(schema=1, family=FAMILY, format=CURRENT, source=nested['source'], source_sha256=nested['source_sha256'],
        bindings=b, window=span, functions=dict(register=b['register']), leaves={b['id_getter']:'b804000000c3'},
        fixtures=fixtures, fixture_boundaries=boundaries, globals=globals_, literals=literals, call_sites=dict(register=calls(new_rows)),
        packet_bytes=352, packet_allocation_bytes=344, verify_whole_exports=True,
        nested_context=copy.deepcopy(nested_pointer), full_handler_context=copy.deepcopy(handler_pointer))
    roots(c)
    return c, dict(method='whole_helper_and_static_registration_window', window_instruction_count=21, window_bytes=75,
        helper_instructions=101, helper_bytes=395, logger_line=0xb27, packet_storage_extent=352, packet_allocation_bytes=344,
        cookie_initial_bytes=cookie_after.hex(), window_executed=False, insert_executed=False, dispatch_executed=False,
        remaining_scope='Static null allocation branches do not prove safe allocation failure; actual insert, ownership, name getter and dispatch remain fixtures/unknowns')


def export_coverage(root, c, native, bindings, image):
    wanted = roots(c); rr = validate_static(native, bindings, image, c); actual_root = next(iter(wanted)); available = False
    exact = [(r['address'], r['bytes'].lower()) for r in rr]
    for run, expected in c.get('exports', {}).items():
        if not isinstance(run, str) or Path(run).name != run or not run.startswith('run-'): raise ValueError('Registration export name differs')
        path = Path(root)/'ghidra/request-exports'/c['source_sha256']/run/'details.json'; payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != expected: raise ValueError('Registration export hash changed')
        report = json.loads(payload)
        if report.get('new_source_sha256', report.get('source_sha256')) != c['source_sha256']: raise ValueError('Registration export source differs')
        for fn in report['functions']:
            if address(fn['address']) != actual_root: continue
            if any(fn.get(flag) is not True for flag in ('decompilation_completed','block_coverage_complete','direct_flow_coverage_complete')):
                raise ValueError('Registration helper export coverage flags differ')
            actual = [(address(row['address']), row['bytes'].lower()) for row in fn['instructions']]
            if len(actual) != len(set(at for at,_ in actual)) or sorted(actual) != sorted(exact):
                raise ValueError('Registration helper export exact instruction body differs')
            load('audit-launcher-shape-11318').normalize_function(native, image, fn); available = True
    if not available: raise ValueError('Registration export lacks complete helper root')
