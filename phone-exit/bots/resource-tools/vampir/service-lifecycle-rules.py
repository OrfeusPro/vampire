"""Typed source projection for sequential service/control/backend lifetime.

Only twelve whole roots and the control virtual-dispatch capsule execute.
Heap, engine/container/vector and callback effects remain named fixtures.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
FAMILY = 'service-lifecycle'
CURRENT = 'service-lifecycle-v1'
REFERENCE = 'reference-service-lifecycle'
META = {'schema', 'source', 'source_sha256', 'family', 'format', 'layout', 'exports',
        'transfer_proof', 'release_id', 'provenance'}
EXTENTS = dict(service_bytes=240, backend_bytes=800, control_bytes=24, callback_fixture_bytes=48)
SHAPES = {'service.publisher': (43, 214), 'service.assign': (87, 352),
    'control.move_release': (39, 123), 'control.deleting': (13, 43),
    'backend.constructor': (176, 823), 'backend.base_constructor': (119, 616),
    'service.deleting': (70, 285), 'backend.deleting': (16, 52),
    'backend.destructor': (149, 616), 'backend.base_destructor': (75, 372),
    'backend.reset': (126, 527), 'backend.string_ring_clear': (81, 294)}
DISPATCH = '488b49104885c9740b488b01ba0100000048ff20c3'
ALLOC_PREFIX = '4885c9b801000000ba10000000480f45c1488bc8e9'
FIELDS = set(EXTENTS) | {'functions', 'leaves', 'fixtures', 'call_sites', 'table_roles',
    'source_tables', 'source_globals', 'opaque_entries', 'backend_context', 'backend_check', 'verify_whole_exports'}
# Every direct call receives either an explicit native role or a named fixture.
CALL_ROLES = {
    'service.publisher': {0x22: 'service_init'},
    'service.assign': {0x17: 'allocate', 0x24: '@backend.constructor', 0x3e: 'allocate',
        0x8f: '@control.move_release', 0x119: 'callback_allocate', 0x135: 'callback_token'},
    'control.move_release': {}, 'control.deleting': {0x1d: 'sized_free'},
    'backend.constructor': {0x23: '@backend.base_constructor', 0x2f: 'observer_init', 0x49: 'observer_init',
        0xb1: 'derived_storage_init', 0x198: 'iterator_find', 0x1d7: 'reserve', 0x201: 'allocate',
        0x221: 'global_container', 0x272: 'iterator_find', 0x2be: 'reserve', 0x2e8: 'allocate'},
    'backend.base_constructor': {0x3d: 'allocate', 0x54: 'observer_init', 0x68: 'observer_init',
        0xdf: 'allocate', 0x11f: 'allocate', 0x17f: 'allocate',
        0x1f5: 'vector_init', 0x208: 'vector_init', 0x21b: 'vector_init'},
    'service.deleting': {0x3b: 'unsized_free', 0x56: 'unsized_free', 0x62: 'service_member_destroy',
        0x70: 'unsized_free', 0x85: 'unsized_free', 0x8e: 'service_container_destroy',
        0xd8: 'service_engine_destroy', 0x10f: 'sized_free'},
    'backend.deleting': {0xf: '@backend.destructor', 0x21: 'sized_free'},
    'backend.destructor': {0x5f: 'global_container', 0xb3: 'iterator_find', 0xf8: 'iterator_remove',
        0x144: 'iterator_find', 0x189: 'iterator_remove', 0x1bc: 'callback_resize',
        0x1d4: 'unsized_free', 0x209: 'unsized_free', 0x21a: 'unsized_free',
        0x226: 'vector_destroy', 0x232: 'observer_destroy', 0x23e: 'observer_destroy'},
    'backend.base_destructor': {0x33: '@backend.reset', 0x74: 'sized_free',
        0xa2: 'vector_destroy', 0xae: 'vector_destroy', 0xba: 'vector_destroy',
        0xc6: 'member_118_destroy', 0xd2: 'member_d0_destroy', 0xde: '@backend.string_ring_clear',
        0xfa: 'sized_free', 0x103: 'string_destroy', 0x10c: 'observer_destroy',
        0x115: 'observer_destroy', 0x136: 'list_clear', 0x14b: 'list_clear'},
    'backend.reset': {0x68: 'iterator_find', 0xad: 'iterator_remove',
        0xfe: 'iterator_find', 0x143: 'iterator_remove', 0x168: '!socket_provider', 0x177: '!socket_action'},
    'backend.string_ring_clear': {0x73: 'sized_free', 0xc4: 'sized_free', 0xfe: 'sized_free'},
}
INDIRECT = {'service.assign': {0xbf: 'qword ptr [rax]', 0xd5: 'qword ptr [rax + 8]'},
    'control.move_release': {0x43: 'qword ptr [rax]', 0x57: 'qword ptr [rax + 8]'},
    'service.deleting': {0xb8: 'qword ptr [rax]', 0xcc: 'qword ptr [rax + 8]'},
    'backend.destructor': {0x1a8: 'qword ptr [rax]', 0x1fa: 'qword ptr [rax + 0x10]'},
    'backend.base_destructor': {0x13d: '#invalid_parameter'},
    'backend.reset': {0x18c: 'qword ptr [rax + 0x28]'},
    'backend.string_ring_clear': {0x11f: '#invalid_parameter'}}
TABLE_ANCHORS = {
    'service.publisher': {0xa: 'service_base', 0x2c: 'service_primary', 0x36: 'service_secondary'},
    'service.assign': {0x59: 'control', 0xfb: 'callback_handler', 0x12b: 'callback_base', 0x143: 'callback'},
    'control.deleting': {0x6: 'control_base'},
    'backend.constructor': {0x34: 'derived_observer_initial', 0x51: 'backend_primary',
        0x62: 'derived_secondary38', 0x74: 'derived_secondary50',
        0x7f: 'derived_observer200', 0x8d: 'derived_observer218'},
    'backend.base_constructor': {0x1a: 'base_initial', 0x59: 'base_observer_initial',
        0x77: 'backend_base', 0x84: 'base_secondary38', 0x8f: 'base_secondary50', 0x9a: 'base_string',
        0xf8: 'base_initial', 0x13f: 'base_containerc8', 0x14d: 'base_initial',
        0x195: 'base_container110', 0x1a9: 'base_vector'},
    'service.deleting': {0xb: 'service_primary', 0x18: 'service_secondary', 0xe2: 'service_base'},
    'backend.destructor': {0x20: 'backend_primary', 0x2d: 'derived_secondary38',
        0x38: 'derived_secondary50', 0x43: 'derived_observer200', 0x51: 'derived_observer218'},
    'backend.base_destructor': {0x10: 'backend_base', 0x1d: 'base_secondary38',
        0x28: 'base_secondary50', 0x11e: 'base_initial'},
}
TABLE_ROLES = {name for values in TABLE_ANCHORS.values() for name in values.values()}
GLOBALS = {'service.publisher': {0x17: 'singleton'}, 'service.deleting': {0xfa: 'singleton'},
    'backend.base_destructor': {0x13d: 'invalid_parameter'}, 'backend.reset': {0x17c: 'provider'},
    'backend.string_ring_clear': {0x11f: 'invalid_parameter'}}
FIXTURES = {role for values in CALL_ROLES.values() for role in values.values() if not role.startswith(('@', '!'))} | {'callback_destroy'}
TAILS = {'backend.destructor': (0x263, '@backend.base_destructor'),
         'backend.base_destructor': (0x16f, 'sized_free'),
         'backend.reset': (0x20a, '@backend.string_ring_clear')}


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = module_from_spec(spec); spec.loader.exec_module(value); return value


def tools():
    names = ('service-lifecycle-rules.py', 'portable-native-family.py', 'login-dispatch-rules.py',
        'login-handler-transfer-rules.py', 'version-system-transfer-rules.py', 'login-state-flow-rules.py',
        'login-backend-wire-rules.py', 'login-backend-wire-source.py', 'audit-launcher-shape-11318.py',
        'knowledge-index.py', 'build-object-zero-init-code.py')
    return {**load('update-native-login-backend-wire').select('login-backend-wire').tools(),
        **{str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in names}}


def address(value):
    if not isinstance(value, str) or not re.fullmatch('0x[0-9a-f]+', value): raise ValueError('Lifecycle explicit address differs')
    return int(value, 16)


def pointer(value):
    if (not isinstance(value, dict) or set(value) != {'path', 'sha256'} or not isinstance(value['path'], str)
            or not value['path'] or not isinstance(value['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', value['sha256'])):
        raise ValueError('Lifecycle parent pointer differs')


def data(image, at, size): return load('version-system-transfer-rules').image_bytes(image, at, size)
def decode(native, image, at, size): return load('login-handler-transfer-rules').decode(native, image, at, size)
def at_row(rows, offset):
    row = next((r for r in rows if r['address'] == rows[0]['address'] + offset), None)
    if row is None: raise ValueError('Lifecycle source instruction anchor missing')
    return row


def functional(c):
    if (not isinstance(c, dict) or set(c) - META != FIELDS or type(c.get('schema')) is not int
            or c['schema'] != 1 or c.get('family') != FAMILY or c.get('format') not in (CURRENT, REFERENCE)
            or not isinstance(c.get('source'), str) or not c['source']
            or not isinstance(c.get('source_sha256'), str) or not re.fullmatch('[0-9a-f]{64}', c['source_sha256'])
            or c.get('verify_whole_exports') is not True
            or any(not isinstance(c.get(k), dict) for k in ('functions', 'leaves', 'fixtures', 'call_sites',
                'table_roles', 'source_tables', 'source_globals', 'opaque_entries'))
            or set(c['functions']) != set(SHAPES) or set(c['fixtures']) != FIXTURES
            or set(c['call_sites']) != set(SHAPES) or set(c['table_roles']) != TABLE_ROLES
            or set(c['source_globals']) != {'singleton', 'provider', 'invalid_parameter'}
            or set(c['opaque_entries']) != {'allocate', 'sized_free'}):
        raise ValueError('Lifecycle typed source fields/scope differ')
    for key, size in EXTENTS.items():
        if type(c[key]) is not int or c[key] != size: raise ValueError('Lifecycle extent differs: ' + key)
    for key in ('backend_context', 'backend_check'): pointer(c[key])
    for at in (*c['functions'].values(), *c['fixtures'].values(), *c['leaves'], *c['table_roles'].values()): address(at)
    table_widths = {address(at): 8 for role, at in c['table_roles'].items() if role != 'callback_handler'}
    for role, width in (('service_base', 48), ('service_primary', 80), ('control', 16), ('backend_primary', 32)):
        table_widths[address(c['table_roles'][role])] = width
    if {address(at) for at in c['source_tables']} != set(table_widths): raise ValueError('Lifecycle source table inventory differs')
    for at, raw in c['source_tables'].items():
        if not isinstance(raw, str) or not re.fullmatch('[0-9a-f]{%d}' % (table_widths[address(at)] * 2), raw):
            raise ValueError('Lifecycle source table extent differs')
    for role, spec in c['opaque_entries'].items():
        width = 25 if role == 'allocate' else 5
        if (not isinstance(spec, dict) or set(spec) != {'address', 'bytes'}
                or spec['address'] != c['fixtures'][role] or not isinstance(spec['bytes'], str)
                or not re.fullmatch('[0-9a-f]{%d}' % (width * 2), spec['bytes'])
                or not spec['bytes'].startswith(ALLOC_PREFIX if role == 'allocate' else 'e9')):
            raise ValueError('Lifecycle opaque entry extent/shape differs')
    for role, spec in c['source_globals'].items():
        if not isinstance(spec, dict): raise ValueError('Lifecycle global source span differs')
        required = {'address', 'size_bytes', 'storage', 'section'} | ({'bytes'} if spec.get('storage') == 'file' else set())
        if (not isinstance(spec, dict) or set(spec) != required or spec.get('storage') not in ('file', 'zero_fill')
                or type(spec.get('size_bytes')) is not int or spec['size_bytes'] != 8
                or not isinstance(spec.get('section'), dict)):
            raise ValueError('Lifecycle global source span differs')
        address(spec['address'])
        if spec['storage'] == 'file' and not re.fullmatch('[0-9a-f]{16}', spec.get('bytes', '')):
            raise ValueError('Lifecycle global source bytes differ')
    for sites in c['call_sites'].values():
        if not isinstance(sites, dict): raise ValueError('Lifecycle source call-site declaration differs')
        for at, target in sites.items():
            address(at)
            if not isinstance(target, str) or not target: raise ValueError('Lifecycle source call target differs')
    return {k: copy.deepcopy(v) for k, v in c.items() if k not in META}


def roots(c):
    functional(c)
    whole = {address(at) for at in c['functions'].values()}; leaves = {address(at) for at in c['leaves']}
    fixtures = {address(at) for at in c['fixtures'].values()}
    if ((len(whole), len(leaves), len(fixtures)) != (12, 1, len(FIXTURES))
            or list(c['leaves'].values()) != [DISPATCH] or whole & leaves or (whole | leaves) & fixtures):
        raise ValueError('Lifecycle exact twelve-root/dispatch/fixture inventory differs')
    return whole


def parents(root, c):
    core = load('portable-native-family'); api = load('update-native-login-backend-wire').select('login-backend-wire')
    backend = core.checked(root, c['backend_context'], 'generated-native-contexts')
    report = core.checked(root, c['backend_check'], 'native-adapter-checks')
    if (backend.get('family') != 'login-backend-wire' or not backend.get('transfer_proof')
            or backend.get('source_sha256') != c['source_sha256']
            or Path(backend['source']).resolve() != Path(c['source']).resolve()):
        raise ValueError('Lifecycle requires exact same-source proved backend parent')
    api.report_valid(report, backend, c['backend_context']['sha256'])
    return backend


def global_span(image, at):
    rva = at - image.pe.base
    found = [s for s in image.pe.sections if s['rva'] <= rva and rva + 8 <= s['rva'] + s['size']]
    if len(found) != 1: raise ValueError('Lifecycle global outside one PE span')
    section = found[0]
    if rva + 8 <= section['rva'] + section['raw_size']:
        return dict(address=hex(at), size_bytes=8, storage='file', section=copy.deepcopy(section), bytes=data(image, at, 8).hex())
    if section['name'] != '.data' or rva < section['rva'] + section['raw_size']:
        raise ValueError('Lifecycle global crosses file/zero-fill span')
    return dict(address=hex(at), size_bytes=8, storage='zero_fill', section=copy.deepcopy(section))


def dispatch_rows(native, image, at):
    """The exact capsule has an internal null return and a virtual terminal arm."""
    if image.containing(at) is not None or data(image, at, 21).hex() != DISPATCH:
        raise ValueError('Lifecycle exact control dispatch capsule differs')
    rr = decode(native, image, at, 21)
    expected = [('mov', 'rcx, qword ptr [rcx + 0x10]'), ('test', 'rcx, rcx'),
        ('je', hex(at + 20)), ('mov', 'rax, qword ptr [rcx]'), ('mov', 'edx, 1'),
        ('jmp', 'qword ptr [rax]'), ('ret', '')]
    if ([(r['mnemonic'], r['operands']) for r in rr] != expected
            or [r['address'] - at for r in rr] != [0, 4, 7, 9, 12, 17, 20]
            or rr[2]['direct_target'] != at + 20 or rr[5]['direct_target'] is not None
            or any(r['call'] or r['rip_references'] for r in rr)):
        raise ValueError('Lifecycle control dispatch decoded flow differs')
    return rr


def project(root, native, bindings, image, backend, backend_pointer, backend_check, functions, *, format=CURRENT):
    c = dict(schema=1, family=FAMILY, format=format, source=backend['source'], source_sha256=backend['source_sha256'],
        functions=copy.deepcopy(functions), backend_context=copy.deepcopy(backend_pointer),
        backend_check=copy.deepcopy(backend_check), verify_whole_exports=True, **EXTENTS)
    pointer(backend_pointer); pointer(backend_check)
    if parents(root, c) != backend: raise ValueError('Lifecycle supplied backend differs from checked parent')
    if set(functions) != set(SHAPES) or functions['service.publisher'] != backend['functions']['publisher']:
        raise ValueError('Lifecycle publisher parent binding differs')
    rows = {role: bindings.rows(native, image, address(at)) for role, at in functions.items()}
    fixtures, table_roles, globals_, excluded = {}, {}, {}, {}
    for role, rr in rows.items():
        if (len(rr), sum(len(bytes.fromhex(r['bytes'])) for r in rr)) != SHAPES[role]:
            raise ValueError('Lifecycle complete chained shape differs: ' + role)
        calls = {r['address'] - address(functions[role]) for r in rr if r['call']}
        if calls != set(CALL_ROLES[role]) | set(INDIRECT.get(role, {})):
            raise ValueError('Lifecycle complete source call inventory differs: ' + role)
        for offset, name in CALL_ROLES[role].items():
            r = at_row(rr, offset)
            if (r['direct_target'] is None or r['mnemonic'] != 'call' or len(bytes.fromhex(r['bytes'])) != 5 or not r['bytes'].startswith('e8')):
                raise ValueError('Lifecycle direct call anchor differs')
            at = hex(r['direct_target'])
            if name.startswith('@'):
                if at != functions[name[1:]]: raise ValueError('Lifecycle native call role differs')
            else:
                group = excluded if name.startswith('!') else fixtures
                if name in group and group[name] != at: raise ValueError('Lifecycle shared fixture target differs')
                group[name] = at
        for offset, expected in INDIRECT.get(role, {}).items():
            r = at_row(rr, offset)
            if r['direct_target'] is not None: raise ValueError('Lifecycle virtual call became direct')
            if expected != '#invalid_parameter' and r['operands'] != expected:
                raise ValueError('Lifecycle virtual slot/receiver differs')
            if expected == '#invalid_parameter' and len(r['rip_references']) != 1:
                raise ValueError('Lifecycle invalid-parameter IAT differs')
        for offset, name in TABLE_ANCHORS.get(role, {}).items():
            r = at_row(rr, offset)
            if r['mnemonic'] != 'lea' or len(r['rip_references']) != 1: raise ValueError('Lifecycle vptr/source pointer anchor differs')
            at = hex(r['rip_references'][0])
            if name in table_roles and table_roles[name] != at: raise ValueError('Lifecycle source table alias differs')
            table_roles[name] = at
        for offset, name in GLOBALS.get(role, {}).items():
            refs = at_row(rr, offset)['rip_references']
            if len(refs) != 1: raise ValueError('Lifecycle source global anchor differs')
            at = refs[0]
            if name in globals_ and globals_[name] != at: raise ValueError('Lifecycle global source alias differs')
            globals_[name] = at
        if {r['address'] - address(functions[role]) for r in rr if r['rip_references']} != set(TABLE_ANCHORS.get(role, {})) | set(GLOBALS.get(role, {})):
            raise ValueError('Lifecycle undeclared source RIP input')
    source_tables = {at: data(image, address(at), 8).hex() for role, at in table_roles.items() if role != 'callback_handler'}
    for role, width in (('service_base', 48), ('service_primary', 80), ('control', 16), ('backend_primary', 32)):
        at = table_roles[role]; source_tables[at] = data(image, address(at), width).hex()
    for at, encoded in source_tables.items():
        value, width = address(at) - image.pe.base, len(bytes.fromhex(encoded))
        if not any(s['name'] == '.rdata' and s['rva'] <= value and value + width <= s['rva'] + s['raw_size'] for s in image.pe.sections):
            raise ValueError('Lifecycle source table is not file-backed rdata')
    slot = lambda role, offset=0: hex(struct.unpack_from('<Q', bytes.fromhex(source_tables[table_roles[role]]), offset)[0])
    dispatch = slot('control'); fixtures['callback_destroy'] = slot('callback')
    if (slot('service_primary') != functions['service.deleting'] or slot('service_primary', 8) != functions['service.assign']
            or slot('control', 8) != functions['control.deleting'] or slot('backend_primary') != functions['backend.deleting']):
        raise ValueError('Lifecycle primary/control virtual source linkage differs')
    dispatch_rows(native, image, address(dispatch))
    for role, (offset, target) in TAILS.items():
        r = at_row(rows[role], offset); wanted = functions[target[1:]] if target.startswith('@') else fixtures[target]
        if (r['mnemonic'] != 'jmp' or r['direct_target'] != address(wanted) or not r['bytes'].startswith('e9')
                or len(bytes.fromhex(r['bytes'])) != 5): raise ValueError('Lifecycle terminal native/fixture tail differs')
    for role, rr in rows.items():
        local = {r['address'] for r in rr}
        external = [r for r in rr if r['branch'] and r['direct_target'] not in local]
        if len(external) != (1 if role in TAILS else 0): raise ValueError('Lifecycle undeclared external branch')
    entries = {role: dict(address=fixtures[role], bytes=data(image, address(fixtures[role]), width).hex())
               for role, width in (('allocate', 25), ('sized_free', 5))}
    for role, width in (('allocate', 25), ('sized_free', 5)):
        at = address(fixtures[role]); rr = decode(native, image, at, width)
        if (image.containing(at) is not None or len(rr) != (6 if role == 'allocate' else 1)
                or rr[-1]['mnemonic'] != 'jmp' or rr[-1]['direct_target'] is None):
            raise ValueError('Lifecycle opaque heap entry boundary differs')
        if role == 'sized_free' and rr[-1]['direct_target'] != address(fixtures['unsized_free']):
            raise ValueError('Lifecycle sized/unsized free source target differs')
    imported = load('build-object-zero-init-code').import_at(image.data, image, globals_['invalid_parameter'])
    if (imported['dll'].lower(), imported['name']) != ('api-ms-win-crt-runtime-l1-1-0.dll', '_invalid_parameter_noinfo_noreturn'):
        raise ValueError('Lifecycle excluded invalid-parameter named import differs')
    c.update(leaves={dispatch: DISPATCH}, fixtures=fixtures, table_roles=table_roles, source_tables=source_tables,
        source_globals={role: global_span(image, at) for role, at in globals_.items()}, opaque_entries=entries,
        call_sites={role: {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
                          for r in rr if r['call']} for role, rr in rows.items()})
    roots(c)
    if (table_roles['service_base'] != backend['service']['initial_table']
            or table_roles['service_primary'] != backend['service']['primary_table']
            or table_roles['service_secondary'] != backend['service']['secondary_table']
            or fixtures['service_init'] != backend['service']['helper']
            or c['source_globals']['singleton']['address'] != backend['source_inputs']['service_global']['address']
            or any(source_tables[table_roles[role]] != backend['source_inputs'][key]['bytes'] for role, key in
                (('service_base', 'service_initial_table'), ('service_primary', 'service_primary_table'), ('service_secondary', 'service_secondary_table')))):
        raise ValueError('Lifecycle accepted publisher/service table provenance differs')
    spans = [(r['address'], r['address'] + len(bytes.fromhex(r['bytes']))) for rr in rows.values() for r in rr] + [(address(dispatch), address(dispatch) + 21)]
    for at in (*fixtures.values(), *excluded.values()):
        value = address(at)
        if any(lo <= value < hi for lo, hi in spans): raise ValueError('Lifecycle fixture/excluded target shadows native instruction')
        section = next((s for s in image.pe.sections if s['rva'] <= value - image.pe.base < s['rva'] + s['raw_size']), None)
        if section is None or section['name'] != '.text': raise ValueError('Lifecycle fixture is not file-backed code')
    if {address(x) for x in excluded.values()} & {address(x) for x in fixtures.values()}:
        raise ValueError('Lifecycle excluded socket effect aliases allowed fixture')
    return c, rows


def validate_static(root, native, bindings, image, c):
    roots(c); backend = parents(root, c)
    candidate, rows = project(root, native, bindings, image, backend, c['backend_context'], c['backend_check'], c['functions'], format=c['format'])
    if functional(candidate) != functional(c): raise ValueError('Lifecycle typed source projection differs')
    return rows


def transfer(root, native, bindings, before, after, baseline, mapping, backend, *, backend_pointer, backend_check):
    old = validate_static(root, native, bindings, before, baseline)
    common, pairing = load('update-native-archive-wire'), load('login-backend-wire-rules')
    functions = {role: hex(common.unique_root(native, bindings, before, after, address(baseline['functions'][role])))
                 for role in SHAPES if role != 'service.publisher'}
    functions['service.publisher'] = backend['functions']['publisher']
    c, new = project(root, native, bindings, after, backend, backend_pointer, backend_check, functions)
    for group in ('functions', 'fixtures', 'table_roles'):
        for role, at in baseline[group].items(): common.add_link(mapping, address(at), address(c[group][role]))
    for role, rr in old.items():
        target = TAILS.get(role, (None, None))[1]
        tail = baseline['functions'][target[1:]] if target and target.startswith('@') else baseline['fixtures'][target] if target else None
        pairing.pair_rows(native, rr, new[role], mapping, declared_tails={address(tail)} if tail else ())
    a, b = next(iter(baseline['leaves'])), next(iter(c['leaves']))
    # This capsule's virtual arm precedes its null RET. Generic returning-leaf
    # or last-instruction-only virtual-tail validators cannot describe it.
    ar, br = dispatch_rows(native, before, address(a)), dispatch_rows(native, after, address(b))
    for x, y in zip(ar, br): common.add_link(mapping, x['address'], y['address'])
    for role in ('allocate', 'sized_free'):
        a, b = baseline['opaque_entries'][role], c['opaque_entries'][role]
        ar = decode(native, before, address(a['address']), len(bytes.fromhex(a['bytes'])))
        br = decode(native, after, address(b['address']), len(bytes.fromhex(b['bytes'])))
        pairing.pair_rows(native, ar, br, mapping, declared_tails={ar[-1]['direct_target']})
    for role, span in baseline['source_globals'].items():
        target = c['source_globals'][role]
        common.add_link(mapping, address(span['address']), address(target['address']))
        if (span['size_bytes'], span['storage'], span['section']['name']) != (target['size_bytes'], target['storage'], target['section']['name']):
            raise ValueError('Lifecycle global storage kind changed')
    for role in sorted(TABLE_ROLES - {'callback_handler'}):
        a, b = baseline['table_roles'][role], c['table_roles'][role]
        av, bv = bytes.fromhex(baseline['source_tables'][a]), bytes.fromhex(c['source_tables'][b])
        if len(av) != len(bv): raise ValueError('Lifecycle table source extent changed')
        aa, bb = struct.unpack('<' + 'Q' * (len(av) // 8), av), struct.unpack('<' + 'Q' * (len(bv) // 8), bv)
        for i, (x, y) in enumerate(zip(aa, bb)):
            if any((x == aa[j]) != (y == bb[j]) for j in range(i)): raise ValueError('Lifecycle table alias topology changed')
            common.add_link(mapping, x, y)
    return c, dict(method='native_service_assignment_refcontrol_primary_lifecycle', whole_roots=12,
        control_dispatch_capsules=1, opaque_native_capsules=0, whole_shapes={k: list(v) for k, v in SHAPES.items()},
        native_allocator=False, native_engine_containers=False, native_callback_lifetime=False,
        native_vector_storage=False, native_socket=False, concurrent_references=False, session_executed=False)


def export_coverage(root, c, native, bindings, image):
    rows = validate_static(root, native, bindings, image, c)
    needed = {address(c['functions'][role]): rr for role, rr in rows.items()}; seen = set()
    if not isinstance(c.get('exports'), dict) or not 1 <= len(c['exports']) <= 8: raise ValueError('Lifecycle export count differs')
    for run, sha in c['exports'].items():
        if not isinstance(run, str) or Path(run).name != run or not run.startswith('run-'): raise ValueError('Lifecycle export run differs')
        path = Path(root) / 'ghidra/request-exports' / c['source_sha256'] / run / 'details.json'
        if hashlib.sha256(path.read_bytes()).hexdigest() != sha: raise ValueError('Lifecycle export SHA differs')
        report = json.loads(path.read_text('utf-8'))
        if report.get('new_source_sha256', report.get('source_sha256')) != c['source_sha256']: raise ValueError('Lifecycle export source differs')
        for fn in report['functions']:
            at = address(fn['address'])
            if at not in needed: continue
            load('login-backend-wire-source').check_coverage(dict(functions=[fn]), at, needed[at])
            load('audit-launcher-shape-11318').normalize_function(native, image, fn)
            seen.add(at)
    if seen != set(needed): raise ValueError('Lifecycle exports lack twelve complete whole roots')
