"""Typed source projection for bounded resize, queue and transport ownership.

Allocation/CRT effects remain explicit fixtures. Five whole roots, including the
vector growth body, and the source set-count leaf enter the native inventory.
Opaque allocator/free entry capsules are pinned data and never execute.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
FAMILY = 'buffer-transport'
CURRENT = 'buffer-transport-v1'
REFERENCE = 'reference-buffer-transport'
META = {'schema', 'source', 'source_sha256', 'family', 'format', 'layout', 'exports',
        'transfer_proof', 'release_id', 'provenance'}
EXTENTS = dict(vector_bytes=24, queue_bytes=32, archive_bytes=64, transport_bytes=400)
ROLES = {'archive.raw', 'vector.resize', 'vector.grow', 'queue.append', 'transport'}
HELPERS = {'allocate', 'free', 'memcpy', 'memmove', 'memset'}
INPUTS = {'archive_table', 'allocation_entry', 'free_entry'}
FIELDS = set(EXTENTS) | {'functions', 'leaves', 'helpers', 'call_sites', 'source_inputs',
    'wire_context', 'wire_check', 'verify_whole_exports'}
SHAPES = {'vector.resize': (39, 130), 'vector.grow': (88, 326),
          'queue.append': (38, 140), 'transport': (29, 103)}
CALLS = {'vector.resize': {0x65}, 'vector.grow': {0x5b, 0xa2, 0xba, 0xcc, 0x101, 0x133, 0x13a, 0x140},
    'queue.append': {0x3b, 0x4d, 0x62}, 'transport': {0x10, 0x26, 0x2e, 0x5c},
    'archive.raw': {0x56, 0x71, 0x81}}
ABI = {
    'vector.resize': {0xf: '488b7108', 0x16: '488b11', 0x1f: '482bca', 0x2f: '488b4710',
        0x3b: '4c8d442430', 0x40: '488bd3', 0x43: '488bcf', 0x5a: '482bd9',
        0x5d: '33d2', 0x5f: '4c8bc3', 0x62: '488bce', 0x6e: '48894708'},
    'vector.grow': {0x39: '4c2b31', 0x9f: '488bcb', 0xb1: '4a8d0c37',
        0xb5: '4d2bc6', 0xb8: '33d2', 0xbf: '488b16', 0xc2: '488bcf',
        0xc5: '4c8b4608', 0xc9: '4c2bc2'},
    'queue.append': {0x1a: '488b4108', 0x21: '488b7910', 0x28: '4883c108',
        0x2c: '4d63f0', 0x34: '418d4001', 0x38: '4863d0', 0x49: '498d143e',
        0x56: '48ffc9', 0x59: '4803cf', 0x5c: '4d8bc6', 0x5f: '488bd5',
        0x7f: 'c640ff00', 0x83: 'b001'},
    'transport': {0x9: '4881c170010000', 0x15: '84c0', 0x33: '32c0',
        0x3b: '83bb0801000001', 0x44: '83bbc000000000', 0x4d: '488b4350',
        0x51: '488d4b50', 0x55: '488d9310010000', 0x5c: 'ff5020', 0x5f: 'b001'},
}
ALLOC_PREFIX = '4885c9b801000000ba10000000480f45c1488bc8e9'
SET_COUNT = '895108c3'


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec); spec.loader.exec_module(module); return module


def tools():
    names = ('buffer-transport-rules.py', 'portable-native-family.py',
        'login-handler-transfer-rules.py', 'version-system-transfer-rules.py',
        'login-backend-wire-rules.py', 'login-backend-wire-source.py', 'login-dispatch-rules.py',
        'audit-launcher-shape-11318.py', 'knowledge-index.py')
    return {**load('update-native-archive-wire').tools(),
        **{str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in names}}


def address(value):
    if not isinstance(value, str) or not re.fullmatch('0x[0-9a-f]+', value):
        raise ValueError('Buffer transport explicit address differs')
    return int(value, 16)


def pointer(value):
    if (not isinstance(value, dict) or set(value) != {'path', 'sha256'}
            or not isinstance(value['path'], str) or not value['path']
            or not isinstance(value['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', value['sha256'])):
        raise ValueError('Buffer transport parent pointer differs')


def data(image, at, size):
    return load('version-system-transfer-rules').image_bytes(image, at, size)


def decode(native, image, at, size):
    return load('login-handler-transfer-rules').decode(native, image, at, size)


def functional(c):
    objects = ('functions', 'leaves', 'helpers', 'call_sites', 'source_inputs')
    if (not isinstance(c, dict) or set(c) - META != FIELDS
            or any(not isinstance(c.get(k), dict) for k in objects)
            or type(c.get('schema')) is not int or c['schema'] != 1 or c.get('family') != FAMILY
            or c.get('format') not in (CURRENT, REFERENCE) or c.get('verify_whole_exports') is not True
            or not isinstance(c.get('source'), str) or not c['source']
            or not isinstance(c.get('source_sha256'), str) or not re.fullmatch('[0-9a-f]{64}', c['source_sha256'])
            or set(c['functions']) != ROLES or set(c['helpers']) != HELPERS
            or set(c['call_sites']) != ROLES or set(c['source_inputs']) != INPUTS):
        raise ValueError('Buffer transport typed fields/source/scope differ')
    for key, size in EXTENTS.items():
        if type(c[key]) is not int or c[key] != size:
            raise ValueError('Buffer transport extent differs: ' + key)
    for key in ('wire_context', 'wire_check'): pointer(c[key])
    for at in (*c['functions'].values(), *c['helpers'].values(), *c['leaves']): address(at)
    for role, sites in c['call_sites'].items():
        if not isinstance(sites, dict): raise ValueError('Buffer transport call sites differ')
        for at, target in sites.items():
            address(at)
            # The single wake slot and excluded invalid-parameter IAT are the
            # only indirect source calls. Project rechecks their decoded text.
            direct_call = isinstance(target, str) and re.fullmatch('0x[0-9a-f]+', target)
            wake = role == 'transport' and address(at) == address(c['functions'][role]) + 0x5c and target == 'qword ptr [rax + 0x20]'
            invalid = (role == 'vector.grow' and address(at) == address(c['functions'][role]) + 0x133
                and isinstance(target, str) and re.fullmatch(r'qword ptr \[rip \+ 0x[0-9a-f]+\]', target))
            if not (direct_call or wake or invalid): raise ValueError('Buffer transport call target differs')
    for key, item in c['source_inputs'].items():
        if (not isinstance(item, dict) or set(item) != {'address', 'bytes'}
                or not isinstance(item['bytes'], str) or not re.fullmatch('(?:[0-9a-f]{2})+', item['bytes'])):
            raise ValueError('Buffer transport source input differs')
        address(item['address'])
        size = {'archive_table': 248, 'allocation_entry': 25, 'free_entry': 5}[key]
        if len(bytes.fromhex(item['bytes'])) != size:
            raise ValueError('Buffer transport source input extent differs')
    if (not c['source_inputs']['allocation_entry']['bytes'].startswith(ALLOC_PREFIX)
            or not c['source_inputs']['free_entry']['bytes'].startswith('e9')
            or c['source_inputs']['allocation_entry']['address'] != c['helpers']['allocate']
            or c['source_inputs']['free_entry']['address'] != c['helpers']['free']):
        raise ValueError('Buffer transport opaque source entry differs')
    return {k: copy.deepcopy(v) for k, v in c.items() if k not in META}


def roots(c):
    functional(c)
    whole = {address(at) for at in c['functions'].values()}
    leaves = {address(at) for at in c['leaves']}
    helpers = {address(at) for at in c['helpers'].values()}
    if ((len(whole), len(leaves), len(helpers)) != (5, 1, 5)
            or list(c['leaves'].values()) != [SET_COUNT]
            or whole & leaves or (whole | leaves) & helpers):
        raise ValueError('Buffer transport exact five-root/one-leaf inventory or helper alias differs')
    return whole


def parents(root, c):
    core, api = load('portable-native-family'), load('update-native-archive-wire')
    wire = core.checked(root, c['wire_context'], 'generated-native-contexts')
    report = core.checked(root, c['wire_check'], 'native-adapter-checks')
    if (wire.get('family') != 'archive-wire' or not wire.get('transfer_proof')
            or wire.get('source_sha256') != c['source_sha256']
            or Path(wire['source']).resolve() != Path(c['source']).resolve()):
        raise ValueError('Buffer transport requires exact same-source proved wire')
    api.report_valid(report, wire, c['wire_context']['sha256'])
    return wire


def at_row(rows, offset):
    row = next((r for r in rows if r['address'] == rows[0]['address'] + offset), None)
    if row is None: raise ValueError('Buffer transport source anchor missing')
    return row


def direct(rows, offset, *, jump=False):
    row = at_row(rows, offset)
    if (row['direct_target'] is None or row['call'] is not (not jump)
            or row['branch'] is not jump or row['mnemonic'] != ('jmp' if jump else 'call')
            or len(bytes.fromhex(row['bytes'])) != 5 or not row['bytes'].startswith('e9' if jump else 'e8')):
        raise ValueError('Buffer transport source direct-call/tail anchor differs')
    return hex(row['direct_target'])


def import_identity(image, at, name):
    raw = data(image, at, 6)
    if raw[:2] != bytes.fromhex('ff25'): raise ValueError('Buffer transport helper is not an import thunk')
    slot = at + 6 + struct.unpack_from('<i', raw, 2)[0]
    found = load('build-object-zero-init-code').import_at(image.data, image, slot)
    if (found['dll'].lower(), found['name']) != ('vcruntime140.dll', name):
        raise ValueError('Buffer transport named CRT import differs: ' + name)


def project(root, native, bindings, image, wire, wire_pointer, wire_check, functions, *, format=CURRENT):
    """Project only declared roles; parent wire supplies raw/leaf/table provenance."""
    c = dict(schema=1, family=FAMILY, format=format, source=wire['source'], source_sha256=wire['source_sha256'],
        functions=copy.deepcopy(functions), wire_context=copy.deepcopy(wire_pointer),
        wire_check=copy.deepcopy(wire_check), verify_whole_exports=True, **EXTENTS)
    pointer(wire_pointer); pointer(wire_check)
    if (set(functions) != ROLES or functions['archive.raw'] != wire['archive']['raw']
            or functions['vector.resize'] != wire['archive']['growth']):
        raise ValueError('Buffer transport source raw/resize parent binding differs')
    if parents(root, c) != wire:
        raise ValueError('Buffer transport supplied wire differs from its checked pointer')
    rows = {role: bindings.rows(native, image, address(at)) for role, at in functions.items()}
    for role, rr in rows.items():
        if role in SHAPES and (len(rr), sum(len(bytes.fromhex(r['bytes'])) for r in rr)) != SHAPES[role]:
            raise ValueError('Buffer transport complete chained root shape differs: ' + role)
        if {r['address'] - address(functions[role]) for r in rr if r['call']} != CALLS[role]:
            raise ValueError('Buffer transport exact source call inventory differs: ' + role)
        for offset, encoded in ABI.get(role, {}).items():
            if at_row(rr, offset)['bytes'] != encoded:
                raise ValueError('Buffer transport source ABI anchor differs: ' + role)
    resize, grow, queue, transport, raw = (rows[k] for k in ('vector.resize', 'vector.grow', 'queue.append', 'transport', 'archive.raw'))
    helpers = dict(allocate=direct(grow, 0x5b), free=direct(grow, 0x101),
        memcpy=direct(queue, 0x62), memmove=direct(grow, 0xcc), memset=direct(resize, 0x65))
    if (direct(grow, 0xa2) != helpers['allocate'] or direct(grow, 0xba) != helpers['memset']
            or direct(resize, 0x55, jump=True) != functions['vector.grow']
            or any(direct(queue, off) != functions['vector.resize'] for off in (0x3b, 0x4d))
            or direct(transport, 0x10) != functions['queue.append']
            or direct(raw, 0x56) != functions['vector.resize'] or direct(raw, 0x71) != helpers['memcpy']
            or wire['helpers']['memcpy'] != helpers['memcpy']):
        raise ValueError('Buffer transport shared source helper/consumer edge differs')
    set_count = wire['archive_helpers']['set_count_leaf']
    if direct(raw, 0x81) != set_count or data(image, address(set_count), 4).hex() != SET_COUNT:
        raise ValueError('Buffer transport source set-count binding differs')
    spec = wire['archive_leaves'].get(set_count, {})
    if (spec.get('bytes') != SET_COUNT or spec.get('size') != 4
            or spec.get('sha256') != hashlib.sha256(bytes.fromhex(SET_COUNT)).hexdigest()
            or image.containing(address(set_count)) is not None):
        raise ValueError('Buffer transport source set-count capsule differs')
    for role in ('memcpy', 'memmove', 'memset'): import_identity(image, address(helpers[role]), role)
    source_inputs = {name: dict(address=hex(at), bytes=data(image, at, size).hex()) for name, at, size in (
        ('archive_table', address(wire['archive']['table']), 248),
        ('allocation_entry', address(helpers['allocate']), 25), ('free_entry', address(helpers['free']), 5))}
    if (hashlib.sha256(bytes.fromhex(source_inputs['archive_table']['bytes'])).hexdigest() != wire['archive_table_sha256']
            or struct.unpack_from('<Q', bytes.fromhex(source_inputs['archive_table']['bytes']), 0x88)[0] != address(functions['archive.raw'])):
        raise ValueError('Buffer transport archive table raw slot differs')
    c.update(helpers=helpers, leaves={set_count: SET_COUNT}, source_inputs=source_inputs,
        call_sites={role: {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
                          for r in rr if r['call']} for role, rr in rows.items()})
    roots(c)
    spans = [(r['address'], r['address'] + len(bytes.fromhex(r['bytes']))) for rr in rows.values() for r in rr]
    spans.append((address(set_count), address(set_count) + 4))
    for at in helpers.values():
        value = address(at)
        section = next((s for s in image.pe.sections if s['rva'] <= value - image.pe.base < s['rva'] + s['raw_size']), None)
        if section is None or section['name'] != '.text':
            raise ValueError('Buffer transport helper entry is not file-backed code')
        if any(lo <= value < hi for lo, hi in spans): raise ValueError('Buffer helper shadows native instructions')
    for key, size in (('allocation_entry', 25), ('free_entry', 5)):
        item = source_inputs[key]; at = address(item['address']); rr = decode(native, image, at, size)
        if image.containing(at) is not None or rr[-1]['mnemonic'] != 'jmp' or rr[-1]['direct_target'] is None:
            raise ValueError('Buffer transport opaque entry boundary differs')
    excluded = [direct(grow, off) for off in (0x13a, 0x140)] + [direct(transport, off) for off in (0x26, 0x2e)]
    if {address(at) for at in excluded} & (roots(c) | {address(set_count)} | {address(at) for at in helpers.values()}):
        raise ValueError('Buffer transport excluded error edge aliases admitted code')
    return c, rows


def validate_static(root, native, bindings, image, c):
    roots(c); wire = parents(root, c)
    candidate, rows = project(root, native, bindings, image, wire, c['wire_context'], c['wire_check'],
        c['functions'], format=c['format'])
    if functional(candidate) != functional(c): raise ValueError('Buffer transport typed source projection differs')
    return rows


def transfer(root, native, bindings, before, after, baseline, mapping, wire, *, wire_pointer, wire_check):
    old = validate_static(root, native, bindings, before, baseline)
    common, pairing = load('update-native-archive-wire'), load('login-backend-wire-rules')
    functions = {role: hex(common.unique_root(native, bindings, before, after, address(baseline['functions'][role])))
                 for role in sorted(ROLES - {'archive.raw'})}
    functions['archive.raw'] = wire['archive']['raw']
    c, new = project(root, native, bindings, after, wire, wire_pointer, wire_check, functions)
    for role in sorted(ROLES):
        common.add_link(mapping, address(baseline['functions'][role]), address(c['functions'][role]))
    for role in sorted(HELPERS): common.add_link(mapping, address(baseline['helpers'][role]), address(c['helpers'][role]))
    for role in sorted(ROLES):
        pairing.pair_rows(native, old[role], new[role], mapping,
            declared_tails={address(baseline['functions']['vector.grow'])} if role == 'vector.resize' else ())
    a, b = next(iter(baseline['leaves'])), next(iter(c['leaves']))
    pairing.pair_rows(native, decode(native, before, address(a), 4), decode(native, after, address(b), 4), mapping)
    for key in ('allocation_entry', 'free_entry'):
        aa, bb = baseline['source_inputs'][key], c['source_inputs'][key]
        ar = decode(native, before, address(aa['address']), len(bytes.fromhex(aa['bytes'])))
        br = decode(native, after, address(bb['address']), len(bytes.fromhex(bb['bytes'])))
        pairing.pair_rows(native, ar, br, mapping, declared_tails={ar[-1]['direct_target']})
    aa, bb = baseline['source_inputs']['archive_table'], c['source_inputs']['archive_table']
    common.add_link(mapping, address(aa['address']), address(bb['address']))
    av, bv = struct.unpack('<31Q', bytes.fromhex(aa['bytes'])), struct.unpack('<31Q', bytes.fromhex(bb['bytes']))
    for i, (a, b) in enumerate(zip(av, bv)):
        if any((a == av[j]) != (b == bv[j]) for j in range(i)):
            raise ValueError('Buffer transport archive table alias topology changed')
        common.add_link(mapping, a, b)
    return c, dict(method='native_resize_growth_queue_transport_archive_raw', whole_roots=5,
        returning_leaves=1, tail_fragments=0, whole_shapes={k: list(v) for k, v in SHAPES.items()},
        native_allocator=False, native_socket=False, native_drain=False, native_backend_lifetime=False,
        native_writer=False, session_executed=False)


def export_coverage(root, c, native, bindings, image):
    rows = validate_static(root, native, bindings, image, c)
    needed = {address(c['functions'][role]): rr for role, rr in rows.items()}; seen = set()
    if not isinstance(c.get('exports'), dict) or not 1 <= len(c['exports']) <= 8:
        raise ValueError('Buffer transport export count differs')
    for run, sha in c['exports'].items():
        if not isinstance(run, str) or Path(run).name != run or not run.startswith('run-'):
            raise ValueError('Buffer transport export run differs')
        path = Path(root) / 'ghidra/request-exports' / c['source_sha256'] / run / 'details.json'
        if hashlib.sha256(path.read_bytes()).hexdigest() != sha: raise ValueError('Buffer transport export SHA differs')
        report = json.loads(path.read_text('utf-8'))
        if report.get('new_source_sha256', report.get('source_sha256')) != c['source_sha256']:
            raise ValueError('Buffer transport export source differs')
        for function in report['functions']:
            at = address(function['address'])
            if at not in needed: continue
            load('login-backend-wire-source').check_coverage(dict(functions=[function]), at, needed[at])
            load('audit-launcher-shape-11318').normalize_function(native, image, function)
            seen.add(at)
    if seen != set(needed): raise ValueError('Buffer transport exports lack five complete whole roots')
