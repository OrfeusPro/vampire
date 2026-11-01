"""Typed source projection for real CRC/XOR and bounded Login frame delivery."""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
FAMILY = 'frame-integrity'
CURRENT = 'frame-integrity-v1'
REFERENCE = 'reference-frame-integrity'
META = {'schema', 'source', 'source_sha256', 'family', 'format', 'layout', 'exports',
        'transfer_proof', 'release_id', 'provenance'}
EXTENTS = dict(packet_bytes=320, backend_bytes=784, archive_bytes=64)
INPUTS = {'archive_flags', 'archive_table', 'cleanup_wrapper_table', 'cleanup_table',
          'cleanup_base_table', 'cleanup_final_table', 'gate', 'diagnostic_pointer'}
FIELDS = set(EXTENTS) | {'functions', 'leaves', 'tails', 'helpers', 'call_sites',
    'backend_context', 'wire_context', 'backend', 'source_inputs', 'integrity', 'verify_whole_exports'}
PRIMITIVES = {'initializer': ('checksum_init', 0xe4, 10),
              'update': ('checksum', 0x12c, 55), 'transform': ('transform', 0x173, 84)}
INITIALIZER = 'c701ffffffff488bc1c3'
CRC_NORMAL = '4c8bd14585c074294c8d1d00000000900fb602488d5201458b0a4933c141c1e9080fb6c845330c8b45890a4183c0ff75df418b02f7d0c3'
TRANSFORM = '4d85c948b8a78420d0c978b39a4c8bd14c0f44c84c894c242085d27e344533c98bca4d2bd06666660f1f840000000000498bc14d8d400183e00749ffc10fb644042043324402ff418840ff4883e90175df8bc2c3'
FALLBACK_KEY = 0x9ab378c9d02084a7


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tools():
    names = ('frame-integrity-rules.py', 'login-backend-wire-rules.py',
        'login-backend-wire-source.py', 'login-dispatch-rules.py',
        'login-handler-transfer-rules.py', 'update-native-archive-wire.py',
        'update-native-contexts.py', 'audit-launcher-shape-11318.py')
    return {str(HERE/n): hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in names}


def address(v): return load('login-dispatch-rules').address(v)
def data(image, at, size): return load('login-dispatch-rules').data(image, at, size)
def decode(native, image, at, size): return load('login-handler-transfer-rules').decode(native, image, at, size)


def role_names():
    return load('login-backend-wire-rules').WIRE_FUNCTIONS | {'backend', 'wire.append', 'wire.cleanup'}


def functional(c):
    objects = ('functions', 'leaves', 'tails', 'helpers', 'call_sites', 'backend', 'source_inputs', 'integrity')
    parent = load('login-backend-wire-rules')
    if (not isinstance(c, dict) or set(c)-META != FIELDS
            or any(not isinstance(c.get(k), dict) for k in objects)
            or type(c.get('schema')) is not int or c['schema'] != 1 or c.get('family') != FAMILY
            or c.get('format') not in (CURRENT, REFERENCE)
            or not isinstance(c.get('source'), str) or not c['source']
            or not isinstance(c.get('source_sha256'), str) or not re.fullmatch('[0-9a-f]{64}', c['source_sha256'])
            or c.get('verify_whole_exports') is not True or set(c['backend']) != parent.BACKEND
            or set(c['helpers']) != {'memcpy'} or set(c['call_sites']) != role_names()
            or set(c['source_inputs']) != INPUTS):
        raise ValueError('Frame integrity typed source/scope differs')
    for key, size in EXTENTS.items():
        if type(c[key]) is not int or c[key] != size:
            raise ValueError('Frame integrity extent differs: ' + key)
    for key in ('backend_context', 'wire_context'):
        load('login-dispatch-rules').pointer(c[key])
    for key in parent.BACKEND-{'globals'}: address(c['backend'][key])
    globals_ = c['backend']['globals']
    if not isinstance(globals_, dict) or set(globals_) != {'gate', 'diagnostic_pointer'}:
        raise ValueError('Frame integrity ambient globals differ')
    for at in globals_.values(): address(at)
    integrity = c['integrity']
    if (set(integrity) != set(PRIMITIVES) | {'table', 'anchors', 'fallback_key'}
            or type(integrity['fallback_key']) is not int or integrity['fallback_key'] != FALLBACK_KEY
            or not isinstance(integrity['anchors'], dict) or set(integrity['anchors']) != set(PRIMITIVES)):
        raise ValueError('Frame integrity primitive fields differ')
    for role, (key, _, _) in PRIMITIVES.items():
        if integrity[role] != c['backend'][key]: raise ValueError('Frame integrity primitive role differs')
        a = integrity['anchors'][role]
        if (not isinstance(a, dict) or set(a) != {'callsite', 'target', 'bytes'}
                or a['target'] != integrity[role]):
            raise ValueError('Frame integrity source anchor differs')
        address(a['callsite'])
        if not isinstance(a['bytes'], str) or not re.fullmatch('e8[0-9a-f]{8}', a['bytes']):
            raise ValueError('Frame integrity anchor opcode differs')
    table = integrity['table']
    if (not isinstance(table, dict) or set(table) != {'address', 'bytes', 'sha256', 'size'}
            or type(table['size']) is not int or table['size'] != 1024
            or table['bytes'] != crc_table().hex()
            or table['sha256'] != hashlib.sha256(crc_table()).hexdigest()):
        raise ValueError('Frame integrity CRC table differs')
    address(table['address'])
    return {k: copy.deepcopy(v) for k, v in c.items() if k not in META}


def normalized_crc(raw):
    value = bytearray(raw)
    if len(value) != 55 or value[8:11] != bytes.fromhex('4c8d1d'):
        raise ValueError('Frame integrity CRC leaf shape differs')
    value[11:15] = bytes(4)
    return value.hex()


def crc_table():
    rows = []
    for value in range(256):
        for _ in range(8): value = (value >> 1) ^ (0xedb88320 if value & 1 else 0)
        rows.append(value)
    return struct.pack('<256I', *rows)


def roots(c):
    functional(c)
    if set(c['functions']) != role_names(): raise ValueError('Frame integrity whole roles differ')
    whole = {address(v) for v in c['functions'].values()}
    leaves = {address(a) for a in c['leaves']}
    tails = {address(a) for a in c['tails']}
    if ((len(whole), len(leaves), len(tails)) != (16, 9, 2)
            or whole & leaves or whole & tails or leaves & tails):
        raise ValueError('Frame integrity exact16whole/9returning/2tail inventory differs')
    for raw in (*c['leaves'].values(), *c['tails'].values()):
        if not isinstance(raw, str) or not re.fullmatch('(?:[0-9a-f]{2})+', raw):
            raise ValueError('Frame integrity source capsule differs')
    b, i = c['backend'], c['integrity']
    if (set(c['tails']) != {b['cleanup_wrapper'], b['cleanup_base']}
            or c['leaves'].get(b['packet_id_getter']) != 'b803000000c3'
            or c['leaves'].get(b['get_buffer']) != '83793000750333c0c3488b4118c3'
            or len(bytes.fromhex(c['leaves'].get(b['cleanup_final'], ''))) != 11
            or c['leaves'].get(i['initializer']) != INITIALIZER
            or c['leaves'].get(i['transform']) != TRANSFORM
            or normalized_crc(bytes.fromhex(c['leaves'].get(i['update'], ''))) != CRC_NORMAL):
        raise ValueError('Frame integrity returning/tail role or primitive bytes differ')
    excluded = {address(b[key]) for key in ('state_getter', 'debug_first', 'debug_second', 'fallback', 'transport')}
    if excluded & (whole | leaves | tails): raise ValueError('Frame integrity fixture aliases native instruction')
    return whole


def parents(root, c):
    core = load('portable-native-family')
    return tuple(core.checked(root, c[role+'_context'], 'generated-native-contexts') for role in ('backend', 'wire'))


def project(root, native, bindings, image, backend, wire, backend_pointer, wire_pointer, *, format=CURRENT):
    parent = load('login-backend-wire-rules')
    parent.roots(backend)
    for p in (backend_pointer, wire_pointer): load('login-dispatch-rules').pointer(p)
    if (backend['wire_context'] != wire_pointer or not backend.get('transfer_proof')
            or wire.get('family') != 'archive-wire' or not wire.get('transfer_proof')
            or backend['source_sha256'] != wire['source_sha256']
            or Path(backend['source']).resolve() != Path(wire['source']).resolve()):
        raise ValueError('Frame integrity requires exact same-source proved backend/wire lineage')
    functions = {k: backend['functions'][k] for k in sorted(role_names())}
    rows = {k: bindings.rows(native, image, address(at)) for k, at in functions.items()}
    b = copy.deepcopy(backend['backend'])
    leaf_addresses = set(wire['archive_leaves']) | {wire['bindings']['encoder']} | {
        b['packet_id_getter'], b['get_buffer'], b['cleanup_final']}
    leaves = {at: backend['leaves'][at] for at in sorted(leaf_addresses)}
    anchors, integrity = {}, dict(fallback_key=FALLBACK_KEY)
    rr = rows['backend']
    for role, (key, offset, size) in PRIMITIVES.items():
        at = address(b[key])
        raw = data(image, at, size)
        load('login-backend-wire-source').fragment(native, image, at, raw.hex())
        instruction = parent.at_rows(rr, offset)
        if instruction.get('direct_target') != at or instruction.get('bytes', '')[:2] != 'e8':
            raise ValueError('Frame integrity backend source call anchor differs')
        anchors[role] = dict(callsite=hex(instruction['address']), target=hex(at), bytes=instruction['bytes'])
        integrity[role] = hex(at)
        leaves[hex(at)] = raw.hex()
    update = bytes.fromhex(leaves[integrity['update']])
    if normalized_crc(update) != CRC_NORMAL: raise ValueError('Frame integrity CRC source logic changed')
    table_at = address(integrity['update']) + 15 + struct.unpack_from('<i', update, 11)[0]
    table = data(image, table_at, 1024)
    if table != crc_table(): raise ValueError('Frame integrity source CRC polynomial table changed')
    integrity.update(anchors=anchors, table=dict(address=hex(table_at), bytes=table.hex(),
        sha256=hashlib.sha256(table).hexdigest(), size=1024))
    c = dict(schema=1, family=FAMILY, format=format, source=backend['source'],
        source_sha256=backend['source_sha256'], functions=functions, leaves=leaves,
        tails={at: backend['tails'][at] for at in (b['cleanup_wrapper'], b['cleanup_base'])},
        helpers=copy.deepcopy(backend['helpers']), call_sites={k: parent.calls(r) for k, r in rows.items()},
        backend_context=copy.deepcopy(backend_pointer), wire_context=copy.deepcopy(wire_pointer), backend=b,
        source_inputs={k: copy.deepcopy(backend['source_inputs'][k]) for k in sorted(INPUTS)},
        integrity=integrity, verify_whole_exports=True, **EXTENTS)
    roots(c)
    # Validate every capsule and explicit tail, including inherited ones.
    for at, raw in c['leaves'].items(): load('login-backend-wire-source').fragment(native, image, address(at), raw)
    for at, target in ((b['cleanup_wrapper'], functions['wire.cleanup']), (b['cleanup_base'], b['cleanup_final'])):
        load('login-backend-wire-source').fragment(native, image, address(at), c['tails'][at], tail_target=address(target))
    return c, rows


def validate_static(root, native, bindings, image, c):
    roots(c)
    backend, wire = parents(root, c)
    candidate, rows = project(root, native, bindings, image, backend, wire,
        c['backend_context'], c['wire_context'], format=c['format'])
    if (functional(candidate) != functional(c) or candidate['source_sha256'] != c['source_sha256']
            or Path(candidate['source']).resolve() != Path(c['source']).resolve()):
        raise ValueError('Frame integrity typed source projection differs')
    return rows


def transfer(root, native, bindings, before, after, baseline, mapping, backend, wire, *, backend_pointer, wire_pointer):
    old = validate_static(root, native, bindings, before, baseline)
    c, new = project(root, native, bindings, after, backend, wire, backend_pointer, wire_pointer)
    common, parent = load('update-native-archive-wire'), load('login-backend-wire-rules')
    old_backend, old_wire = parents(root, baseline)
    for role in sorted(role_names()):
        common.add_link(mapping, address(baseline['functions'][role]), address(c['functions'][role]))
    for role in parent.BACKEND-{'globals'}:
        common.add_link(mapping, address(baseline['backend'][role]), address(c['backend'][role]))
    common.add_link(mapping, address(old_wire['bindings']['encoder']), address(wire['bindings']['encoder']))
    for role, at in old_wire['archive_helpers'].items():
        common.add_link(mapping, address(at), address(wire['archive_helpers'][role]))
    for role in sorted(role_names()):
        parent.pair_rows(native, old[role], new[role], mapping,
            declared_tails={address(baseline['backend']['cleanup_base'])} if role == 'wire.cleanup' else (),
            virtual_tail=role == 'wire.append')
    # Same instruction pairing proves each RIP operand and external call edge;
    # capsule pairing also records the CRC table relocation and source vtables.
    old_leaf = list(baseline['leaves'])
    for a in old_leaf:
        if a in (baseline['integrity'][r] for r in PRIMITIVES):
            role = next(r for r in PRIMITIVES if baseline['integrity'][r] == a)
            b = c['integrity'][role]
        else:
            target = mapping.get(address(a))
            if target is None: raise ValueError('Frame integrity inherited leaf has no proved relocation')
            b = hex(target)
        if b not in c['leaves']: raise ValueError('Frame integrity inherited leaf target differs')
        parent.pair_rows(native, decode(native, before, address(a), len(bytes.fromhex(baseline['leaves'][a]))),
            decode(native, after, address(b), len(bytes.fromhex(c['leaves'][b]))), mapping)
    for role in ('cleanup_wrapper', 'cleanup_base'):
        a, b = baseline['backend'][role], c['backend'][role]
        aa = decode(native, before, address(a), len(bytes.fromhex(baseline['tails'][a])))
        bb = decode(native, after, address(b), len(bytes.fromhex(c['tails'][b])))
        parent.pair_rows(native, aa, bb, mapping, declared_tails={aa[-1]['direct_target']})
    # The source tables are parent-proved; enforce this role's exact selected
    # widths/alias topology too, rather than inheriting a whole service profile.
    for role, item in baseline['source_inputs'].items():
        target = c['source_inputs'][role]
        common.add_link(mapping, address(item['address']), address(target['address']))
        if 'bytes' not in item:
            if (item['size_bytes'], item['span']['name']) != (target['size_bytes'], target['span']['name']):
                raise ValueError('Frame integrity source storage changed')
        elif role == 'archive_flags':
            if item['bytes'] != target['bytes']: raise ValueError('Frame integrity archive flags changed')
        else:
            a, b = bytes.fromhex(item['bytes']), bytes.fromhex(target['bytes'])
            if len(a) != len(b) or len(a) % 8: raise ValueError('Frame integrity source table extent changed')
            av, bv = struct.unpack('<'+'Q'*(len(a)//8), a), struct.unpack('<'+'Q'*(len(b)//8), b)
            for i, (x, y) in enumerate(zip(av, bv)):
                if any((x == av[j]) != (y == bv[j]) for j in range(i)):
                    raise ValueError('Frame integrity source table alias changed')
                common.add_link(mapping, x, y)
    common.add_link(mapping, address(baseline['integrity']['table']['address']), address(c['integrity']['table']['address']))
    return c, dict(method='native_crc_xor_login_backend_writer_cleanup', whole_roots=16,
        returning_leaves=9, tail_fragments=2, crc_relocation_bytes=[11, 15],
        native_checksum=True, native_transform=True, native_transport=False,
        synthetic_packet=True, native_prepare=False, session_executed=False)


def export_coverage(root, c, native, bindings, image):
    rows = validate_static(root, native, bindings, image, c)
    needed = {address(c['functions'][role]): r for role, r in rows.items()}
    seen = set()
    for run, sha in c.get('exports', {}).items():
        if Path(run).name != run or not run.startswith('run-'): raise ValueError('Frame integrity export run differs')
        path = Path(root)/'ghidra/request-exports'/c['source_sha256']/run/'details.json'
        if hashlib.sha256(path.read_bytes()).hexdigest() != sha: raise ValueError('Frame integrity export SHA differs')
        report = json.loads(path.read_text('utf-8'))
        if report.get('new_source_sha256', report.get('source_sha256')) != c['source_sha256']:
            raise ValueError('Frame integrity export source differs')
        for fn in report['functions']:
            at = address(fn['address'])
            if at not in needed: continue
            load('login-backend-wire-source').check_coverage(dict(functions=[fn]), at, needed[at])
            load('audit-launcher-shape-11318').normalize_function(native, image, fn)
            seen.add(at)
    if seen != set(needed): raise ValueError('Frame integrity exports lack16 complete whole roots')
