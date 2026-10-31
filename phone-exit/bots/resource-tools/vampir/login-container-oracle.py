"""High-level bounded container and signed-ANSI oracles, independent of native order.

Native snapshots must be read from memory. example_after() only constructs one
valid graph for tooling tests; it does not predict the implementation's ordering.
"""
import copy
import json
import math
import struct

FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME = 0x100000001b3
PACKET_NAME = b'PktLoginResult'
CALL_ROLES = ('register', 'insert', 'rehash', 'name_getter', 'string_constructor', 'id_getter')
FLAGS = ('abi', 'guards', 'protected_inputs', 'fixture_writes_bounded')


def require(ok, message):
    if not ok: raise ValueError(message)


def fnv16(key):
    require(type(key) is int and 0 <= key <= 0xffff, 'Container key differs')
    value = FNV_OFFSET
    for byte in (key & 255, key >> 8): value = ((value ^ byte) * FNV_PRIME) & 0xffffffffffffffff
    return value


def float_value(bits):
    require(bits in ('3f800000', '40000000'), 'Container load factor outside bounded matrix')
    return struct.unpack('>f', bytes.fromhex(bits))[0]


def capacity(requested, mode):
    require(type(requested) is int and requested > 0 and mode in ('exact', 'rounded'), 'Name capacity policy differs')
    return requested if mode == 'exact' else (requested + 15) // 16 * 16


def source_bytes(scenario):
    if scenario['kind'] == 'getter': return PACKET_NAME
    source = scenario['source_hex']
    if source is None: return b''
    require(isinstance(source, str), 'ANSI source differs')
    return bytes.fromhex(source).split(b'\0', 1)[0]


def ctor_expected(scenario):
    data = source_bytes(scenario)
    count = len(data) + 1 if data else 0
    units = [(byte if byte < 128 else byte - 256) & 0xffff for byte in data] + ([0] if data else [])
    return dict(descriptor=dict(data='name_heap' if data else 'null', num=count,
        max=capacity(count, scenario['capacity']) if count else 0),
        utf16_hex=b''.join(struct.pack('<H', value) for value in units).hex(),
        spare_unchanged=True, old_pointer_freed=False, outparam_returned=True)


def _inputs(scenario):
    keys = scenario['keys']; count = scenario['bucket_count']; size = scenario['vector_capacity']
    require(isinstance(keys, list) and len(keys) <= 8 and all(type(k) is int and 0 <= k <= 0xffff for k in keys)
        and len(keys) == len(set(keys)), 'Container unique-key seed differs')
    require(count == 8 and type(count) is int and type(size) is int and 2*count <= size <= 32,
        'Container seed extent differs')
    float_value(scenario['load_factor_bits'])
    return [dict(label='n'+str(i), key=key, packet='packet_'+str(i), handler='handler_'+str(i))
        for i, key in enumerate(keys)]


def expected_operation(scenario):
    kind = scenario['kind']; entries = _inputs(scenario); old_count = scenario['bucket_count']
    require(kind in ('insert', 'rehash', 'fusion'), 'Container operation differs')
    duplicate = False; requested = None; returned = None
    if kind == 'rehash':
        requested = scenario['requested']
        require(type(requested) is int and 1 <= requested <= 64, 'Bounded rehash request differs')
    else:
        key = scenario['key']; fnv16(key)
        found = next((entry for entry in entries if entry['key'] == key), None)
        duplicate = found is not None
        returned = dict(outparam_returned=True, node=found['label'] if found else 'candidate', status=0 if found else 1)
        if not duplicate:
            projected = len(entries) + 1; factor = float_value(scenario['load_factor_bits'])
            if projected / old_count > factor:
                minimum = max(8, math.ceil(projected / factor))
                requested = max(minimum, old_count*8) if old_count < 512 else minimum
            entries.append(dict(label='candidate', key=key, packet='packet_input', handler='handler_input'))
    count = max(2, 1 << (requested-1).bit_length()) if requested is not None else old_count
    require(count <= 64, 'Container matrix bucket bound differs')
    vector_size = max(2*old_count, 2*count) if requested is not None else 2*old_count
    vector_capacity = 2*count if requested is not None and 2*count > 2*old_count else scenario['vector_capacity']
    return dict(entries=entries, count=len(entries), bucket_count=count, mask=count-1,
        vector_size=vector_size, vector_capacity=vector_capacity, duplicate=duplicate,
        rehash_requested=requested, reallocated=requested is not None and 2*count > 2*old_count, returned=returned)


def _graph(entries, count, size, cap, factor):
    # Only a valid model graph; native iteration order is deliberately unconstrained.
    ordered = sorted(entries, key=lambda entry: fnv16(entry['key']) & (count-1))
    labels = ['head'] + [entry['label'] for entry in ordered] + ['head']
    nodes = [dict(entry, next=labels[i+2], prev=labels[i]) for i, entry in enumerate(ordered)]
    slots = ['head'] * size
    for index in range(count):
        members = [entry['label'] for entry in ordered if fnv16(entry['key']) & (count-1) == index]
        if members: slots[2*index:2*index+2] = [members[0], members[-1]]
    return dict(count=len(entries), bucket_count=count, mask=count-1, load_factor_bits=factor,
        head=dict(next=labels[1], prev=labels[-2]), vector=dict(size=size, capacity=cap, slots=slots), nodes=nodes)


def seed(scenario):
    return _graph(_inputs(scenario), scenario['bucket_count'], 2*scenario['bucket_count'],
        scenario['vector_capacity'], scenario['load_factor_bits'])


def example_after(scenario):
    """One valid output for pure tooling tests, never a substitute for native reads."""
    value = expected_operation(scenario)
    return _graph(value['entries'], value['bucket_count'], value['vector_size'],
        value['vector_capacity'], scenario['load_factor_bits'])


def validate_map(snapshot, scenario):
    require(isinstance(snapshot, dict) and set(snapshot) == {'count','bucket_count','mask','load_factor_bits','head','vector','nodes'},
        'Container snapshot fields differ')
    expected = expected_operation(scenario)
    for key in ('count', 'bucket_count', 'mask'):
        require(type(snapshot[key]) is int and snapshot[key] == expected[key], 'Container '+key+' differs')
    require(snapshot['load_factor_bits'] == scenario['load_factor_bits'], 'Container load factor changed')
    raw_nodes = snapshot['nodes']; require(isinstance(raw_nodes, list), 'Container nodes differ')
    require(all(isinstance(node, dict) and set(node) == {'label','key','packet','handler','next','prev'} for node in raw_nodes),
        'Container node fields differ')
    require(all(all(isinstance(node[key], str) for key in ('label','next','prev')) for node in raw_nodes),
        'Container node label/link differs')
    nodes = {node['label']: node for node in raw_nodes}
    wanted = {entry['label']: entry for entry in expected['entries']}
    require(len(nodes) == len(raw_nodes) == expected['count'] and set(nodes) == set(wanted),
        'Container live nodes/orphans differ')
    for label, node in nodes.items():
        require(type(node['key']) is int and {key: node[key] for key in ('label','key','packet','handler')} == wanted[label],
            'Container key/payload changed')
    head = snapshot['head']; require(isinstance(head, dict) and set(head) == {'next','prev'}, 'Container head differs')
    require(all(isinstance(value, str) for value in head.values()), 'Container head link differs')
    links = dict(nodes, head=head); order = []; previous = 'head'; current = head['next']
    while current != 'head':
        require(isinstance(current, str) and current in nodes and current not in order, 'Container forward cycle/orphan differs')
        node = nodes[current]
        require(node['prev'] == previous, 'Container backward link differs')
        order.append(current); previous = current; current = node['next']
        require(len(order) <= expected['count'], 'Container cycle exceeds live count')
    require(len(order) == expected['count'] and head['prev'] == previous, 'Container head/list count differs')
    for label, node in links.items():
        require(node['next'] in links and node['prev'] in links and links[node['next']]['prev'] == label
            and links[node['prev']]['next'] == label, 'Container reciprocal link differs')
    vector = snapshot['vector']
    require(isinstance(vector, dict) and set(vector) == {'size','capacity','slots'}, 'Container vector fields differ')
    require(type(vector['size']) is int and type(vector['capacity']) is int and vector['size'] == expected['vector_size']
        and vector['capacity'] == expected['vector_capacity'], 'Container vector descriptor differs')
    slots = vector['slots']; require(isinstance(slots, list) and len(slots) == vector['size'], 'Container vector extent differs')
    for index in range(expected['bucket_count']):
        positions = [i for i, label in enumerate(order) if fnv16(nodes[label]['key']) & expected['mask'] == index]
        require(not positions or positions == list(range(positions[0], positions[-1]+1)), 'Container bucket segment not contiguous')
        ends = [order[positions[0]], order[positions[-1]]] if positions else ['head','head']
        require(slots[2*index:2*index+2] == ends, 'Container bucket first/last differs')
    require(all(label == 'head' for label in slots[2*expected['bucket_count']:]), 'Inactive bucket tail differs')
    return expected


def event(action, **fields): return dict(action=action, **fields)


def expected_events(scenario):
    kind = scenario['kind']
    if kind in ('ctor','getter'):
        descriptor = ctor_expected(scenario)['descriptor']
        return [event('reserve', requested=descriptor['num'], capacity=descriptor['max'])] if descriptor['num'] else []
    operation = expected_operation(scenario); events = []
    if kind != 'rehash': events.append(event('node_allocate', bytes=40))
    if operation['duplicate']: events.append(event('sized_free', allocation='candidate', bytes=40))
    if operation['rehash_requested'] is not None:
        events.append(event('vector_reset', slots=2*operation['bucket_count'], reallocated=operation['reallocated']))
    if kind == 'fusion':
        if operation['duplicate']:
            count = len(PACKET_NAME)+1
            events.extend([event('reserve', requested=count, capacity=capacity(count, scenario['capacity'])),
                event('utf8_length', utf16_units=len(PACKET_NAME), utf8_bytes=len(PACKET_NAME)),
                event('utf8_convert', utf16_units_with_nul=count, capacity=count, utf8_hex=PACKET_NAME.hex()),
                event('log', packet_id=4, line=0xb27, utf8_hex=PACKET_NAME.hex()), event('free', allocation='name_heap')])
        events.append(event('security'))
    return events


def native_calls(scenario):
    kind = scenario['kind']; result = dict.fromkeys(CALL_ROLES, 0)
    if kind in ('ctor', 'getter'):
        result['string_constructor'] = 1
        if kind == 'getter': result['name_getter'] = 1
    else:
        operation = expected_operation(scenario)
        result['rehash'] = int(operation['rehash_requested'] is not None)
        if kind != 'rehash': result['insert'] = 1
        if kind == 'fusion':
            result['register'] = 1; result['id_getter'] = 2 if operation['duplicate'] else 1
            if operation['duplicate']: result.update(name_getter=1, string_constructor=1)
    return result


def expected_case(scenario):
    """Canonical scalar fields plus one possible map graph for tooling fixtures."""
    row = dict(scenario=copy.deepcopy(scenario), events=expected_events(scenario), native_calls=native_calls(scenario),
        **dict.fromkeys(FLAGS, True))
    if scenario['kind'] in ('ctor','getter'): row.update(ctor_expected(scenario))
    else:
        operation = expected_operation(scenario)
        row.update(after=example_after(scenario), returned=operation['returned'])
        if scenario['kind'] == 'fusion': row.update(name_descriptor_consumed=operation['duplicate'],
            name_buffer_freed=operation['duplicate'], payloads_freed=False)
    return row


def validate_case(row, scenario):
    require(isinstance(row, dict), 'Container case differs')
    expected = expected_case(scenario)
    require(set(row) == set(expected), 'Container case fields differ')
    if scenario['kind'] not in ('ctor','getter'): validate_map(row['after'], scenario)
    # Iteration order is not part of the high-level unique-map contract.
    for key in expected:
        if key == 'after': continue
        encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
        require(encode(row[key]) == encode(expected[key]), 'Container case '+key+' differs')
    return row
