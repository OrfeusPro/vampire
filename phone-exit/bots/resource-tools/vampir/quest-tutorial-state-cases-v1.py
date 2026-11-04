"""Tutorial map application and queue draining over explicit bounded storage."""
from itertools import product
import struct

KEYS = (1001, 3001, 3002, 3007, 3008, 3009, 3011, 3012, 3014, 3015, 3024, 4017, 4018, 4019, 4020, 4021)
BEFORE, AFTER = b'\xa1' * 16, b'\xa2' * 16
SCOPES = ('tutorial-startup', 'tutorial-populated', 'tutorial-drain')


def expected_calls(scope):
    if scope in ('startup', 'tutorial-startup'):
        return 192
    if scope in ('populated', 'tutorial-populated'):
        return 384
    if scope in ('drain', 'tutorial-drain'):
        return 880
    raise ValueError('Unknown Tutorial state call scope')


def expected_cases(scope):
    if scope in ('startup', 'tutorial-startup'):
        result = []
        for count, found, policy, state, selector, flag in product(
                (0, 1, 16), (False, True), (0, 1), (0, 1, 2, 3), (0, 1), (0, 1)):
            active = bool(count and found and state == 1)
            result.append(dict(count=count, row_found=found, policy_raw50=policy, state=state,
                selector=selector, flag=flag, server_count=count if found else 0,
                local_count=int(active), launched=[selector + 1] if active else []))
        return result
    if scope in ('populated', 'tutorial-populated'):
        result = []
        for server, local, external, selector, state, keep, blocked in product(
                (False, True), (False, True), (False, True), (0, 2, 0xffffffff),
                (0, 1, 2, 3), (0, 1), (False, True)):
            events = [] if server else ['insertion']
            if local:
                events += ['gate'] + ([] if blocked else ['launch'])
            result.append(dict(server_present=server, local_present=local, external=external,
                selector=selector, state=state, keep=keep, blocked=blocked, events=events,
                local_selector=selector if keep or blocked else (selector + 1) & 0xffffffff,
                local_state=1 if not blocked and state == 0 else state))
        return result
    if scope in ('drain', 'tutorial-drain'):
        return [dict(initial_phase=phase, order=list(order), records=count, flag=flag,
                     resumed=phase < 6, released=sum(item is not None for item in order))
                for phase, order, count, flag in product((0, 5, 6, 7),
                    ((), (None,), (0,), (0, None, 1), (2, 1, 0)), (0, 1, 8, 64), (0, 1))]
    raise ValueError('Unknown Tutorial state case scope')


def helpers(h, context):
    uc, x = h.uc, h.x
    functions = {name: int(at, 16) for name, at in context['functions'].items()}
    fixtures = {name: int(at, 16) for name, at in context['fixtures'].items()}

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def number(at, size=8):
        return int.from_bytes(uc.mem_read(at, size), 'little')

    def read(at, size):
        return bytes(uc.mem_read(at, size)) if size else b''

    def seed(at, body):
        uc.mem_write(at - 16, BEFORE + bytes(body) + AFTER)

    def guards(regions):
        for at, size in regions:
            if read(at - 16, 16) != BEFORE or read(at + size, 16) != AFTER:
                raise ValueError('Tutorial state object or storage guard changed')

    return functions, fixtures, reg, number, read, seed, guards


def install(h, fixtures, active):
    if any(fixtures.get(role) not in h.available_fixtures for role in active):
        raise ValueError('Tutorial state expected fixture lacks a reviewed caller')
    for role, at in fixtures.items():
        if at not in h.available_fixtures:
            continue

        def excluded(machine, role=role):
            raise ValueError('Tutorial state excluded fixture reached: ' + role)

        h.add_fixture(at, active.get(role, excluded))


def verify_startup(h, context):
    functions, fixtures, reg, number, read, seed, guards = helpers(h, context)
    uc = h.uc
    model, server_nodes, local_nodes, server_buckets, local_buckets, data, records, row, group, status = (
        h.scratch + n for n in (0x10000, 0x11000, 0x12000, 0x13000, 0x14000,
                               0x15000, 0x16000, 0x17000, 0x18000, 0x19000))
    mutable = ((model, 0x400), (server_nodes, 32 * 40), (local_nodes, 32 * 40),
               (server_buckets, 128), (local_buckets, 128), (status, 32 * 16))
    inputs = ((data, 0x30), (records, 16 * 24), (row, 0x80), (group, 16))
    current, launches, lookup_events = {}, [], []

    def table_lookup(machine):
        out, key = reg('RCX'), reg('RDX') & 0xffffffff
        if key not in KEYS[:current['count']]:
            raise ValueError('Tutorial table lookup key is outside current snapshot')
        lookup_events.append(('table', key))
        h.write(out, struct.pack('<IIQ', key, 0, row if current['row_found'] else 0))
        h.finish(out)

    def group_lookup(machine):
        out, key_pointer = reg('RCX'), reg('RDX')
        key = number(key_pointer, 4)
        if key not in KEYS:
            raise ValueError('Tutorial group lookup key is outside bounded keys')
        lookup_events.append(('group', key))
        h.write(out, struct.pack('<Q', group if current['row_found'] else 0))
        h.finish(out)

    def map_allocate(machine):
        header, out = reg('RCX'), reg('RDX')
        if header not in (model + 0xa8, model + 0x1c8):
            raise ValueError('Tutorial map allocation header differs')
        index = number(header + 8, 4)
        if index >= 32 or number(header + 0x34, 4):
            raise ValueError('Tutorial map fixture requires bounded fresh storage')
        nodes = server_nodes if header == model + 0xa8 else local_nodes
        node = nodes + index * 40
        h.write(node, bytes(40))
        h.write(header + 8, struct.pack('<I', index + 1))
        h.write(header + 0x28, struct.pack('<I', index + 1))
        h.write(header + 0x10, struct.pack('<I', (1 << (index + 1)) - 1))
        h.write(out, struct.pack('<IIQ', index, 0, node))
        h.finish()

    def status_allocate(machine):
        descriptor = reg('RCX')
        if reg('RDX') or number(descriptor + 8, 4) != 1 or number(descriptor):
            raise ValueError('Tutorial status fixture requires empty storage')
        h.write(status, bytes(32 * 16))
        h.write(descriptor, struct.pack('<Q', status))
        h.write(descriptor + 12, struct.pack('<I', 32))
        h.finish()

    def prune_cleanup(machine):
        at = reg('RCX')
        if number(at) or number(at + 8, 4) or number(at + 0x34, 4):
            raise ValueError('Tutorial prune cleanup reached a populated temporary set')
        h.finish()

    def status_cleanup(machine):
        if number(reg('RCX')) not in (0, status):
            raise ValueError('Tutorial status cleanup escaped prepared storage')
        h.finish()

    def cookie(machine):
        h.finish(reg('RAX'))

    def launch(machine):
        if (reg('RCX'), reg('RDX'), reg('R8')) != (model, local_nodes + 8, current['selector'] + 1):
            raise ValueError('Tutorial startup task launch association differs')
        launches.append(reg('R8'))
        h.finish()

    install(h, fixtures, dict(table_lookup=table_lookup, group_lookup=group_lookup,
        map_allocate=map_allocate, status_allocate=status_allocate, prune_cleanup=prune_cleanup,
        status_cleanup=status_cleanup, cookie=cookie, launch=launch))
    cases = []
    for expected in expected_cases('startup'):
        current = expected
        launches.clear()
        lookup_events.clear()
        h.reset_regions()
        for at, size in mutable + inputs:
            seed(at, bytes(size))
        for at, size in mutable:
            h.allow_write(at, size)
        for at, size in inputs:
            h.allow_read(at, size)
        for offset, nodes, buckets in ((0xa8, server_nodes, server_buckets),
                                       (0x1c8, local_nodes, local_buckets)):
            header = model + offset
            uc.mem_write(header, struct.pack('<QII', nodes, 0, 32))
            uc.mem_write(header + 0x28, struct.pack('<IIiI', 0, 128, -1, 0))
            uc.mem_write(header + 0x40, struct.pack('<QI', buckets, 32))
            uc.mem_write(buckets, b'\xff' * 128)
        uc.mem_write(data + 8, bytes([expected['flag']]))
        uc.mem_write(data + 0x10, struct.pack('<QII', records, expected['count'], expected['count']))
        uc.mem_write(row + 0x50, struct.pack('<I', expected['policy_raw50']))
        uc.mem_write(group, struct.pack('<QI', 0, 2))
        for index, key in enumerate(KEYS[:expected['count']]):
            uc.mem_write(records + 24 * index + 8, struct.pack('<IIIB', key,
                expected['selector'] if index == 0 else 0, 0x12340000 + index,
                expected['state'] if index == 0 else 0))
        before = {at: read(at, size) for at, size in inputs}
        h.call(functions['apply'], model, rdx=data, budget=1000000)
        server_count, local_count = number(model + 0xb0, 4), number(model + 0x1d0, 4)
        if server_count != expected['server_count'] or local_count != expected['local_count']:
            raise ValueError('Tutorial startup server/local map count differs')
        for index in range(server_count):
            if read(server_nodes + index * 40 + 16, 13) != read(records + index * 24 + 8, 13):
                raise ValueError('Tutorial startup authoritative record copy differs')
        if local_count and read(local_nodes + 16, 13) != struct.pack(
                '<IIIB', 1001, expected['selector'] + 1, 0x12340000, 1):
            raise ValueError('Tutorial startup local record projection differs')
        if launches != expected['launched'] or any(read(at, len(body)) != body for at, body in before.items()):
            raise ValueError('Tutorial startup launch trace or immutable input changed')
        guards(mutable + inputs)
        cases.append(dict(expected, server_count=server_count, local_count=local_count, launched=launches.copy()))
    return dict(cases=cases, metrics=h.validate())


def verify_populated(h, context):
    functions, fixtures, reg, number, read, seed, guards = helpers(h, context)
    uc = h.uc
    model, server_nodes, local_nodes, inserted, packet, buckets = (
        h.scratch + n for n in (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000))
    regions = ((model, 0x400), (server_nodes, 120), (local_nodes, 120),
               (inserted, 24), (packet, 24), (buckets, 0x400))
    current, events = {}, []

    def insertion(machine):
        if (reg('RCX'), reg('RDX')) != (model + 0xa8, 1001):
            raise ValueError('Tutorial populated insertion arguments differ')
        events.append('insertion')
        h.finish(inserted)

    def gate(machine):
        if (reg('RCX'), reg('RDX'), reg('R8'), reg('R9')) != (
                model, 1001, current['selector'], current['state']):
            raise ValueError('Tutorial populated gate arguments differ')
        events.append('gate')
        h.finish(int(current['blocked']))

    def launch(machine):
        if (reg('RCX'), reg('RDX'), reg('R8')) != (model, local_nodes + 48, current['local_selector']):
            raise ValueError('Tutorial populated launch arguments differ')
        events.append('launch')
        h.finish()

    install(h, fixtures, dict(insertion=insertion, gate=gate, launch=launch))

    def map_setup(offset, nodes, present, external):
        header = model + offset
        if not present:
            return
        uc.mem_write(header, struct.pack('<QI', nodes, 3))
        uc.mem_write(header + 0x38, struct.pack('<i', 0))
        bucket = buckets + offset
        uc.mem_write(bucket, struct.pack('<i', 0))
        uc.mem_write(header + 0x40, struct.pack('<QI', bucket if external else 0, 1))
        for index, key in enumerate((7, 1001, 8)):
            node = nodes + index * 40
            uc.mem_write(node, struct.pack('<I', key))
            uc.mem_write(node + 16, struct.pack('<IIIB', key, 99, 0xaabbccdd, 3))
            uc.mem_write(node + 32, struct.pack('<i', index + 1 if index < 2 else -1))

    cases = []
    for expected in expected_cases('populated'):
        current = expected
        events.clear()
        h.reset_regions()
        for at, size in regions:
            seed(at, b'\xa5' * size if at in (server_nodes, local_nodes, inserted) else bytes(size))
        for at, size in regions:
            if at == packet or at == buckets:
                h.allow_read(at, size)
            else:
                h.allow_write(at, size)
        map_setup(0xa8, server_nodes, expected['server_present'], expected['external'])
        map_setup(0x1c8, local_nodes, expected['local_present'], expected['external'])
        uc.mem_write(packet + 8, struct.pack('<IIIB', 1001, expected['selector'], 0x12345678, expected['state']))
        before_packet, before_model, before_buckets = read(packet, 24), read(model, 0x400), read(buckets, 0x400)
        before_server, before_local = read(server_nodes, 120), read(local_nodes, 120)
        h.call(functions['apply'], model, rdx=packet, r8=expected['keep'])
        server = server_nodes + 48 if expected['server_present'] else inserted
        if read(server + 8, 13) != struct.pack('<IIIB', 1001, expected['selector'], 0x12345678, expected['state']):
            raise ValueError('Tutorial populated authoritative projection differs')
        if expected['local_present'] and read(local_nodes + 48 + 8, 13) != struct.pack(
                '<IIIB', 1001, expected['local_selector'], 0xaabbccdd, expected['local_state']):
            raise ValueError('Tutorial populated local selector/state projection differs')
        for nodes, previous in ((server_nodes, before_server), (local_nodes, before_local)):
            if read(nodes, 40) != previous[:40] or read(nodes + 80, 40) != previous[80:]:
                raise ValueError('Tutorial populated unrelated map records changed')
        if (read(packet, 24) != before_packet or read(model, 0x400) != before_model
                or read(buckets, 0x400) != before_buckets or events != expected['events']):
            raise ValueError('Tutorial populated trace or immutable input changed')
        guards(regions)
        cases.append(dict(expected, events=events.copy()))
    return dict(cases=cases, metrics=h.validate())


def verify_drain(h, context):
    functions, fixtures, reg, number, read, seed, guards = helpers(h, context)
    uc = h.uc
    model, state_object, queue = (h.scratch + n for n in (0x1000, 0x2000, 0x3000))
    packets = [h.scratch + 0x4000 + index * 0x100 for index in range(3)]
    records = [h.scratch + 0x10000 + index * 0x1000 for index in range(3)]
    table = int(context['packet_table'], 16)
    record_table = int(context['record_table'], 16)
    state = {}

    def state_provider(machine):
        if reg('RCX') != model:
            raise ValueError('Tutorial drain state provider owner differs')
        state['state_calls'] += 1
        h.finish(state_object)

    def application(machine):
        pointer = reg('RDX') - 16
        if reg('RCX') != model or pointer not in state['expected']:
            raise ValueError('Tutorial drain application association differs')
        if state['waiting_release'] is not None or pointer != state['expected'][len(state['applied'])]:
            raise ValueError('Tutorial drain apply/release order differs')
        vector, count, capacity = struct.unpack('<QII', read(pointer + 0x20, 16))
        if (count, capacity, number(pointer + 0x18, 1)) != (state['count'], state['count'], state['flag']):
            raise ValueError('Tutorial drain queued metadata differs')
        values = [struct.unpack('<IIIB', read(vector + i * 24 + 8, 13)) for i in range(count)]
        if values != state['values'][pointer]:
            raise ValueError('Tutorial drain queued record projection differs')
        state['applied'].append(pointer)
        state['waiting_release'] = pointer
        h.finish()

    def destructor(machine):
        pointer = reg('RCX')
        if reg('RDX') != 1 or pointer != state['waiting_release'] or pointer in state['released']:
            raise ValueError('Tutorial drain destructor order or ownership differs')
        state['released'].append(pointer)
        state['waiting_release'] = None
        h.write(pointer, b'\xdd' * 48)
        h.finish()

    def shrink(machine):
        if ((reg('RCX'), reg('RDX')) != (model + 0x198, 0) or number(model + 0x1a0, 4)
                or state['waiting_release'] is not None or state['released'] != state['expected']):
            raise ValueError('Tutorial drain shrank before queue was reset and released')
        state['shrink'] += 1
        h.write(model + 0x198, bytes(16))
        h.finish()

    install(h, fixtures, dict(state_provider=state_provider, application=application,
                             destructor=destructor, shrink=shrink))
    cases = []
    for expected in expected_cases('drain'):
        order, count, flag = expected['order'], expected['records'], expected['flag']
        regions = ((model, 0x400), (state_object, 0x80), (queue, 32),
                   *((pointer, 48) for pointer in packets), *((pointer, 64 * 24) for pointer in records))
        h.reset_regions()
        for at, size in regions:
            seed(at, bytes(size))
        for at, size in regions:
            h.allow_write(at, size)
        state.clear()
        state.update(expected=[packets[index] for index in order if index is not None], applied=[], released=[],
            waiting_release=None, shrink=0, state_calls=0, count=count, flag=flag, values={})
        uc.mem_write(state_object + 0x30, bytes([expected['initial_phase']]))
        uc.mem_write(model + 0x198, struct.pack('<QII', queue, len(order), 4))
        for index, item in enumerate(order):
            uc.mem_write(queue + index * 8, struct.pack('<Q', 0 if item is None else packets[item]))
        for index, pointer in enumerate(packets):
            h.call(functions['packet_constructor'], pointer)
            if number(pointer) != table:
                raise ValueError('Tutorial drain packet constructor table differs')
            uc.mem_write(pointer + 0x18, bytes([flag]))
            uc.mem_write(pointer + 0x20, struct.pack('<QII', records[index] if count else 0, count, count))
            state['values'][pointer] = [(1001 + i, index, i, 1) for i in range(count)]
            for item, value in enumerate(state['values'][pointer]):
                uc.mem_write(records[index] + item * 24, struct.pack('<QIIIB3x', record_table, *value))
        # The consumer may update its queue header and the explicit destructor
        # fixture may poison packets. Record arrays and phase remain read-only.
        h.reset_regions()
        h.allow_write(model, 0x400)
        h.allow_read(state_object, 0x80)
        h.allow_read(queue, 32)
        for pointer in packets:
            h.allow_write(pointer, 48)
        for pointer in records:
            h.allow_read(pointer, 64 * 24)
        before_records = [read(pointer, 64 * 24) for pointer in records]
        before = read(model, 0x400) + read(queue, 32) + b''.join(read(p, 48) for p in packets)
        h.call(functions['consumer'], model, budget=100000)
        if expected['resumed']:
            after = read(model, 0x400) + read(queue, 32) + b''.join(read(p, 48) for p in packets)
            if before != after or state['applied'] or state['released'] or state['shrink']:
                raise ValueError('Tutorial drain changed queue before ready phase')
            uc.mem_write(state_object + 0x30, b'\x06')
            h.call(functions['consumer'], model, budget=100000)
        if (state['applied'] != state['expected'] or state['released'] != state['expected']
                or state['shrink'] != 1 or read(model + 0x198, 16) != bytes(16)):
            raise ValueError('Tutorial drain did not apply, release and clear once')
        previous = (state['applied'].copy(), state['released'].copy(), state['shrink'])
        h.call(functions['consumer'], model, budget=100000)
        if previous != (state['applied'], state['released'], state['shrink']):
            raise ValueError('Tutorial drain empty queue processed twice')
        if state['state_calls'] != 2 + int(expected['resumed']):
            raise ValueError('Tutorial drain native state gate call count differs')
        if any(read(pointer, len(body)) != body for pointer, body in zip(records, before_records)):
            raise ValueError('Tutorial drain modified immutable record storage')
        guards(regions)
        cases.append(dict(expected, released=len(state['released'])))
    return dict(cases=cases, metrics=h.validate())


def verify(h, context):
    family = context.get('family', context.get('scope'))
    try:
        scenario = {
            'startup': verify_startup, 'tutorial-startup': verify_startup,
            'populated': verify_populated, 'tutorial-populated': verify_populated,
            'drain': verify_drain, 'tutorial-drain': verify_drain,
        }[family]
    except KeyError as error:
        raise ValueError('Unknown Tutorial native state family') from error
    result = scenario(h, context)
    if result['cases'] != expected_cases(family):
        raise ValueError('Tutorial state exact case matrix differs')
    return result
