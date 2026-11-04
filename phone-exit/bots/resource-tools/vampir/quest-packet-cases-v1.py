"""Synthetic whole packet scenarios for the source-bound quest reader harness."""
import itertools
import struct


FAMILIES = {'quest-sync': 1854, 'tutorial-update': 9905}


def quest_body(groups, quests, raw):
    parts = [struct.pack('<H', groups)]
    for group in range(groups):
        parts.append(struct.pack('<BH', raw, quests))
        for item in range(quests):
            parts.append(struct.pack('<QBBQQBIII', 2**64 - 1 - group * 8 - item,
                raw, 255 - item, 2**63 + group, item, raw, item, group, 2**32 - 1))
    parts.append(struct.pack('<Q', 2**64 - 1 if raw else 0))
    return b''.join(parts)


def tutorial_body(flag, count, state):
    return struct.pack('<BH', flag, count) + b''.join(
        struct.pack('<IIIB', 2**32 - 1 - item, item, 1001002 + item, state)
        for item in range(count))


def scenarios(family):
    if family == 'quest-sync':
        builder = quest_body
        values = itertools.product((0, 1, 2, 8), (0, 1, 2, 8), (0, 1, 6, 7, 12, 255))
        prefix = builder(2, 2, 255)
    elif family == 'tutorial-update':
        builder = tutorial_body
        values = itertools.chain(itertools.product((0, 1, 255), (0, 1, 2, 8), (0, 1, 2, 3, 4, 255)), [(1, 64, 255)])
        prefix = builder(1, 64, 255)
    else:
        raise ValueError('Unknown quest packet family')
    for spec in values:
        body = builder(*spec)
        yield dict(kind='valid', spec=list(spec), size=len(body), accepted=True, consumed=len(body)), body
    for size in range(len(prefix)):
        yield dict(kind='truncated', spec=[], size=size, accepted=False, consumed=size), prefix[:size]
    trailing = prefix + b'\xe3\x6c'
    yield dict(kind='trailing', spec=[], size=len(trailing), accepted=True, consumed=len(prefix)), trailing


def verify(harness, context, root, source_store):
    family = context['family']
    quest = family == 'quest-sync'
    functions = {name: int(address, 16) for name, address in context['functions'].items()}
    leaves = {int(address, 16): data for address, data in context['leaves'].items()}
    bindings = {(int(table, 16), int(slot, 16)): int(target, 16) for table, slot, target in context['bindings']}
    packet_table, = [table for (table, slot), target in bindings.items()
                     if slot == 0x20 and target == functions['reader']]
    id_getter = bindings[packet_table, 0x28]
    nested_table, = [table for (table, slot), target in bindings.items()
                     if slot == 0x20 and target == functions['nested_reader']]
    h = harness.make_harness(context, context['exports'], set(functions.values()), leaves,
                            root, source_store=source_store)
    packet, archive, buffer = (h.scratch + offset for offset in (0x2000, 0x4000, 0x6000))
    allocations = {}
    fixture_counts = {}
    guards = []
    heap = h.scratch + 0x10000

    def number(address, size=8):
        return int.from_bytes(h.uc.mem_read(address, size), 'little')

    def reg(name):
        return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def protect(address, data):
        h.uc.mem_write(address, data)
        guards.append((address, data))

    def allocate(container, count, stride):
        nonlocal heap
        limit = 8 if quest else 64
        if not 0 <= count <= limit or number(container) or number(container + 12, 4):
            raise ValueError('Only bounded fresh packet storage is a fixture')
        old_count = number(container + 8, 4)
        if old_count not in (0, count):
            raise ValueError('Packet fixture container count differs')
        size = count * stride
        pointer = 0
        if size:
            pointer = heap + 16
            heap = (pointer + size + 31) & ~15
            if heap > h.scratch + 0x30000:
                raise ValueError('Packet fixture heap budget exceeded')
            protect(pointer - 16, b'\xb1' * 16)
            protect(pointer + size, b'\xb2' * 16)
            h.allow_write(pointer, size)
            h.write(pointer, bytes(size))
            allocations[pointer] = [count, stride, False]
        h.write(container, struct.pack('<QII', pointer, old_count, count))

    def live(pointer, count, stride):
        if count and allocations.get(pointer) != [count, stride, False]:
            raise ValueError('Packet references storage outside its live allocation')
        if not count and pointer:
            raise ValueError('Empty packet collection has a nonempty pointer')

    def fixture(role):
        def execute(machine):
            fixture_counts[role] = fixture_counts.get(role, 0) + 1
            rcx, rdx = reg('RCX'), reg('RDX')
            count = rdx & 0xffffffff
            if role.endswith('no_growth'):
                raise ValueError('Fresh packet collection tried to grow')
            if role in ('group_allocate', 'quest_allocate', 'temporary_quest_allocate'):
                if role == 'group_allocate' and rcx != packet + 24:
                    raise ValueError('Quest group allocation container differs')
                allocate(rcx, count, 32 if role == 'group_allocate' else 72)
            elif role == 'reserve':
                if rdx != packet + 32:
                    raise ValueError('Tutorial reserve container differs')
                allocate(rdx, reg('R8'), 24)
            elif role in ('empty_groups_cleanup', 'empty_items_cleanup'):
                if rcx or count:
                    raise ValueError('Only empty previous packet cleanup is a fixture')
            elif role == 'quest_cleanup':
                if rcx:
                    allocation = allocations.get(rcx)
                    if not allocation or allocation[1:] != [72, False] or count > allocation[0]:
                        raise ValueError('Quest cleanup storage differs')
                elif count:
                    raise ValueError('Quest cleanup count has no storage')
            elif role == 'free':
                allocation = allocations.get(rcx)
                if not allocation or allocation[2] or allocation[1] != 72:
                    raise ValueError('Quest free storage differs')
                size = allocation[0] * allocation[1]
                h.write(rcx, b'\xdd' * size)
                h.release_region(rcx, size)
                allocation[2] = True
            else:
                raise ValueError('Unknown packet fixture role')
            h.finish()
        return execute

    for role, address in context['fixtures'].items():
        h.add_fixture(int(address, 16), fixture(role))

    def compare(body):
        if not quest:
            flag, count = struct.unpack_from('<BH', body)
            pointer, length, capacity = struct.unpack('<QII', h.uc.mem_read(packet + 32, 16))
            if (number(packet + 24, 1), length, capacity) != (int(bool(flag)), count, count):
                raise ValueError('Tutorial packet header differs')
            live(pointer, count, 24)
            table, = [at for (at, slot), target in bindings.items()
                      if slot == 0x20 and target == functions['item_reader']]
            for i, (a, b, c, state) in enumerate(struct.iter_unpack('<IIIB', body[3:])):
                at = pointer + 24 * i
                if number(at) != table or struct.unpack('<IIIB', h.uc.mem_read(at + 8, 13)) != (a, b, c, min(state, 3)):
                    raise ValueError('Tutorial record projection differs')
            if fixture_counts != dict(empty_items_cleanup=1, reserve=1):
                raise ValueError('Tutorial fixture counts differ')
            return
        groups = number(packet + 32, 4)
        pointer = number(packet + 24)
        if groups != struct.unpack_from('<H', body)[0] or number(packet + 36, 4) != groups:
            raise ValueError('Quest group count differs')
        live(pointer, groups, 32)
        tables = {role: next(at for (at, slot), target in bindings.items()
                            if slot == 0x20 and target == functions[role])
                  for role in ('group_reader', 'quest_reader', 'progress_reader')}
        cursor = 2
        nonempty = 0
        for i in range(groups):
            kind, count = struct.unpack_from('<BH', body, cursor)
            cursor += 3
            nonempty += int(count > 0)
            group = pointer + i * 32
            records, length, capacity = struct.unpack('<QII', h.uc.mem_read(group + 16, 16))
            if (number(group), number(group + 8, 1), length, capacity) != (tables['group_reader'], min(kind, 12), count, count):
                raise ValueError('Quest group projection differs')
            live(records, count, 72)
            for j in range(count):
                key, state, progress, a, b, flag, c, d, e = struct.unpack_from('<QBBQQBIII', body, cursor)
                cursor += 39
                at = records + j * 72
                actual = (number(at), number(at + 8), number(at + 16, 1), number(at + 24),
                          number(at + 32, 1), number(at + 40), number(at + 48), number(at + 56, 1),
                          *struct.unpack('<III', h.uc.mem_read(at + 60, 12)))
                if actual != (tables['quest_reader'], key, min(state, 6), tables['progress_reader'],
                              progress, a, b, int(bool(flag)), c, d, e):
                    raise ValueError('Quest record projection differs after temporary cleanup')
        if number(packet + 40) != struct.unpack_from('<Q', body, cursor)[0]:
            raise ValueError('Quest packet suffix differs')
        if cursor + 8 != len(body):
            raise ValueError('Quest oracle did not consume the complete packet')
        wanted = dict(empty_groups_cleanup=2)
        if groups:
            wanted['group_allocate'] = 1
            wanted['quest_cleanup'] = 3 * groups
            if nonempty:
                wanted.update(quest_allocate=nonempty, temporary_quest_allocate=nonempty, free=nonempty)
        if fixture_counts != wanted or sum(v[2] for v in allocations.values()) != fixture_counts.get('free', 0):
            raise ValueError(f'Quest cleanup/free counts differ {fixture_counts}')

    rows = []
    for expected, body in scenarios(family):
        try:
            allocations.clear()
            fixture_counts.clear()
            guards.clear()
            heap = h.scratch + 0x10000
            h.reset_regions()
            for address in (packet, archive):
                h.allow_write(address, 64)
                protect(address - 16, b'\xa1' * 16)
                protect(address + 64, b'\xa2' * 16)
                h.uc.mem_write(address, bytes(64))
            h.allow_read(buffer, len(body))
            protect(buffer - 16, b'\xa3' * 16 + body + b'\xa4' * 16)
            if h.call(functions['packet_constructor'], packet) != packet:
                raise ValueError('Packet constructor return differs')
            if (number(packet), number(packet + 16), h.call(id_getter, packet)) != (packet_table, nested_table, FAMILIES[family]):
                raise ValueError('Packet ID or initial vptr differs')
            h.call(functions['input_constructor'], archive, rdx=buffer, r8=len(body), r9=1, stack_args=(0,))
            accepted = bool(h.call(functions['reader'], packet, rdx=archive, budget=1000000) & 255)
            consumed = number(archive + 0x30) - buffer
            if (accepted, consumed) != (expected['accepted'], expected['consumed']):
                raise ValueError(f'Packet result differs: accepted={accepted}, consumed={consumed}')
            if accepted:
                compare(body[:consumed])
            if any(bytes(h.uc.mem_read(at, len(value))) != value for at, value in guards):
                raise ValueError('Packet input or allocation canary changed')
            for at, (count, stride, freed) in allocations.items():
                if freed and bytes(h.uc.mem_read(at, count * stride)) != b'\xdd' * (count * stride):
                    raise ValueError('Freed packet allocation poison changed')
        except Exception as error:
            raise ValueError(f'{family} scenario {expected}: {error}') from error
        rows.append(expected)
    return dict(family=family, packet_id=FAMILIES[family], cases=rows, exports=h.evidence, **h.validate())
