"""Tutorial 9905 receiver gate and native deferred copy with bounded fixtures."""
from itertools import product
import struct


PACKET_ID = 9905
PACKET_SIZE = 48
RECORD_SIZE = 24
QUEUE_CAPACITY = 4
MAX_RECORDS = 64
GUARD_SIZE = 16
BEFORE = b'\xa1' * GUARD_SIZE
AFTER = b'\xa2' * GUARD_SIZE
POISON = b'\x5a'
RECORD_FIELDS = struct.Struct('<QIIIB')
ARRAY = struct.Struct('<QII')
TYPED_COPY_LEA = bytes.fromhex('4c8bd14585c07448488d420c4c2bd2488d15')


def scenarios():
    for via_handler in (False, True):
        for state, force, flag, count, prior in product(
                (0, 5, 6, 7), (0,) if via_handler else (0, 1),
                (0, 1), (0, 1, 8, MAX_RECORDS), (0, 1)):
            yield dict(via_handler=via_handler, native_state=state, force=force,
                       flag=flag, count=count, prior=prior)


def expected_cases():
    result = []
    for case in scenarios():
        events = [] if case['force'] else ['state_provider']
        deferred = not case['force'] and case['native_state'] < 6
        if deferred:
            events.extend(('packet_allocate', 'empty_cleanup'))
            if case['count']:
                events.append('reserve')
        else:
            events.append('apply')
        result.append(dict(case, deferred=deferred, fixture_events=events))
    return result


def one(candidates, role):
    if len(candidates) != 1:
        raise ValueError('Tutorial ' + role + ' is missing or ambiguous')
    return candidates[0]


def tables(context):
    leaves = {int(at, 16): bytes.fromhex(body) for at, body in context['leaves'].items()}
    bindings = {(int(table, 16), int(slot, 16)): int(target, 16)
                for table, slot, target in context['bindings']}
    getter_body = b'\xb8' + struct.pack('<I', PACKET_ID) + b'\xc3'
    getter = one([at for at, body in leaves.items() if body == getter_body], 'packet ID leaf')
    packet = one([table for (table, slot), at in bindings.items()
                  if slot == 0x28 and at == getter], 'packet table')
    base = one([at + 7 + struct.unpack_from('<i', body, 3)[0]
                for at, body in leaves.items()
                if body[:3] == b'\x48\x8d\x05' and len(body) > 7], 'packet base table')
    lea_end = len(TYPED_COPY_LEA) + 4
    record = one([at + lea_end + struct.unpack_from('<i', body, len(TYPED_COPY_LEA))[0]
                  for at, body in leaves.items()
                  if body.startswith(TYPED_COPY_LEA) and len(body) >= lea_end], 'record table')
    if record == base or any((table, 0x20) not in bindings for table in (record, base)):
        raise ValueError('Tutorial record/base table bindings differ')
    return packet, base, record


def verify(h, context):
    functions = {role: int(at, 16) for role, at in context['functions'].items()}
    fixtures = {role: int(at, 16) for role, at in context['fixtures'].items()}
    packet_table, base_table, record_table = tables(context)
    model, state_object, packet, records, queue, clone, clone_records = (
        h.scratch + offset for offset in (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x7000, 0x8000))
    uc = h.uc
    events = []
    current = {}

    def reg(name):
        return uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def read(address, size):
        return bytes(uc.mem_read(address, size)) if size else b''

    def seed(address, body):
        uc.mem_write(address - GUARD_SIZE, BEFORE + body + AFTER)

    def check(address, expected, role):
        guarded = BEFORE + expected + AFTER
        if read(address - GUARD_SIZE, len(guarded)) != guarded:
            raise ValueError('Tutorial ' + role + ' bytes or guards differ')

    def state_provider(machine):
        if events or (reg('RCX'), reg('RDX'), reg('R8') & 0xff) != (model, packet, 0):
            raise ValueError('Tutorial state provider called with unexpected gate inputs')
        events.append('state_provider')
        h.finish(state_object)

    def packet_allocate(machine):
        if reg('RCX') != PACKET_SIZE or events != ['state_provider']:
            raise ValueError('Tutorial clone allocator size or order differs')
        events.append('packet_allocate')
        h.allow_write(clone, PACKET_SIZE)
        h.allow_write(model + 0x1a0, 4)
        h.allow_write(queue + 8 * current['prior'], 8)
        h.finish(clone)

    def empty_cleanup(machine):
        if (reg('RCX'), reg('RDX')) != (0, 0) or events != ['state_provider', 'packet_allocate']:
            raise ValueError('Tutorial cleanup must see fresh empty clone storage')
        events.append('empty_cleanup')
        h.finish()

    def reserve(machine):
        count = current['count']
        if (not 0 < count <= MAX_RECORDS or (reg('RCX'), reg('RDX'), reg('R8')) != (clone + 0x20, count, 0)
                or ARRAY.unpack(read(clone + 0x20, ARRAY.size)) != (0, count, 0)
                or events != ['state_provider', 'packet_allocate', 'empty_cleanup']):
            raise ValueError('Tutorial reserve arguments, fresh storage or call order differ')
        events.append('reserve')
        h.allow_write(clone_records, count * RECORD_SIZE)
        h.write(clone + 0x20, struct.pack('<Q', clone_records))
        h.write(clone + 0x2c, struct.pack('<I', count))
        h.finish()

    def apply(machine):
        if (reg('RCX'), reg('RDX')) != (model, packet + 0x10):
            raise ValueError('Tutorial immediate application arguments differ')
        events.append('apply')
        h.finish()

    active = dict(state_provider=state_provider, packet_allocate=packet_allocate,
                  empty_cleanup=empty_cleanup, reserve=reserve, apply=apply)
    if any(fixtures.get('tutorial_' + role) not in h.available_fixtures for role in active):
        raise ValueError('Tutorial expected fixture has no reviewed caller')
    for name, address in fixtures.items():
        if address not in h.available_fixtures:
            continue

        def excluded(machine, role=name):
            raise ValueError('Tutorial excluded fixture reached: ' + role)

        h.add_fixture(address, active.get(name.removeprefix('tutorial_'), excluded))

    fresh = POISON * PACKET_SIZE
    defaults = bytearray(fresh)
    struct.pack_into('<Q', defaults, 0, packet_table)
    struct.pack_into('<Q', defaults, 0x10, base_table)
    defaults[0x18] = 0
    ARRAY.pack_into(defaults, 0x20, 0, 0, 0)
    actual = []
    for expected in expected_cases():
        current = expected
        count, prior, flag = (current[key] for key in ('count', 'prior', 'flag'))
        events.clear()
        h.reset_regions()
        seed(packet, fresh)
        h.allow_write(packet, PACKET_SIZE)
        if h.call(functions['packet_constructor'], packet) != packet:
            raise ValueError('Tutorial packet constructor return differs')
        check(packet, defaults, 'constructed packet')

        packet_bytes = bytearray(defaults)
        struct.pack_into('<HB', packet_bytes, 8, 0x1234, 0x56)
        packet_bytes[0x18] = flag
        ARRAY.pack_into(packet_bytes, 0x20, records if count else 0, count, count)
        model_bytes = bytearray(b'\xc1' * 0x1a8)
        ARRAY.pack_into(model_bytes, 0x198, queue, prior, QUEUE_CAPACITY)
        state_bytes = bytearray(b'\xc2' * 0x31)
        state_bytes[0x30] = current['native_state']
        initial_queue = struct.pack('<4Q', 0xfeed if prior else 0, 0xdead, 0xbeef, 0xbead)
        rows = [RECORD_FIELDS.pack(record_table, 1001 + i, i, 1001002 + i, i % 4)
                for i in range(count)]
        input_rows = b''.join(row + b'\xf1\xf2\xf3' for row in rows)
        copied_rows = b''.join(row + POISON * 3 for row in rows)
        seed(packet, packet_bytes)
        seed(model, model_bytes)
        seed(state_object, state_bytes)
        seed(queue, initial_queue)
        seed(records, input_rows)
        seed(clone, fresh)
        seed(clone_records, POISON * (count * RECORD_SIZE))
        h.set_global(model)

        h.reset_regions()
        h.allow_read(packet, PACKET_SIZE)
        h.allow_read(records, len(input_rows))
        h.allow_read(state_object + 0x30, 1)
        h.allow_read(model + 0x198, ARRAY.size)
        h.allow_read(queue, len(initial_queue))
        if current['via_handler']:
            h.call(functions['handler'], r8=packet)
        else:
            h.call(functions['receiver'], model, rdx=packet, r8=current['force'])

        deferred = 'packet_allocate' in events
        row = {key: current[key] for key in ('via_handler', 'native_state', 'force', 'flag', 'count', 'prior')}
        result = dict(row, deferred=deferred, fixture_events=events.copy())
        if result != expected:
            raise ValueError('Tutorial state gate or fixture event order differs: ' + str(result))
        check(packet, packet_bytes, 'source packet')
        check(records, input_rows, 'source records')
        check(state_object, state_bytes, 'state provider object')
        expected_queue = bytearray(initial_queue)
        expected_clone = bytearray(fresh)
        if deferred:
            struct.pack_into('<I', model_bytes, 0x1a0, prior + 1)
            struct.pack_into('<Q', expected_queue, 8 * prior, clone)
            expected_clone = bytearray(packet_bytes)
            ARRAY.pack_into(expected_clone, 0x20, clone_records if count else 0, count, count)
            # Destroy the source after native execution to confirm independent retained storage.
            uc.mem_write(packet, b'\xff' * PACKET_SIZE)
            if input_rows:
                uc.mem_write(records, b'\xff' * len(input_rows))
        check(model, model_bytes, 'queue owner')
        check(queue, expected_queue, 'queue slots')
        check(clone, expected_clone, 'deferred clone')
        check(clone_records, copied_rows if deferred else POISON * len(input_rows), 'deferred records')
        actual.append(result)

    return dict(cases=actual, metrics=h.validate())
