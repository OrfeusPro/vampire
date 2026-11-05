"""Apply QuestSync progress to an existing matching task through native code."""
import struct
from itertools import product

FAMILY = 'quest-matching-state'
CALLBACK = 0x2803E000
KEYS = (0, 110120005, 0xFFFFFFFFFFFFFFFF)
STATES = (0, 2, 255)
INDEXES = (0, 1, 127, 128, 254, 255)
ALIGNMENTS = (0, 3)


def expected_cases(family=FAMILY):
    if family != FAMILY:
        raise ValueError('Unknown Quest matching-state case family')
    return [
        dict(key=str(key), old=old, state=state, index=index, alignment=alignment,
             callback='start' if old != 2 and state == 2 else 'update')
        for key, old, state, index, alignment in product(KEYS, STATES, STATES, INDEXES, ALIGNMENTS)
    ]


def expected_calls(family=FAMILY):
    return len(expected_cases(family)) * 2


def verify(h, context):
    """Copy and getter execute natively, with observed task callback boundaries."""
    family = context.get('family', FAMILY)
    cases = expected_cases(family)
    functions = {role: int(address, 16) for role, address in context['functions'].items()}
    leaves = {role: int(address, 16) for role, address in context['leaf_roles'].items()}
    fixtures = {role: int(address, 16) for role, address in context['fixtures'].items()}
    callback_returns = {int(address, 16): role
                        for role, address in context['callback_returns'].items()}
    if (set(functions) != {'state', 'progress'} or set(leaves) != {'copy', 'index_getter'}
            or set(context['callback_returns']) != {'task_start', 'task_update'}
            or len(callback_returns) != 2
            or fixtures.get('task_start') != CALLBACK or fixtures.get('task_update') != CALLBACK):
        raise ValueError('Quest matching-state native role scope differs')
    uc, x = h.uc, h.x
    record = h.scratch + 0x1000
    task = h.scratch + 0x3000
    vtable = h.scratch + 0x5000
    source = h.scratch + 0x9000
    selected = {}
    callbacks = []

    def reject(condition, message):
        if not condition:
            raise ValueError('Quest matching-state ' + message)

    def callback(machine):
        stack = machine.reg_read(x.UC_X86_REG_RSP)
        returning, = struct.unpack('<Q', machine.mem_read(stack, 8))
        role = callback_returns.get(returning)
        reject(role is not None, 'callback return PC differs')
        reject(machine.reg_read(x.UC_X86_REG_RCX) == task, 'callback receiver differs')
        reject(bytes(machine.mem_read(task + 0x20, 32)) == selected['raw'],
               'callback preceded the native progress copy')
        reject(bytes(machine.mem_read(record + 0x28, 1)) == bytes([selected['old']]),
               'record state was stored before callback return')
        callbacks.append('start' if role == 'task_start' else 'update')
        h.finish()

    h.add_fixture(CALLBACK, callback)
    for role, address in fixtures.items():
        if address == CALLBACK:
            continue
        reject(address in h.available_fixtures, 'excluded fixture lacks a native caller')

        def unexpected(machine, role=role):
            raise ValueError('Quest matching-state excluded branch reached: ' + role)

        h.add_fixture(address, unexpected)
    vtable_bytes = bytearray(0x38)
    struct.pack_into('<Q', vtable_bytes, 0x10, leaves['copy'])
    struct.pack_into('<Q', vtable_bytes, 0x28, CALLBACK)
    struct.pack_into('<Q', vtable_bytes, 0x30, CALLBACK)
    native_entries = (functions['state'], functions['progress'], leaves['copy'], leaves['index_getter'])
    entries_before = {at: h.entry_counts.get(at, 0) for at in native_entries}
    completed = []
    for case in cases:
        key = int(case['key'])
        progress = source + case['alignment']
        payload = bytearray((offset * 17 + case['index']) & 255 for offset in range(32))
        struct.pack_into('<Q', payload, 0, key)
        payload[8] = 6
        payload[9] = case['index']
        payload = bytes(payload)
        record_bytes = bytearray(b'R' * 0x40)
        task_bytes = bytearray(b'T' * 0x60)
        struct.pack_into('<Q', record_bytes, 0x30, task)
        record_bytes[0x28] = case['old']
        struct.pack_into('<Q', task_bytes, 0, vtable)
        struct.pack_into('<Q', task_bytes, 0x20, key)
        record_before = b'\xa1' * 16 + record_bytes + b'\xa2' * 16
        task_before = b'\xb1' * 16 + task_bytes + b'\xb2' * 16
        input_before = b'\xc1' * 16 + payload + b'\xc2' * 16
        table_before = b'\xd1' * 16 + vtable_bytes + b'\xd2' * 16
        uc.mem_write(record - 16, bytes(record_before))
        uc.mem_write(task - 16, bytes(task_before))
        uc.mem_write(progress - 16, input_before)
        uc.mem_write(vtable - 16, bytes(table_before))
        h.reset_regions()
        h.allow_read(record, len(record_bytes))
        h.allow_write(record + 0x28, 1)
        h.allow_read(task, len(task_bytes))
        h.allow_write(task + 0x20, 32)
        h.allow_read(progress, len(payload))
        h.allow_read(vtable, len(vtable_bytes))
        selected.update(raw=payload, old=case['old'])
        callbacks.clear()
        h.call(functions['state'], record, rdx=case['state'], r8=progress, budget=1000)
        reject(callbacks == [case['callback']], 'actual native callback branch differs')
        expected_record = bytearray(record_before)
        expected_record[16 + 0x28] = case['state']
        expected_task = bytearray(task_before)
        expected_task[16 + 0x20:16 + 0x40] = payload
        reject(bytes(uc.mem_read(record - 16, len(expected_record))) == bytes(expected_record),
               'record or guard changed outside the state byte')
        reject(bytes(uc.mem_read(task - 16, len(expected_task))) == bytes(expected_task),
               'task or guard changed outside the copied progress')
        reject(bytes(uc.mem_read(progress - 16, len(input_before))) == input_before,
               'input progress or its guard changed')
        reject(bytes(uc.mem_read(vtable - 16, len(table_before))) == bytes(table_before),
               'synthetic virtual table or guard changed')
        reject(h.call(leaves['index_getter'], record, budget=1000) & 255 == case['index'],
               'sender index getter differs after native application')
        completed.append(dict(case))
    for at in native_entries:
        reject(h.entry_counts.get(at, 0) - entries_before[at] == len(cases),
               'native entry count differs from complete matrix')
    metrics = h.validate()
    reject(metrics['call_counts'] == expected_calls(family)
           and metrics['abi_checks'] == expected_calls(family)
           and metrics['fixture_calls'] == len(cases), 'call, ABI or fixture coverage differs')
    return dict(cases=completed, metrics=metrics)
