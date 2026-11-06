"""Current model wrapper composition; map, setter and callback effects are fixtures."""
import hashlib
import struct
from types import SimpleNamespace

SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
FUNCTIONS = dict(wrapper='0x1455b4d30', state='0x1455f4a70', progress='0x1455fd340')
LEAVES = {'0x1455cec10': '0f10020f1141200f104a100f114930c3',
          '0x1455e7500': '488b41304885c07503b0ffc30fb64029c3'}
SETTER = dict(address='0x1455e7560',
    bytes='440fb6c284d274274183e801741a4183e801740d4183f801751c488b0148ff6030488b0148ff6028488b0148ff6020488b0148ff6018c3',
    virtual_tails=[dict(address='0x1455e757d', slot='0x30'),
        dict(address='0x1455e7584', slot='0x28'), dict(address='0x1455e758b', slot='0x20'),
        dict(address='0x1455e7592', slot='0x18')], return_address='0x1455e7596')
CONTROL = {'none': None, 'last': (1, 1), 'weak_retained': (1, 2), 'strong_retained': (2, 1)}
FLAGS = dict(scope='model_wrapper_existing_matching_task', map_operations='fixtures_without_retention',
    task_callbacks='fixtures', record_control_callbacks='fixtures', setter_effects='fixture',
    setter_source_window_verified=True, setter_native_execution=False,
    native_state_progress_and_copy=True, native_record_refcount_release=True,
    active_task_verified=False, factory_executed=False, replacement_executed=False,
    real_map_ownership_verified=False, runtime_admitted=False, action_admitted=False, network_used=False)
CALLBACK = 0x2803e000


def cases():
    result = []
    pairs = ((0, 0, 2, 'last', 110120, 110120005, 0),
             (1, 2, 2, 'weak_retained', 0, 0xffffffffffffffff, 1),
             (2, 2, 0, 'strong_retained', 0xffffffffffffffff, 0, 255),
             (3, 0, 255, 'none', 110120, 110120020, 1),
             (4, 255, 2, 'last', 0, 110120005, 255),
             (255, 2, 255, 'weak_retained', 0xffffffffffffffff, 110120020, 0))
    for alignment in (0, 3):
        for control in CONTROL:
            result.append(dict(alignment=alignment, record=False, control=control,
                key='110120', task_key='110120005', old_state=0, state=2, flag=255, index=1))
        for flag, old, state, control, key, task_key, index in pairs:
            result.append(dict(alignment=alignment, record=True, control=control,
                key=str(key), task_key=str(task_key), old_state=old, state=state, flag=flag, index=index))
    return result


def expected(case):
    events = []
    callback = None
    if case['record']:
        callback = 'start' if case['old_state'] != 2 and case['state'] == 2 else 'update'
        events += ['remove_map', 'insert_map', callback, 'setter', 'notify']
    counts = CONTROL[case['control']]
    after = None
    if counts is not None:
        strong, weak = counts
        strong -= 1
        if strong == 0:
            events.append('destroy_record_control')
            weak -= 1
            if weak == 0:
                events.append('delete_record_control')
        after = [strong, weak]
    return dict(case=case, events=events, callback=callback, control=after,
        getter_index=case['index'] if case['record'] else None,
        resulting_state=case['state'] if case['record'] else None,
        supplied_setter_flag=case['flag'] if case['record'] else None)


def validate(result):
    wanted = [expected(case) for case in cases()]
    metrics = result.get('metrics', {})
    entries = {'0x1455b4d30': len(wanted), **{name: 12 for name in (
        '0x1455f4a70', '0x1455fd340', '0x1455cec10', '0x1455e7500',
        '0x1455d3d90', '0x145581540', '0x1455e7560', '0x144a6ad80')},
        '0x2803e000': sum(sum(row['events'].count(name) for name in (
            'start', 'update', 'destroy_record_control', 'delete_record_control')) for row in wanted)}
    if (any(result.get(key) != value for key, value in FLAGS.items())
            or result.get('cases') != wanted or result.get('setter_static') != SETTER
            or metrics.get('call_counts') != 32 or metrics.get('abi_checks') != 32
            or set(metrics) != {'call_counts', 'abi_checks', 'read_checks', 'write_checks', 'fixture_calls', 'entry_counts'}
            or any(type(metrics.get(name)) is not int or metrics[name] <= 0
                   for name in ('read_checks', 'write_checks', 'fixture_calls'))
            or metrics.get('entry_counts') != entries):
        raise ValueError('Quest model wrapper proof scope or matrix differs')


def execute(index, root, context, exports, source):
    native_context = context['native']
    if (native_context.get('source_sha256') != SOURCE or native_context.get('functions') != FUNCTIONS
            or native_context.get('leaves') != LEAVES or context.get('setter_static') != SETTER
            or hashlib.sha256(source).hexdigest() != SOURCE):
        raise ValueError('Quest model wrapper source, roots or static setter differ')
    native = index.extension('build-native-entry-code')
    image = native.Image(source)
    at = int(SETTER['address'], 16)
    encoded = bytes.fromhex(SETTER['bytes'])
    if image.containing(at) is not None:
        raise ValueError('Quest model setter is no longer the bounded non-unwind window')
    rows = index.extension('quest-action-transfer-rules-v1').decode(native, image, at, len(encoded))
    tails = [dict(address=hex(row['address']), slot=hex(int(row['operands'].split('+ ')[1].split(']')[0], 16)))
             for row in rows if row['mnemonic'] == 'jmp' and row['direct_target'] is None]
    if (''.join(row['bytes'] for row in rows) != SETTER['bytes'] or tails != SETTER['virtual_tails']
            or rows[-1]['address'] != int(SETTER['return_address'], 16) or rows[-1]['mnemonic'] != 'ret'
            or any(row['call'] or row['branch'] and row['direct_target'] is not None
                and row['direct_target'] not in {item['address'] for item in rows} for row in rows)):
        raise ValueError('Quest model static setter bytes or branch boundaries differ')
    store = SimpleNamespace(root=root,
        source=lambda sha: source if sha == SOURCE else (_ for _ in ()).throw(ValueError('Wrong model source')),
        image=lambda api, sha: image if sha == SOURCE else (_ for _ in ()).throw(ValueError('Wrong model source')))
    h = index.extension('quest-tutorial-state-harness-v1').make_harness(
        index, store, native_context, exports, {})
    uc, x, base = h.uc, h.x, h.scratch
    model, wrapper0, record0, task0, progress0, task_table, control, control_table = [base + n for n in
        (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000)]
    selected, events = {}, []
    fixtures = {role: int(value, 16) for role, value in native_context['fixtures'].items()}
    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))
    def require(ok, reason):
        if not ok:
            raise ValueError('Quest model wrapper: ' + reason)
    def u64(at):
        return struct.unpack('<Q', uc.mem_read(at, 8))[0]
    def pair(at):
        return struct.unpack('<QQ', uc.mem_read(at, 16))
    def counts():
        return list(struct.unpack('<II', uc.mem_read(control + 8, 8)))
    def remove_map(machine):
        case = selected['case']
        require(reg('RCX') == model and reg('RDX') == int(case['key']), 'map removal receiver/key differs')
        require(events == [] and uc.mem_read(selected['record'] + 0x28, 1)[0] == case['old_state'],
                'map removal order differs')
        events.append('remove_map')
        h.finish()
    def insert_map(machine):
        require(reg('RCX') == model + 0x30 and reg('R9') == 0, 'map insertion receiver/flag differs')
        key_pointer, wrapper_pointer = pair(reg('R8'))
        require(u64(key_pointer) == int(selected['case']['key']) and wrapper_pointer == selected['wrapper']
                and pair(wrapper_pointer) == (selected['record'], control if CONTROL[selected['case']['control']] else 0),
                'map insertion key/capture differs')
        require(events == ['remove_map'], 'map insertion order differs')
        # Deliberately no map insertion, output write or extra reference retention.
        events.append('insert_map')
        h.finish()
    def setter(machine):
        case = selected['case']
        require(reg('RCX') == selected['record'] and reg('RDX') & 255 == case['flag'], 'setter receiver/flag differs')
        require(uc.mem_read(selected['record'] + 0x28, 1)[0] == case['state']
                and bytes(uc.mem_read(selected['task'] + 0x20, 32)) == selected['raw'],
                'setter ran before real state/copy')
        require(events == ['remove_map', 'insert_map', selected['callback']], 'setter order differs')
        events.append('setter')
        h.finish()
    def notify(machine):
        require(reg('RCX') == model + 8 and u64(reg('RDX')) == 0x141428ac8
                and u64(reg('R8')) == int(selected['case']['key']), 'notification descriptor/key differs')
        require(events == ['remove_map', 'insert_map', selected['callback'], 'setter'], 'notification order differs')
        events.append('notify')
        h.finish()
    def virtual(machine):
        returning = u64(reg('RSP'))
        case = selected['case']
        if returning in (0x1455fd38b, 0x1455fd3a6):
            role = 'start' if returning == 0x1455fd38b else 'update'
            require(reg('RCX') == selected['task'] and role == selected['callback'], 'task callback differs')
            require(events == ['remove_map', 'insert_map']
                    and uc.mem_read(selected['record'] + 0x28, 1)[0] == case['old_state']
                    and bytes(uc.mem_read(selected['task'] + 0x20, 32)) == selected['raw'],
                    'task callback must follow copy and precede state storage')
            events.append(role)
        elif returning == 0x1455b4e03:
            require(reg('RCX') == control and counts()[0] == 0, 'record control destruction differs')
            require(events == (['remove_map', 'insert_map', selected['callback'], 'setter', 'notify'] if case['record'] else []),
                    'record destruction order differs')
            events.append('destroy_record_control')
        elif returning == 0x1455b4e18:
            require(reg('RCX') == control and counts() == [0, 0] and reg('RDX') == 1,
                    'record control delete counters/flag differ')
            require(events[-1:] == ['destroy_record_control'], 'record control delete order differs')
            events.append('delete_record_control')
        else:
            raise ValueError('Quest model wrapper reached an excluded virtual/replacement callback')
        h.finish()
    def trap(machine):
        raise ValueError('Quest model wrapper reached excluded factory/replacement')
    callbacks = dict(remove_map=remove_map, insert_map=insert_map, setter=setter, notify=notify,
        virtual=virtual, factory=trap, bind_owner=trap, shared_move_release=trap)
    require(set(fixtures) == set(callbacks), 'fixture roles differ')
    for role, address in fixtures.items():
        h.add_fixture(address, callbacks[role])
    result = []
    for number, case in enumerate(cases()):
        at = case['alignment']
        record, task, progress, wrapper = record0 + at, task0 + at, progress0 + at, wrapper0 + at
        h.reset_regions()
        allocations = ((model, 0x1a0), (wrapper, 16), (record, 0x50), (task, 0x60),
                       (progress, 32), (task_table, 0x40), (control, 24), (control_table, 16))
        for location, size in allocations:
            uc.mem_write(location - 16, b'G' * (size + 32))
            h.allow_read(location, size)
        h.allow_write(record + 0x28, 1)
        h.allow_write(task + 0x20, 32)
        h.allow_write(control + 8, 8)
        raw = bytearray((number + i * 13) & 255 for i in range(32))
        struct.pack_into('<Q', raw, 0, int(case['task_key']))
        raw[8], raw[9] = 6, case['index']
        raw = bytes(raw)
        uc.mem_write(progress, raw)
        uc.mem_write(task, struct.pack('<Q', task_table))
        uc.mem_write(task + 0x20, bytes(32))
        uc.mem_write(task + 0x20, struct.pack('<Q', int(case['task_key'])))
        uc.mem_write(task_table, bytes(0x40))
        uc.mem_write(task_table + 0x10, struct.pack('<Q', 0x1455cec10))
        for slot in (0x28, 0x30, 0x38):
            uc.mem_write(task_table + slot, struct.pack('<Q', CALLBACK))
        uc.mem_write(record + 0x20, struct.pack('<Q', int(case['key'])))
        uc.mem_write(record + 0x28, bytes([case['old_state']]))
        uc.mem_write(record + 0x30, struct.pack('<QQ', task, 0))
        control_counts = CONTROL[case['control']]
        uc.mem_write(control_table, struct.pack('<QQ', CALLBACK, CALLBACK))
        uc.mem_write(control, struct.pack('<QIIQ', control_table, *(control_counts or (9, 9)), record if case['record'] else 0))
        uc.mem_write(wrapper, struct.pack('<QQ', record if case['record'] else 0, control if control_counts else 0))
        before = {location: bytes(uc.mem_read(location - 16, size + 32)) for location, size in allocations}
        want = expected(case)
        selected.clear()
        selected.update(case=case, record=record, task=task, wrapper=wrapper, raw=raw, callback=want['callback'])
        events.clear()
        h.call(0x1455b4d30, model, rdx=wrapper, r8=case['state'], r9=progress, stack_args=(case['flag'],), budget=20000)
        require(events == want['events'], 'callback/cleanup order differs')
        for location, size in allocations:
            expected_bytes = bytearray(before[location])
            if location == record and case['record']:
                expected_bytes[16 + 0x28] = case['state']
            elif location == task and case['record']:
                expected_bytes[16 + 0x20:16 + 0x40] = raw
            elif location == control and control_counts:
                struct.pack_into('<II', expected_bytes, 16 + 8, *want['control'])
            require(bytes(uc.mem_read(location - 16, size + 32)) == bytes(expected_bytes),
                    'output/control guards or immutable input changed')
        if case['record']:
            require(h.call(0x1455e7500, record) & 255 == case['index'], 'copied sender index differs')
        result.append(want)
    value = dict(FLAGS, setter_static=SETTER, cases=result, metrics=h.validate())
    validate(value)
    return value
