"""Bounded native parameter capture and dispatch; JSON and final consumers are fixtures."""
import hashlib
import struct
from types import SimpleNamespace

SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
FUNCTIONS = dict(factory='0x145566ad0', task_adapter='0x1455d2620', dispatcher='0x1445d3a50')
TAILS = {0x1455642a0: ('e9cb9affff', 0x14555dd70), 0x1455b5820: ('e91ba8ffff', 0x1455b0040)}
MODES = ('failed', 'null_json', 'borrowed_json', 'released_json', 'retained_json')
FLAGS = dict(scope='parameter_capture_and_dispatch', json_reader_and_deserializer='fixtures',
    lambda_cleanup='fixture_without_release', final_consumers='fixtures',
    active_task_verified=False, dialogue_started=False, skip_behavior_verified=False,
    action_admitted=False, network_used=False)


def cases():
    values = []
    for alignment in (0, 3):
        for control in (False, True):
            values.append(dict(kind='factory', alignment=alignment, object=False, object_control=control,
                reader=False, reader_control=False, parse='failed'))
            for reader in (False, True):
                for reader_control in (False, True):
                    for parse in MODES:
                        values.append(dict(kind='factory', alignment=alignment, object=True,
                            object_control=control, reader=reader, reader_control=reader_control, parse=parse))
        values.append(dict(kind='task', alignment=alignment, present=False, reader=False,
            reader_control=False, parse='failed'))
        for reader in (False, True):
            for reader_control in (False, True):
                for parse in MODES:
                    values.append(dict(kind='task', alignment=alignment, present=True, reader=reader,
                        reader_control=reader_control, parse=parse))
    return values


def expected(case):
    events = []
    active = case['object'] if case['kind'] == 'factory' else case['present']
    if case['kind'] == 'factory':
        events += ['allocate_object', 'allocate_object_control']
        if not active and case['object_control']:
            events += ['destroy_object_control', 'delete_object_control']
    else:
        events += ['reset_task']
        if active:
            events += ['task_parameter']
    if active:
        events += ['allocate_reader']
        if case['reader']:
            events += ['construct_reader']
        events += ['allocate_reader_control', 'deserialize']
        if case['parse'] != 'failed':
            events += ['callback_' + case['kind']]
        if case['parse'] == 'released_json':
            events += ['destroy_json_control', 'delete_json_control']
        if case['reader_control']:
            events += ['destroy_reader_control', 'delete_reader_control']
        events += ['cleanup_lambda_' + case['kind']]
    events += ['cookie']
    return dict(case=case, events=events,
        dispatch_result=(case['parse'] != 'failed') if active else None,
        callback=case['kind'] if active and case['parse'] != 'failed' else None,
        object_pair=([active, active and case['object_control']] if case['kind'] == 'factory' else None),
        object_control_counts=([2, 2] if active else [0, 0])
            if case['kind'] == 'factory' and case['object_control'] else None,
        reader_control_counts=[0, 0] if active and case['reader_control'] else None,
        json_control_counts=([0, 0] if case['parse'] == 'released_json' else [1, 2])
            if active and case['parse'] in ('released_json', 'retained_json') else None)


def validate(result):
    if (not isinstance(result, dict) or any(result.get(k) != v for k, v in FLAGS.items())
            or result.get('cases') != [expected(case) for case in cases()]
            or result.get('metrics', {}).get('call_counts') != len(cases())
            or result['metrics'].get('abi_checks') != len(cases())
            or result['metrics'].get('entry_counts', {}).get('0x1445d3a50') != 120
            or result['metrics']['entry_counts'].get('0x1455642a0') != 64
            or result['metrics']['entry_counts'].get('0x1455b5820') != 32
            or result['metrics']['entry_counts'].get('0x14140e350') != 96):
        raise ValueError('Quest parameter binding proof scope or matrix differs')


def execute(index, root, context, exports, source):
    native_context = context['native']
    if (native_context.get('source_sha256') != SOURCE or native_context.get('functions') != FUNCTIONS
            or hashlib.sha256(source).hexdigest() != SOURCE):
        raise ValueError('Quest parameter binding source or roots differ')
    native = index.extension('build-native-entry-code')
    image = native.Image(source)
    original_leaf = index.extension('login-input-transfer-rules')
    decode = index.extension('quest-action-transfer-rules-v1').decode

    def leaf_rows(api, selected_image, at, raw):
        if at not in TAILS:
            return original_leaf.leaf_rows(api, selected_image, at, raw)
        text, target = TAILS[at]
        rows = decode(api, selected_image, at, 5)
        if (raw != bytes.fromhex(text) or len(rows) != 1 or rows[0]['bytes'] != text
                or rows[0]['mnemonic'] != 'jmp' or rows[0]['direct_target'] != target
                or target not in {int(value, 16) for value in native_context['fixtures'].values()}
                or selected_image.containing(at) is not None):
            raise ValueError('Quest parameter binding tail leaf differs')
        return rows

    def extension(name):
        if name == 'login-input-transfer-rules':
            return SimpleNamespace(leaf_rows=leaf_rows)
        return index.extension(name)

    def selected(sha):
        if sha != SOURCE:
            raise ValueError('Quest parameter binding source selection differs')
        return source

    store = SimpleNamespace(root=root, source=selected, image=lambda api, sha: image if selected(sha) else None)
    engine = index.extension('quest-tutorial-state-harness-v1')
    h = engine.make_harness(SimpleNamespace(extension=extension), store, native_context, exports, context['tables'])
    uc, x, base = h.uc, h.x, h.scratch
    output0, task0, parameter, parameter_table, encoded = [base + at for at in (0x1000, 0x2000, 0x3000, 0x3800, 0x4000)]
    obj, obj_control, reader, reader_control, json_obj, json_control, json_table = [base + at for at in
        (0x5000, 0x5100, 0x6000, 0x6200, 0x7000, 0x7200, 0x7300)]
    allocations = dict(object=(obj, 0x28), object_control=(obj_control, 0x18),
        reader=(reader, 0x88), reader_control=(reader_control, 0x18))
    fixtures = {name: int(value, 16) for name, value in native_context['fixtures'].items()}
    table_addresses = dict(object_control=0x148af9360, reader_control=0x1489fee48,
        factory_lambda=0x148a22d68, task_lambda=0x1489fee88)
    cookie = int.from_bytes(bytes.fromhex(native_context['readonly_globals']['0x14b274600']), 'little')
    state, events = {}, []
    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))
    def require(ok, why):
        if not ok:
            raise ValueError('Quest parameter binding: ' + why)
    def pair(at):
        return struct.unpack('<QQ', uc.mem_read(at, 16))
    def counts(at):
        return list(struct.unpack('<II', uc.mem_read(at + 8, 8)))

    def allocate(machine):
        require(state['allocation_index'] < len(state['allocation_order']), 'unexpected allocation')
        role = state['allocation_order'][state['allocation_index']]
        state['allocation_index'] += 1
        at, size = allocations[role]
        require(reg('RCX') == size, 'allocation size differs')
        events.append('allocate_' + role)
        available = state['case'].get(role, False)
        if available:
            h.write(at, bytes(size))
        h.finish(at if available else 0)

    def reader_constructor(machine):
        require(reg('RCX') == reader and reg('RDX') == encoded, 'reader constructor input differs')
        events.append('construct_reader')
        h.finish(reader)

    def deserialize(machine):
        case = state['case']
        require(pair(reg('RCX')) == (reader if case['reader'] else 0, reader_control if case['reader_control'] else 0)
            and reg('R8') == 0 and pair(reg('RDX')) == (0, 0), 'deserializer provider/initial output differs')
        events.append('deserialize')
        mode = case['parse']
        if mode in ('borrowed_json', 'released_json', 'retained_json'):
            control = json_control if mode != 'borrowed_json' else 0
            h.write(reg('RDX'), struct.pack('<QQ', json_obj, control))
            if control:
                count = 1 if mode == 'released_json' else 2
                h.write(json_control, struct.pack('<QIIQ', json_table, count, count, json_obj))
        h.finish(int(mode != 'failed'))

    def task_reset(machine):
        require(reg('RCX') == state['task'] + 0x1f0, 'task reset destination differs')
        events.append('reset_task')
        h.finish()

    def provider_or_json_control(machine):
        if reg('RCX') == parameter:
            require(state['case']['kind'] == 'task' and state['case']['present'], 'unexpected task provider')
            events.append('task_parameter')
            h.finish(encoded)
        else:
            require(reg('RCX') == json_control, 'unknown synthetic provider/control')
            if counts(json_control) == [0, 1]:
                events.append('destroy_json_control')
            else:
                require(counts(json_control) == [0, 0] and reg('RDX') == 1, 'JSON delete counters/flag differ')
                events.append('delete_json_control')
            h.finish()

    def consumer(kind):
        def callback(machine):
            case = state['case']
            require(case['kind'] == kind, 'wrong callback target')
            if kind == 'factory':
                require(pair(reg('RCX')) == (obj, obj_control if case['object_control'] else 0), 'factory capture differs')
            else:
                require(struct.unpack('<Q', uc.mem_read(reg('RCX'), 8))[0] == state['task'], 'task capture differs')
            mode = case['parse']
            expected_json = json_obj if mode in ('borrowed_json', 'released_json', 'retained_json') else 0
            expected_control = json_control if mode in ('released_json', 'retained_json') else 0
            require(pair(reg('RDX')) == (expected_json, expected_control), 'callback JSON output differs')
            require(state['callback'] is None, 'callback repeated')
            state['callback'] = kind
            events.append('callback_' + kind)
            h.finish()
        return callback

    def destroy(role):
        def callback(machine):
            at, _ = allocations[role]
            require(reg('RCX') == at and counts(at) == [0, 1], 'destroy counter or object differs')
            events.append('destroy_' + role)
            h.finish()
        return callback

    def control_delete(machine):
        roles = [role for role in ('object_control', 'reader_control') if allocations[role][0] == reg('RCX')]
        require(len(roles) == 1 and counts(reg('RCX')) == [0, 0] and reg('RDX') == 1, 'control delete differs')
        events.append('delete_' + roles[0])
        h.finish()

    def lambda_cleanup(machine):
        kind = state['case']['kind']
        require(struct.unpack('<Q', uc.mem_read(reg('RCX'), 8))[0] == table_addresses[kind + '_lambda'],
            'lambda cleanup storage differs')
        capture = reg('RCX') + 8
        if kind == 'factory':
            require(pair(capture) == (obj, obj_control if state['case']['object_control'] else 0), 'cleanup factory capture differs')
        else:
            require(struct.unpack('<Q', uc.mem_read(capture, 8))[0] == state['task'], 'cleanup task capture differs')
        events.append('cleanup_lambda_' + kind)
        h.finish()

    def security_cookie(machine):
        require(reg('RCX') == cookie, 'security cookie differs')
        events.append('cookie')
        h.finish(reg('RAX'))

    handlers = dict(allocate=allocate, reader_constructor=reader_constructor, deserialize=deserialize,
        task_reset=task_reset, cookie=security_cookie, factory_consumer=consumer('factory'),
        task_consumer=consumer('task'), factory_destroy=destroy('object_control'),
        reader_destroy=destroy('reader_control'), control_delete=control_delete,
        lambda_cleanup=lambda_cleanup, provider_and_json_control=provider_or_json_control)
    require(set(handlers) == set(fixtures), 'fixture role set differs')
    for name, address in fixtures.items():
        h.add_fixture(address, handlers[name])
    return_sites = set()
    for role in ('factory', 'task_adapter'):
        for row in index.extension('update-bindings').rows(native, image, int(FUNCTIONS[role], 16)):
            if row['call'] and row['direct_target'] == int(FUNCTIONS['dispatcher'], 16):
                return_sites.add(row['address'] + len(bytes.fromhex(row['bytes'])))
    require(len(return_sites) == 2, 'dispatcher return sites differ')
    import unicorn
    def observe_dispatch(machine, address, size, unused):
        if address in return_sites:
            require(state['dispatch_result'] is None and reg('RAX') in (0, 1), 'dispatcher result differs')
            state['dispatch_result'] = bool(reg('RAX'))
    uc.hook_add(unicorn.UC_HOOK_CODE, observe_dispatch)
    results = []
    for case in cases():
        events.clear()
        output, task = output0 + case['alignment'], task0 + case['alignment']
        active = case['object'] if case['kind'] == 'factory' else case['present']
        order = (['object', 'object_control'] if case['kind'] == 'factory' else []) + (['reader', 'reader_control'] if active else [])
        state.clear(); state.update(case=case, allocation_order=order, allocation_index=0,
            callback=None, dispatch_result=None, task=task)
        h.reset_regions()
        h.allow_write(output, 16); h.allow_read(task, 0x220)
        h.allow_read(parameter, 0x40); h.allow_read(parameter_table, 0x40)
        text = '{"type":"Dialog"}'.encode('utf-16-le') + b'\0\0'
        h.allow_read(encoded, len(text)); h.allow_read(json_obj, 32); h.allow_read(json_table, 16)
        h.allow_write(json_control, 24)
        for at, size in allocations.values():
            h.allow_write(at, size)
            uc.mem_write(at - 16, b'G' * (size + 32))
        uc.mem_write(output - 16, b'G' * 48)
        uc.mem_write(task - 16, b'T' * 0x240)
        uc.mem_write(task + 0x40, struct.pack('<Q', parameter if case.get('present') else 0))
        uc.mem_write(parameter, bytes(0x40)); uc.mem_write(parameter, struct.pack('<Q', parameter_table))
        uc.mem_write(parameter_table, bytes(0x40)); uc.mem_write(parameter_table + 0x38, struct.pack('<Q', fixtures['provider_and_json_control']))
        uc.mem_write(encoded, text); uc.mem_write(json_obj, b'J' * 32)
        uc.mem_write(json_control - 16, b'G' * 56)
        uc.mem_write(json_table, struct.pack('<QQ', fixtures['provider_and_json_control'], fixtures['provider_and_json_control']))
        immutable = {at: bytes(uc.mem_read(at, size)) for at, size in ((task - 16, 0x240),
            (parameter, 0x40), (parameter_table, 0x40), (encoded, len(text)), (json_obj, 32), (json_table, 16))}
        result = h.call(int(FUNCTIONS['factory' if case['kind'] == 'factory' else 'task_adapter'], 16),
            output if case['kind'] == 'factory' else task, rdx=encoded if case['kind'] == 'factory' else 0, budget=30000)
        want = expected(case)
        require(events == want['events'] and state['callback'] == want['callback']
            and state['dispatch_result'] == want['dispatch_result'], 'event order/capture/result differs')
        require(state['allocation_index'] == len(order), 'allocation sequence incomplete')
        require(all(bytes(uc.mem_read(at, len(raw))) == raw for at, raw in immutable.items()), 'input mutated')
        for at, size in (*allocations.values(), (output, 16), (json_control, 24)):
            require(bytes(uc.mem_read(at - 16, 16)) == b'G' * 16
                and bytes(uc.mem_read(at + size, 16)) == b'G' * 16, 'allocation/output guard changed')
        if case['kind'] == 'factory':
            require(result == output and pair(output) == (obj if active else 0,
                obj_control if active and case['object_control'] else 0), 'factory output pair differs')
            if active:
                require(bytes(uc.mem_read(obj, 40)) == struct.pack('<QQQQQ', 0x1498fe9c0, obj,
                    obj_control if case['object_control'] else 0, 0, 0), 'factory object layout differs')
            if case['object_control']:
                require(counts(obj_control) == want['object_control_counts'], 'factory control counters differ')
        if active and case['reader_control']:
            require(counts(reader_control) == want['reader_control_counts'], 'reader control counters differ')
        if want['json_control_counts'] is not None:
            require(counts(json_control) == want['json_control_counts'], 'JSON control counters differ')
        results.append(want)
    value = dict(FLAGS, cases=results, metrics=h.validate())
    validate(value)
    return value
