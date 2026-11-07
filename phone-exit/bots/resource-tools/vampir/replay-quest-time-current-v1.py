"""Replay current Time lifecycle and selector-1 enqueue with bounded fixtures."""
from collections import Counter
import json
import struct


QUEST = 110110
TASKS = {110110010: 0, 110110020: 1, 110110035: 3, 110110100: 9}
MODES = (
    'open', 'start-noowner', 'start-nocontrol', 'start-dead', 'start-nodata',
    'disabled', 'record-state', 'phase', 'gate-one', 'gate-two', 'missing-model',
    'record-advances', 'pending-same', 'pending-other-index', 'pending-other-type',
    'pending-other-key', 'pending-guard',
)
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
LIMITS = (
    'Whole Time callback/start/tick/timer/completion and selector-1 enqueue execute; init registration is source-checked.',
    'Named JSON fields, weak lookup, phase/gates, event callbacks, allocation, bag storage and pending manager use explicit fixtures.',
    'Selector-1 enqueues QuestInfoId and QuestTaskIndex; wire producer, actor vector and result application are outside this replay.',
    'A fixture state change demonstrates suppression of another completion; real server transition and runtime admission remain open.',
)


def require(ok, reason):
    if not ok:
        raise ValueError('Quest Time replay: ' + reason)


def f32(value):
    return struct.unpack('<f', struct.pack('<f', value))[0]


def selected_rows(rows):
    require(type(rows) in (list, tuple) and len(rows) == len(TASKS), 'selected task rows differ')
    selected = []
    for row, (task_id, index) in zip(rows, TASKS.items()):
        require(type(row) is dict and type(row.get('task_id')) is int and row['task_id'] == task_id
                and type(row.get('index')) is int and row['index'] == index
                and type(row.get('seconds')) is float and row['seconds'] == .1, 'selected task fields differ')
        if 'param' in row:
            parsed = json.loads(row['param'].replace('\\r', '\r').replace('\\n', '\n'))
            require(parsed == {'type': 'Time', 'seconds': .1}, 'selected JSON differs')
        selected.append({key: row[key] for key in ('task_id', 'index', 'seconds')})
    return selected


def expected_case(row, mode):
    started = not mode.startswith('start-')
    reaches_timer = mode in ('open', 'record-advances', 'missing-model') or mode.startswith('pending-')
    completes = reaches_timer and mode != 'missing-model'
    stop_early = mode == 'record-advances'
    initial = int(mode in ('pending-same', 'pending-other-index', 'pending-other-type', 'pending-other-key'))
    added = int(mode in ('open', 'record-advances', 'pending-other-type', 'pending-other-key'))
    index = row['index']
    pending = []
    if initial:
        pending.append(dict(kind=2 if mode == 'pending-other-type' else 1,
                            properties=dict(QuestInfoId=QUEST + (mode == 'pending-other-key'),
                                            QuestTaskIndex=index + (mode == 'pending-other-index'))))
    if added:
        pending.append(dict(kind=1, properties=dict(QuestInfoId=QUEST, QuestTaskIndex=index)))
    states = [int(started)] * 5
    elapsed = [0.] * 5
    if reaches_timer:
        duration = row['seconds']
        states = [1, 0xffffffff, 1, 1, 1] if stop_early else [1, 0xffffffff, 1, 0xffffffff, 1]
        elapsed = [f32(duration / 2), f32(duration), 0., 0., 0.]
        if not stop_early:
            elapsed[3] = f32(duration)
    return dict(**row, mode=mode, states=states, elapsed=elapsed,
                completion_calls=[0, 0, 1, 1, 1 if stop_early else 2] if reaches_timer else [0] * 5,
                enqueue_calls=[0, 0, 1, 1, 1 if stop_early else 2] if completes else [0] * 5,
                pending_counts=[initial] * 2 + [initial + added] * 3, pending_entries=pending)


def validate(result, context, rows):
    source_rows = selected_rows(rows)
    expected = [expected_case(row, mode) for row in source_rows for mode in MODES]
    require(result.get('recipe') == context['recipe'] == 'quest-time-current-v1'
            and result.get('source_sha256') == context['source_sha256'] == SOURCE
            and result.get('source_rows') == source_rows and result.get('cases') == expected
            and result.get('limits') == list(LIMITS) and result.get('whole_functions') == context['roles']
            and result.get('native_execution') is True and result.get('action_admitted') is False
            and result.get('network_used') is False, 'scope or exact matrix differs')
    roles = context['roles']
    entries = {roles['callback']: len(expected), roles['start']: len(expected), roles['tick']: 5 * len(expected),
               roles['completion']: sum(case['completion_calls'][-1] for case in expected),
               roles['enqueue']: sum(case['enqueue_calls'][-1] for case in expected)}
    # One timer tick occurs per admitted update, including the tick that consumes the sentinel.
    entries[roles['timer']] = sum(3 if case['mode'] == 'record-advances' else 5
                                  for case in expected if case['completion_calls'][-1])
    require(result.get('native_entries') == entries and result.get('abi_checks') == 7 * len(expected)
            and result.get('fixture_abi_checks') == 858 * len(source_rows), 'native root or ABI coverage differs')


def run(index, root, context, rows):
    source_rows = selected_rows(rows)
    require(context['schema'] == 1 and context['source_sha256'] == SOURCE, 'source context differs')
    roles = {name: int(address, 16) for name, address in context['roles'].items()}
    leaves = {int(address, 16): data for address, data in context['leaves'].items()}
    h = index.extension('native-request-harness-11316').make_harness(
        context['exports'], set(roles.values()), leaves=leaves, root=root,
        source_sha256=context['source_sha256'], copy_thunk=None)
    native = index.extension('build-native-entry-code')
    bindings = index.extension('update-bindings')
    for export in h.fragments:
        at = int(export['address'], 16)
        actual = [(int(row['address'], 16), row['bytes']) for row in export['instructions']]
        expected = [(row['address'], row['bytes']) for row in bindings.rows(native, h.image, at)]
        require(export['block_coverage_complete'] and export['direct_flow_coverage_complete']
                and not index.missing_conditional_fallthroughs(export['instructions'])
                and actual == expected, 'whole unwind differs at ' + hex(at))

    def source(at, length):
        offset = h.image.offset(at - h.image.pe.base)
        return h.raw[offset:offset + length]

    vtable = int(context['vtable'], 16)
    model_global = int(context['model_global'], 16)
    for slot, name in ((0x20, 'tick'), (0x28, 'start'), (0x48, 'init')):
        require(int.from_bytes(source(vtable + slot, 8), 'little') == roles[name], 'lifecycle vtable differs')
    registration = context['callback_binding']
    tail = int(registration['tail'], 16)
    site = int(registration['site'], 16)
    encoded = bytes.fromhex(registration['bytes'])
    call_site = int(registration['parser_call'], 16)
    call_bytes = bytes.fromhex(registration['parser_bytes'])
    require(source(site, 7) == encoded and encoded[:3] == bytes.fromhex('488d05')
            and site + 7 + struct.unpack_from('<i', encoded, 3)[0] == tail
            and source(call_site, 5) == call_bytes and call_bytes[0] == 0xe8
            and call_site + 5 + struct.unpack_from('<i', call_bytes, 1)[0] == int(registration['parser'], 16)
            and source(tail, 1) == b'\xe9' and tail + 5 + struct.unpack('<i', source(tail + 1, 4))[0] == roles['callback'],
            'callback registration/forwarding differs')
    require(source(0x149906398, 24) == 'QuestInfoId\0'.encode('utf-16le')
            and source(0x1499069a8, 30) == 'QuestTaskIndex\0'.encode('utf-16le'), 'named field identity differs')

    uc, x, base = h.uc, h.x, h.scratch
    task, closure, json_ref, json_object, record, control, data, model, environment, pending, scope, data_table = (
        base + offset for offset in (0x1000, 0x2000, 0x2100, 0x2200, 0x3000, 0x4000, 0x5000,
                                     0x6000, 0x7000, 0x8000, 0xa000, 0xb000))
    stack, stop = base + 0x38008, base + 0x3f000
    current, allocations, variants, bags = {}, {}, {}, {}
    counts = Counter()
    heap = base + 0x10000
    abi_checks = fixture_abi_checks = 0
    writable = ((task, task + 0x2b0), (control + 8, control + 0x10),
                (model + 0x80, model + 0x90), (pending, pending + 8 * 0x58),
                (base + 0x37000, base + 0x38100))

    def register(name):
        return getattr(x, 'UC_X86_REG_' + name)

    def reg(name):
        return uc.reg_read(register(name))

    def get(at, size=8):
        return int.from_bytes(uc.mem_read(at, size), 'little')

    def put(at, value, size=8):
        uc.mem_write(at, (int(value) % (1 << (8 * size))).to_bytes(size, 'little'))

    def allow_write(at, size):
        require(any(lo <= at and at + size <= hi for lo, hi in writable), 'write outside fixture at ' + hex(at))

    def fixture_write(at, raw):
        allow_write(at, len(raw))
        uc.mem_write(at, raw)

    def wide(at):
        raw = bytearray()
        for i in range(128):
            part = bytes(uc.mem_read(at + i * 2, 2))
            if part == b'\0\0':
                return raw.decode('utf-16le')
            raw.extend(part)
        raise ValueError('Quest Time replay: UTF-16 fixture bound')

    def assign(at, value):
        nonlocal heap
        raw = value.encode('utf-16le') + b'\0\0'
        pointer = heap + 16
        heap = pointer + ((len(raw) + 15) & ~15) + 16
        require(heap < base + 0x30000, 'temporary string arena exceeded')
        uc.mem_write(pointer - 16, b'L' * 16 + raw + b'R' * 16)
        allocations[pointer] = raw
        fixture_write(at, struct.pack('<QII', pointer, len(raw) // 2, len(raw) // 2))

    def free(_machine):
        pointer = reg('RCX')
        raw = allocations.pop(pointer, None)
        require(raw is not None and bytes(uc.mem_read(pointer - 16, len(raw) + 32)) == b'L' * 16 + raw + b'R' * 16,
                'temporary string allocation guard')
        h.finish()

    def string_init(_machine):
        assign(reg('RCX'), wide(reg('RDX')))
        h.finish(reg('RCX'))

    def property_type(_machine):
        require(reg('RCX') == json_ref and get(json_ref) == json_object and wide(reg('RDX')) == 'type', 'type getter scope')
        assign(reg('R8'), 'Time')
        h.finish(1)

    def property_seconds(_machine):
        require(reg('RCX') == json_ref and wide(reg('RDX')) == 'seconds'
                and reg('R8') == task + 0x11c, 'duration getter scope')
        fixture_write(reg('R8'), struct.pack('<f', current['seconds']))
        h.finish(1)

    def start_status(_machine):
        require(reg('RCX') == task and reg('RDX') & 255 == 0x17, 'start status scope')
        h.finish()

    def broadcast(_machine):
        require(reg('RCX') == model + 8 and reg('R8') == task + 0x20, 'start broadcast scope')
        h.finish()

    def task_key(_machine):
        require(reg('RCX') == record, 'owner task getter scope')
        h.finish(current['task_id'])

    def task_data(_machine):
        require(reg('RCX') == current['task_id'], 'task data lookup key')
        h.finish(data)

    def gate(mode):
        def evaluate(_machine):
            require(reg('RCX') == QUEST, 'gate quest key')
            h.finish(int(current['mode'] != mode))
        return evaluate

    def other_timer(_machine):
        require(reg('RCX') in (task + 0x1f0, task + 0x240, task + 0xb0), 'other timer receiver')
        h.finish(1)

    def weak_object(_machine):
        require(reg('RCX') == task + 0x194, 'weak lookup scope')
        h.finish(0)

    def lookup(_machine):
        require(reg('RCX') == model and reg('RDX') == QUEST, 'completion model lookup scope')
        h.finish(0 if current['mode'] == 'missing-model' else record)

    def bag_init(_machine):
        at = reg('RCX')
        bags[at] = {}
        fixture_write(at, bytes(0x48))
        h.finish(at)

    def scalar(_machine):
        at = reg('RCX')
        variants[at] = reg('RDX')
        fixture_write(at, bytes(32))
        h.finish(at)

    def set_property(_machine):
        name = wide(reg('RDX'))
        require(name in ('QuestInfoId', 'QuestTaskIndex') and reg('R8') in variants
                and reg('RCX') in bags, 'completion property scope')
        bags[reg('RCX')][name] = variants[reg('R8')]
        h.finish()

    def copy_bag(_machine):
        target, original = reg('RCX'), reg('RDX')
        require(original in bags, 'pending copy source')
        props = bags[original]
        require(props == dict(QuestInfoId=QUEST, QuestTaskIndex=current['index']), 'completion argument bag differs')
        bags[target] = props.copy()
        fixture_write(target, bytes(0x48))
        h.finish(target)

    def get_property(_machine):
        name = wide(reg('RDX'))
        require(name == 'QuestInfoId' and reg('RCX') in bags, 'pending property lookup scope')
        slot = base + 0x9000
        variants[slot] = bags[reg('RCX')][name]
        h.finish(slot)

    def integer_value(_machine):
        require(reg('RCX') in variants, 'pending scalar lookup scope')
        h.finish(variants[reg('RCX')])

    def pending_guard(_machine):
        require(reg('RCX') == scope and reg('RDX') & 0xffff == 7 and reg('R8') == QUEST, 'pending guard scope')
        h.finish(int(current['mode'] == 'pending-guard'))

    def resize(_machine):
        old = reg('RDX')
        require(reg('RCX') == model + 0x80 and get(model + 0x88, 4) == old + 1 and 0 <= old < 8, 'queue growth scope')
        fixture_write(model + 0x80, struct.pack('<Q', pending))
        fixture_write(model + 0x8c, struct.pack('<I', 8))
        h.finish()

    def fallback(_machine):
        require(reg('RCX') == data, 'blocked gate fallback receiver')
        h.finish(0)

    fixtures = {
        0x1414269b0: string_init, 0x1414830e0: free, 0x1445cf1d0: property_type, 0x1445cd2c0: property_seconds,
        0x1455d2eb0: start_status, 0x144a6ad80: broadcast, 0x1455e7520: task_key, 0x14546d9d0: task_data,
        0x14560adb0: lambda _: h.finish(environment), 0x14568cb40: gate('gate-one'), 0x14568ca90: gate('gate-two'),
        0x14549a840: other_timer, 0x1417fa420: weak_object, 0x1455bbca0: lookup, 0x141c82ad0: bag_init,
        0x1445c59f0: scalar, 0x1445c5960: scalar, 0x1445d6a90: set_property, 0x141c4f920: lambda _: h.finish(),
        0x1487ebec0: lambda _: h.finish(reg('RAX')), 0x1445c6730: copy_bag, 0x1445cbdf0: get_property,
        0x1445c7660: integer_value, 0x144aae610: lambda _: h.finish(scope), 0x144aae690: pending_guard,
        0x141539ad0: resize, base + 0xb100: fallback,
    }

    def abi_fixture(callback):
        def execute(machine):
            nonlocal fixture_abi_checks
            before = reg('RSP')
            require(base + 0x37000 <= before < stack and before % 16 == 8, 'fixture entry stack ABI')
            ret = get(before)
            callback(machine)
            require(reg('RSP') == before + 8 and reg('RIP') == ret, 'fixture return ABI')
            fixture_abi_checks += 1
        return execute

    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    for address, fixture in fixtures.items():
        h.add_fixture(address, abi_fixture(fixture))
    uc.hook_add(UC_HOOK_MEM_WRITE, lambda _u, _a, at, size, _v, _d: allow_write(at, size))
    for address in roles.values():
        uc.hook_add(UC_HOOK_CODE, lambda _u, at, _s, _d: counts.update([at]), begin=address, end=address)

    nonvolatile = ('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15', *(f'XMM{i}' for i in range(6, 16)))
    markers = tuple(0x3b30 + i for i in range(len(nonvolatile)))

    def execute(at, receiver, *, rdx=0, delta=0.):
        nonlocal abi_checks
        uc.mem_write(stack - 0x800, b'\xa5' * 0x900)
        put(stack, stop)
        for name, value in zip(nonvolatile, markers):
            uc.reg_write(register(name), value)
        for name, value in (('RSP', stack), ('RCX', receiver), ('RDX', rdx), ('R8', 0), ('R9', 0),
                            ('XMM1', int.from_bytes(struct.pack('<f', delta), 'little'))):
            uc.reg_write(register(name), value)
        try:
            uc.emu_start(at, 0, count=30000)
        except Exception as error:
            raise ValueError(f"Quest Time replay: {current['mode']} at {reg('RIP'):#x}") from error
        require(reg('RIP') == stop and reg('RSP') == stack + 8
                and tuple(reg(name) for name in nonvolatile) == markers, 'native call/return ABI')
        abi_checks += 1

    def guarded(at, size, marker):
        uc.mem_write(at - 16, marker * 16 + bytes(size) + marker * 16)
        return at, size, marker

    def check_guard(at, size, marker):
        require(bytes(uc.mem_read(at - 16, 16)) == bytes(uc.mem_read(at + size, 16)) == marker * 16,
                'object guard differs at ' + hex(at))

    cases = []
    for row in source_rows:
        for mode in MODES:
            current.update(row, mode=mode)
            heap = base + 0x10000
            allocations.clear()
            variants.clear()
            bags.clear()
            guards = [guarded(at, size, bytes([0x50 + i])) for i, (at, size) in enumerate(
                ((task, 0x2b0), (record, 0x60), (control, 0x20), (data, 0xc0), (model, 0x100),
                 (environment, 0x40), (pending, 0x58 * 8)))]
            for at, value, size in ((task, vtable, 8), (task + 0x10, record, 8), (task + 0x18, control, 8),
                                    (task + 0x20, row['task_id'], 8), (task + 0x28, 6, 1), (task + 0x29, row['index'], 1),
                                    (task + 0x40, data, 8), (record + 0x20, QUEST, 8), (record + 0x28, 2, 1),
                                    (record + 0x30, task, 8), (control + 8, 1, 4), (control + 12, 1, 4),
                                    (data, data_table, 8), (data_table + 0x20, base + 0xb100, 8), (closure, task, 8),
                                    (json_ref, json_object, 8), (model_global, model, 8),
                                    (model + 0xe6, 7, 2), (environment + 0x30, 6, 1)):
                put(at, value, size)
            expected = expected_case(row, mode)
            seeded = expected['pending_counts'][0]
            if seeded:
                put(model + 0x80, pending)
                put(model + 0x88, 1, 4)
                put(model + 0x8c, 1, 4)
                seed = expected['pending_entries'][0]
                put(pending, seed['kind'], 1)
                bags[pending + 8] = seed['properties'].copy()
            seed_raw = bytes(uc.mem_read(pending, 0x58))

            execute(tail, closure, rdx=json_ref)
            require(get(task + 0x118, 1) == 0 and bytes(uc.mem_read(task + 0x11c, 4)) == struct.pack('<f', row['seconds'])
                    and not allocations, 'Time fields/callback cleanup')
            missing = {'start-noowner': task + 0x10, 'start-nocontrol': task + 0x18,
                       'start-dead': control + 8, 'start-nodata': task + 0x40}.get(mode)
            if missing is not None:
                put(missing, 0, 4 if mode == 'start-dead' else 8)
            execute(roles['start'], task)
            started = int(missing is None)
            require(get(task + 0xa0, 1) == get(task + 0x1a8, 4) == started
                    and get(task + 0x1a0, 4) == 0, 'start guards/timer fields')
            if started:
                require(bytes(uc.mem_read(task + 0x1a4, 4)) == struct.pack('<f', row['seconds']), 'start duration')
            if mode == 'disabled':
                put(task + 0xa0, 0, 1)
            if mode == 'record-state':
                put(record + 0x28, 1, 1)
            if mode == 'phase':
                put(environment + 0x30, 5, 1)
            preserved = {at: bytes(uc.mem_read(at, size)) for at, size in
                         ((record, 0x60), (control, 0x20), (data, 0xc0), (environment, 0x40))}

            before = counts.copy()
            states, elapsed, completions, enqueues, pending_counts = [], [], [], [], []
            seconds = row['seconds']
            for delta in (seconds / 2, seconds / 2, 0., seconds, 0.):
                execute(roles['tick'], task, delta=delta)
                states.append(get(task + 0x1a8, 4))
                elapsed.append(struct.unpack('<f', uc.mem_read(task + 0x1a0, 4))[0])
                completions.append(counts[roles['completion']] - before[roles['completion']])
                enqueues.append(counts[roles['enqueue']] - before[roles['enqueue']])
                pending_counts.append(get(model + 0x88, 4))
                if mode == 'record-advances' and completions[-1]:
                    put(record + 0x28, 1, 1)
                    preserved[record] = preserved[record][:0x28] + b'\x01' + preserved[record][0x29:]
            require(not allocations and all(bytes(uc.mem_read(at, len(raw))) == raw for at, raw in preserved.items()),
                    'owner/control/data fixture changed')
            for guard in guards:
                check_guard(*guard)
            if seeded:
                require(bytes(uc.mem_read(pending, 0x58)) == seed_raw, 'pending seed mutated')
            require(0 <= pending_counts[-1] <= 2, 'bounded selector queue count')
            entries = [dict(kind=get(pending + i * 0x58, 1), properties=bags[pending + i * 0x58 + 8].copy())
                       for i in range(pending_counts[-1])]
            observed = dict(**row, mode=mode, states=states, elapsed=elapsed, completion_calls=completions,
                            enqueue_calls=enqueues, pending_counts=pending_counts, pending_entries=entries)
            require(observed == expected, f'{mode} result differs for {row["task_id"]}: {observed!r}')
            cases.append(observed)

    result = dict(recipe=context['recipe'], source_sha256=h.sha, source_rows=source_rows, cases=cases,
                  whole_functions=context['roles'], native_entries={hex(at): value for at, value in counts.items()},
                  abi_checks=abi_checks, fixture_abi_checks=fixture_abi_checks, limits=list(LIMITS),
                  native_execution=True, network_used=False, action_admitted=False)
    validate(result, context, rows)
    return result
