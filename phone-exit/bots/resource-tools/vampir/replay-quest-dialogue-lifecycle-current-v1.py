"""Execute the current Dialog completion and event callbacks with bounded fixtures."""
from collections import Counter
import struct


SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'quest-dialogue-lifecycle-current-v1'
QUEST, TASK, INDEX, GROUP = 110110, 110110030, 2, 11011110
ROLES = dict(completion_schedule='0x1455d4290', delayed_callback='0x1455b1190',
             event_callback='0x1455d2dc0', completion='0x1455ca1f0', enqueue='0x1455ca000')
LEAVES = {'0x1455b5830': 'e95bb9ffff', '0x1455e7500': '488b41304885c07503b0ffc30fb64029c3'}
MODES = ('schedule', 'delayed', 'schedule-then-delayed', 'schedule-noowner',
         'schedule-nocontrol', 'schedule-dead', 'delayed-noowner', 'delayed-nocontrol',
         'delayed-dead', 'schedule-missing-model', 'event-blocked', 'event-ready',
         'event-ready-no-subscription')
LIMITS = (
    'Whole completion scheduling, delayed callback, event callback, completion bag and selector-1 enqueue execute.',
    'The task instance, current index, model, bag primitives, delegate construction and engine event state are fixtures.',
    'The event callback forwards to a fixture at task vtable slot +0x28; playback, DialogMove and UI are not executed.',
    'Direct callback invocation does not prove timer dispatch, elapsed dialogue duration, online completion or runtime admission.',
)


def require(ok, message):
    if not ok:
        raise ValueError('Dialog lifecycle replay: ' + message)


def expected(mode):
    schedule = mode.startswith('schedule') and mode not in ('schedule-noowner', 'schedule-nocontrol', 'schedule-dead')
    delayed = mode in ('delayed', 'schedule-then-delayed')
    complete = int(schedule) + int(delayed)
    missing = mode == 'schedule-missing-model'
    ready = mode in ('event-ready', 'event-ready-no-subscription')
    return dict(mode=mode, completion_calls=complete, enqueue_calls=0 if missing else complete,
                pending_count=int(complete > 0 and not missing), delegate_copies=int(schedule),
                timer_armed=int(schedule), delayed_target=int(schedule),
                event_checks=int(mode.startswith('event-')), start_forwards=int(ready),
                removals=int(mode == 'event-ready'), subscription=0 if ready else 73,
                pending_entries=[] if not complete or missing else [dict(
                    kind=1, properties=dict(QuestInfoId=QUEST, QuestTaskIndex=INDEX))])


def validate(result, context, row):
    require(row == dict(task_id=TASK, quest_id=QUEST, index=INDEX, class_info_id=1, dialog_group_id=GROUP),
            'selected Dialog task differs')
    require(context.get('schema') == 1 and context.get('recipe') == RECIPE
            and context.get('source_sha256') == SOURCE and context.get('roles') == ROLES
            and context.get('leaves') == LEAVES,
            'context source or exact roles differ')
    require(result.get('recipe') == RECIPE and result.get('source_sha256') == SOURCE
            and result.get('task') == row and result.get('whole_functions') == ROLES
            and result.get('cases') == [expected(mode) for mode in MODES]
            and result.get('limits') == list(LIMITS) and result.get('native_execution') is True
            and all(result.get(key) is False for key in ('network_used', 'action_admitted', 'dialogue_playback_verified')),
            'receipt scope or exact callback matrix differs')
    require(result.get('native_entries') == {
        ROLES['completion_schedule']: 6, ROLES['delayed_callback']: 5,
        ROLES['event_callback']: 3, ROLES['completion']: 5, ROLES['enqueue']: 4,
    } and result.get('abi_checks') == 14 and result.get('fixture_abi_checks') == 101,
            'native coverage or ABI differs')


def run(index, root, context, row):
    # Validate immutable task/context identity before making a native harness.
    require(context.get('roles') == ROLES and context.get('leaves') == LEAVES and context.get('source_sha256') == SOURCE
            and row == dict(task_id=TASK, quest_id=QUEST, index=INDEX, class_info_id=1, dialog_group_id=GROUP),
            'selected current task or roles differ')
    roles = {name: int(at, 16) for name, at in ROLES.items()}
    h = index.extension('native-request-harness-11316').make_harness(
        context['exports'], set(roles.values()),
        leaves={int(at, 16): data for at, data in context['leaves'].items()},
        root=root, source_sha256=SOURCE, copy_thunk=None)
    native, bindings = index.extension('build-native-entry-code'), index.extension('update-bindings')
    for fragment in h.fragments:
        at = int(fragment['address'], 16)
        actual = [(int(item['address'], 16), item['bytes']) for item in fragment['instructions']]
        exact = [(item['address'], item['bytes']) for item in bindings.rows(native, h.image, at)]
        require(fragment['block_coverage_complete'] and fragment['direct_flow_coverage_complete']
                and not index.missing_conditional_fallthroughs(fragment['instructions']) and actual == exact,
                'whole source unwind differs at ' + hex(at))

    def source(at, size):
        offset = h.image.offset(at - h.image.pe.base)
        return h.raw[offset:offset + size]

    vtable, model_global = int(context['vtable'], 16), int(context['model_global'], 16)
    require(vtable == 0x149907e00 and model_global == 0x14b5e7be0
            and int.from_bytes(source(vtable + 0x28, 8), 'little') == 0x1455c3ea0
            and int.from_bytes(source(0x1489fee88 + 0x10, 8), 'little') == 0x141421bd0,
            'event retry lifecycle slot differs')
    tail = int(context['delayed_tail'], 16)
    encoded = bytes.fromhex(context['leaves'][hex(tail)])
    require(tail == 0x1455b5830 and encoded[0] == 0xe9 and len(encoded) == 5
            and tail + 5 + struct.unpack('<i', encoded[1:])[0] == roles['delayed_callback'],
            'scheduled callback forwarding differs')
    require(source(0x149906398, 24) == 'QuestInfoId\0'.encode('utf-16le')
            and source(0x1499069a8, 30) == 'QuestTaskIndex\0'.encode('utf-16le'), 'named bag keys differ')

    uc, x, base = h.uc, h.x, h.scratch
    task, record, control, model, pending, scope, event, closure, fixture_table = (
        base + offset for offset in (0x1000, 0x3000, 0x4000, 0x6000, 0x8000,
                                    0xa000, 0xb000, 0xc000, 0xd000))
    stack, stop = base + 0x38008, base + 0x3f000
    counts, observed, current, bags, variants = Counter(), Counter(), {}, {}, {}
    abi_checks = fixture_abi_checks = 0
    writable = ((task, task + 0x2b0), (control + 8, control + 0x10),
                (model + 0x80, model + 0x90), (pending, pending + 0x58 * 8),
                (base + 0x37000, base + 0x38100))

    def register(name):
        return getattr(x, 'UC_X86_REG_' + name)

    def reg(name):
        return uc.reg_read(register(name))

    def get(at, size=8):
        return int.from_bytes(uc.mem_read(at, size), 'little')

    def put(at, value, size=8):
        uc.mem_write(at, (int(value) % (1 << (8 * size))).to_bytes(size, 'little'))

    def allow(at, size):
        require(any(lo <= at and at + size <= hi for lo, hi in writable), 'write outside fixture ' + hex(at))

    def write(at, value):
        allow(at, len(value))
        uc.mem_write(at, value)

    def wide(at):
        raw = bytearray()
        for i in range(64):
            part = bytes(uc.mem_read(at + 2 * i, 2))
            if part == b'\0\0':
                return raw.decode('utf-16le')
            raw.extend(part)
        raise ValueError('Dialog lifecycle replay: UTF-16 bound')

    def lookup(_):
        require(reg('RCX') == model and reg('RDX') == QUEST, 'model lookup receiver/key')
        h.finish(0 if current['mode'] == 'schedule-missing-model' else record)

    def bag_init(_):
        bags[reg('RCX')] = {}
        write(reg('RCX'), bytes(0x48))
        h.finish(reg('RCX'))

    def scalar(_):
        variants[reg('RCX')] = reg('RDX')
        write(reg('RCX'), bytes(32))
        h.finish(reg('RCX'))

    def set_property(_):
        name = wide(reg('RDX'))
        require(name in ('QuestInfoId', 'QuestTaskIndex') and reg('RCX') in bags
                and reg('R8') in variants, 'completion property receiver')
        bags[reg('RCX')][name] = variants[reg('R8')]
        h.finish()

    def copy_bag(_):
        require(reg('RDX') in bags and bags[reg('RDX')] == dict(QuestInfoId=QUEST, QuestTaskIndex=INDEX),
                'pending argument bag differs')
        bags[reg('RCX')] = bags[reg('RDX')].copy()
        write(reg('RCX'), bytes(0x48))
        h.finish(reg('RCX'))

    def get_property(_):
        require(wide(reg('RDX')) == 'QuestInfoId' and reg('RCX') in bags, 'pending lookup receiver')
        slot = base + 0x9000
        variants[slot] = bags[reg('RCX')]['QuestInfoId']
        h.finish(slot)

    def integer(_):
        require(reg('RCX') in variants, 'pending scalar receiver')
        h.finish(variants[reg('RCX')])

    def guard(_):
        require(reg('RCX') == scope and reg('RDX') & 0xffff == 7 and reg('R8') == QUEST, 'pending guard receiver')
        h.finish(0)

    def resize(_):
        old = reg('RDX')
        require(reg('RCX') == model + 0x80 and get(model + 0x88, 4) == old + 1 and 0 <= old < 8,
                'pending growth receiver')
        write(model + 0x80, struct.pack('<Q', pending))
        write(model + 0x8c, struct.pack('<I', 8))
        h.finish()

    def delegate_copy(_):
        # The native caller constructs its forwarding pointer and capture. The
        # engine delegate representation remains a fixture, outside this proof.
        require(get(reg('RCX') + 8) == task and get(reg('RDX') - 0x10) == tail,
                'completion delegate capture/target differs')
        observed['delegate_copies'] += 1
        observed['delayed_target'] = 1
        write(reg('RDX'), bytes(0x30))
        h.finish(reg('RDX'))

    def delegate_cleanup(_):
        require(stack - 0x800 <= reg('RCX') < stack and get(reg('RCX')) == 0x1489fee88
                and get(reg('RCX') + 8) == task, 'delegate cleanup capture differs')
        h.finish()

    def engine_receiver(_):
        h.finish(event)

    def event_check(_):
        require(reg('RCX') == event, 'engine event state receiver')
        observed['event_checks'] += 1
        h.finish(int(current['mode'] == 'event-blocked'))

    def remove(_):
        require(reg('RCX') == event + 0x90 and reg('RDX') == 73, 'event removal receiver/handle')
        observed['removals'] += 1
        h.finish()

    def retry_start(_):
        require(reg('RCX') == task and get(task + 0x2a0) == 0, 'event retry receiver/subscription')
        observed['start_forwards'] += 1
        h.finish()

    fixtures = {
        0x1455bbca0: lookup, 0x141c82ad0: bag_init, 0x1445c59f0: scalar,
        0x1445c5960: scalar, 0x1445d6a90: set_property, 0x141c4f920: lambda _: h.finish(),
        0x1487ebec0: lambda _: h.finish(reg('RAX')), 0x1445c6730: copy_bag,
        0x1445cbdf0: get_property, 0x1445c7660: integer,
        0x144aae610: lambda _: h.finish(scope), 0x144aae690: guard, 0x141539ad0: resize,
        0x14147a1e0: delegate_copy, 0x141421bd0: delegate_cleanup,
        0x144ab0d30: engine_receiver, 0x144ab0e10: event_check,
        0x1454e64d0: engine_receiver, 0x141458910: remove, base + 0xe000: retry_start,
    }

    def abi_fixture(callback):
        def execute(machine):
            nonlocal fixture_abi_checks
            before = reg('RSP')
            require(base + 0x37000 <= before <= stack and before % 16 == 8
                    and (before < stack or reg('RIP') == base + 0xe000), 'fixture stack ABI')
            ret = get(before)
            callback(machine)
            require(reg('RSP') == before + 8 and reg('RIP') == ret, 'fixture return ABI')
            fixture_abi_checks += 1
        return execute

    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    for at, callback in fixtures.items():
        h.add_fixture(at, abi_fixture(callback))
    uc.hook_add(UC_HOOK_MEM_WRITE, lambda _u, _a, at, size, _v, _d: allow(at, size))
    for at in roles.values():
        uc.hook_add(UC_HOOK_CODE, lambda _u, at, _s, _d: counts.update([at]), begin=at, end=at)
    nonvolatile = ('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15', *(f'XMM{i}' for i in range(6, 16)))
    markers = tuple(0x3b70 + i for i in range(len(nonvolatile)))

    def execute(at, receiver):
        nonlocal abi_checks
        uc.mem_write(stack - 0x800, b'\xa5' * 0x900)
        put(stack, stop)
        for name, value in zip(nonvolatile, markers):
            uc.reg_write(register(name), value)
        for name, value in (('RSP', stack), ('RCX', receiver), ('RDX', 0), ('R8', 0), ('R9', 0)):
            uc.reg_write(register(name), value)
        try:
            uc.emu_start(at, 0, count=30000)
        except Exception as error:
            raise ValueError(f"Dialog lifecycle replay: {current['mode']} at {reg('RIP'):#x}") from error
        require(reg('RIP') == stop and reg('RSP') == stack + 8
                and tuple(reg(name) for name in nonvolatile) == markers, 'native call/return ABI')
        abi_checks += 1

    cases = []
    for mode in MODES:
        current['mode'] = mode
        observed.clear()
        bags.clear()
        variants.clear()
        guards = []
        for i, (at, size) in enumerate(((task, 0x2b0), (record, 0x60), (control, 0x20), (model, 0x100),
                                        (pending, 0x58 * 8), (event, 0x100))):
            marker = bytes([0x50 + i]) * 16
            uc.mem_write(at - 16, marker + bytes(size) + marker)
            guards.append((at, size, marker))
        for at, value, size in ((task, fixture_table, 8), (fixture_table + 0x28, base + 0xe000, 8),
                                (task + 0x10, record, 8), (task + 0x18, control, 8),
                                (task + 0x2a0, 0 if mode == 'event-ready-no-subscription' else 73, 8),
                                (record + 0x20, QUEST, 8), (record + 0x30, task, 8),
                                (task + 0x29, INDEX, 1), (control + 8, 1, 4), (control + 12, 1, 4),
                                (closure, task, 8), (model_global, model, 8), (model + 0xe6, 7, 2)):
            put(at, value, size)
        for suffix, at, size in (('noowner', task + 0x10, 8), ('nocontrol', task + 0x18, 8),
                                 ('dead', control + 8, 4)):
            if mode.endswith(suffix):
                put(at, 0, size)
        before = counts.copy()
        preserved = [(at, bytes(uc.mem_read(at, size))) for at, size in ((record, 0x60), (control, 0x20), (event, 0x100))]
        if mode.startswith('schedule'):
            execute(roles['completion_schedule'], task)
        if mode == 'schedule-then-delayed' or mode.startswith('delayed'):
            execute(tail, closure)
        if mode.startswith('event-'):
            execute(roles['event_callback'], task)
        require(all(bytes(uc.mem_read(at, len(raw))) == raw for at, raw in preserved), 'fixture owner/control/event changed')
        for at, size, marker in guards:
            require(bytes(uc.mem_read(at - 16, 16)) == bytes(uc.mem_read(at + size, 16)) == marker,
                    'object guard differs at ' + hex(at))
        count = get(model + 0x88, 4)
        require(0 <= count <= 1, 'bounded selector queue count')
        cases.append(dict(mode=mode, completion_calls=counts[roles['completion']] - before[roles['completion']],
                          enqueue_calls=counts[roles['enqueue']] - before[roles['enqueue']], pending_count=count,
                          delegate_copies=observed['delegate_copies'],
                          timer_armed=int(get(task + 0x1f8, 1) == 1 and get(task + 0x1f4, 4) == 0x3f800000
                                          and get(task + 0x1f0, 4) == 0),
                          delayed_target=observed['delayed_target'], event_checks=observed['event_checks'],
                          start_forwards=observed['start_forwards'], removals=observed['removals'],
                          subscription=get(task + 0x2a0), pending_entries=[dict(
                              kind=get(pending + i * 0x58, 1), properties=bags[pending + i * 0x58 + 8].copy())
                              for i in range(count)]))
        require(cases[-1] == expected(mode), f'{mode} observed matrix differs: {cases[-1]!r}')
    result = dict(recipe=RECIPE, source_sha256=SOURCE, task=row, whole_functions=ROLES, cases=cases,
                  native_entries={hex(at): count for at, count in counts.items()}, abi_checks=abi_checks,
                  fixture_abi_checks=fixture_abi_checks, limits=list(LIMITS), native_execution=True,
                  network_used=False, action_admitted=False, dialogue_playback_verified=False)
    validate(result, context, row)
    return result
