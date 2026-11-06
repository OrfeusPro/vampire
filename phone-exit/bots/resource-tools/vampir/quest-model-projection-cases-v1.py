"""Current native map lookup and progress projection, without loaded-table admission."""
import hashlib
import struct
from types import SimpleNamespace

SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
FUNCTIONS = dict(projection='0x145de7870', lookup='0x145b4c280')
LOOKUP_FOUND = ('head', 'tail', 'null_task')
FLAGS = dict(scope='native_lookup_and_progress_projection', manager_provider='fixture',
    hash_provider='fixture', task_kind_provider='fixture', diagnostics='fixtures',
    array_origin='synthetic', native_lookup=True, array_population_verified=False,
    setup_global_shadow=True, native_global_writes_admitted=False,
    active_task_verified=False, negative_indexes_admitted=False, runtime_admitted=False, network_used=False)


def cases():
    values = []
    def add(**changes):
        value = dict(storage='inline', lookup='tail', index=0, count=2, key=110120,
            task_key=110120020, kind=6, alignment=0, hash_value=1,
            counter_a=0x12345678abcdef01, counter_b=0x876543210badf00d,
            log_string=False, log_object=False)
        value.update(changes)
        if value not in values:
            values.append(value)
    for storage in ('inline', 'external'):
        for alignment in (0, 3):
            for mode in ('empty_zero', 'empty_free', 'empty_bucket', 'missing_chain', 'head', 'tail', 'null_task'):
                add(storage=storage, alignment=alignment, lookup=mode)
        for count in (0, 2, 128):
            for index in (0, 1, 2, 127, 128, 255):
                add(storage=storage, count=count, index=index)
        for key in (0, 0xffffffffffffffff):
            for index in (0, 255):
                add(storage=storage, key=key, task_key=key ^ 0x55,
                    index=index, counter_a=0xffffffffffffffff, counter_b=0x100000000,
                    hash_value=0x100000000)
        for log_string in (False, True):
            for log_object in (False, True):
                add(storage=storage, lookup='missing_chain',
                    log_string=log_string, log_object=log_object)
    for kind in (0, 31, 255):
        add(kind=kind, task_key=0xffffffffffffffff, counter_a=0, counter_b=0xffffffffffffffff)
    return values


def expected(case):
    signed_index = case['index'] if case['index'] < 128 else case['index'] - 256
    lookup_found = case['lookup'] in LOOKUP_FOUND
    found = lookup_found and case['lookup'] != 'null_task' and signed_index < case['count']
    result = bytearray(b'\xcc' * 32)
    if found:
        struct.pack_into('<QBB', result, 0, case['task_key'], case['kind'], case['index'])
        struct.pack_into('<II', result, 12, case['counter_a'] & 0xffffffff, case['counter_b'] & 0xffffffff)
    else:
        struct.pack_into('<QH', result, 0, 0, 0xff1f)
        struct.pack_into('<Q', result, 12, 0)
    struct.pack_into('<Q', result, 24, 0)
    events = ['manager', 'hash']
    if found:
        events.append('kind')
    else:
        events += ['format', 'wrap', 'emit']
        if case['log_object']:
            events.append('release')
        if case['log_string']:
            events.append('free')
    getter_calls = 1 if not lookup_found else 2 if signed_index >= case['count'] else 3
    return dict(case=case, signed_index=signed_index, found=found,
                getter_calls=getter_calls, result=result.hex(), events=events)


def validate(result):
    if not isinstance(result, dict):
        raise ValueError('Quest model projection proof scope or matrix differs')
    rows = [expected(case) for case in cases()]
    entries = {'0x145de7870': len(rows), '0x145b4c280': len(rows),
        '0x141500740': sum(row['getter_calls'] for row in rows),
        '0x145b54bb0': len(rows),
        '0x2803e000': sum(sum(row['events'].count(name) for name in ('hash', 'kind', 'release')) for row in rows),
        '0x1414333a0': sum('format' in row['events'] for row in rows),
        '0x1414c33a0': sum('wrap' in row['events'] for row in rows),
        '0x141584450': sum('emit' in row['events'] for row in rows),
        '0x1414830e0': sum('free' in row['events'] for row in rows)}
    metrics = result.get('metrics', {})
    if (any(result.get(key) != value for key, value in FLAGS.items())
            or result.get('cases') != rows
            or metrics.get('call_counts') != len(rows) or metrics.get('abi_checks') != len(rows)
            or metrics.get('fixture_calls') != sum(len(row['events']) for row in rows)
            or metrics.get('entry_counts') != entries
            or any(type(metrics.get(key)) is not int or metrics[key] <= 0 for key in ('read_checks', 'write_checks'))):
        raise ValueError('Quest model projection proof scope or matrix differs')


def execute(index, root, context, exports, source):
    native_context = context['native']
    if (native_context.get('source_sha256') != SOURCE or native_context.get('functions') != FUNCTIONS
            or native_context.get('leaves') != {'0x141500740': '488b01c3'}
            or native_context.get('handler_global') != '0x14b0c5b00'
            or context.get('hash_binding') != dict(slot='0x14b0c5b00', fixture='0x2803e000',
                scope='explicit_function_pointer_fixture_shadow')
            or hashlib.sha256(source).hexdigest() != SOURCE):
        raise ValueError('Quest model projection source or roots differ')
    native = index.extension('build-native-entry-code')
    image = native.Image(source)
    hash_call = next((row for row in index.extension('update-bindings').rows(native, image, 0x145b4c280)
                      if row['address'] == 0x145b4c2ba), None)
    if (hash_call is None or hash_call['call'] is not True or hash_call['direct_target'] is not None
            or hash_call['rip_references'] != [0x14b0c5b00]
            or hash_call['bytes'] != 'ff1540985705'
            or native_context['fixtures'].get('shared') != '0x2803e000'
            or ['0x145b4c2ba', 'qword ptr [rip + 0x5579840]', '0x2803e000']
                not in native_context.get('indirect_fixtures', [])):
        raise ValueError('Quest model projection hash call binding differs')
    def selected(sha):
        if sha != SOURCE:
            raise ValueError('Quest model projection source selection differs')
        return source
    store = SimpleNamespace(root=root, source=selected, image=lambda api, sha: image if selected(sha) else None)
    h = index.extension('quest-tutorial-state-harness-v1').make_harness(
        index, store, native_context, exports, context['tables'])
    uc, x, base = h.uc, h.x, h.scratch
    output0, progress0, manager, nodes, buckets, slots, task, task_table, log_string, log_object, log_table = [
        base + offset for offset in (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x7000,
                                     0x9000, 0xa000, 0xb000, 0xc000, 0xd000)]
    fixtures = {name: int(value, 16) for name, value in native_context['fixtures'].items()}
    state, events = {}, []
    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))
    def require(condition, message):
        if not condition:
            raise ValueError('Quest model projection: ' + message)
    def integer(at, size=8):
        return int.from_bytes(uc.mem_read(at, size), 'little')
    def put(at, value, size=8):
        uc.mem_write(at, int(value).to_bytes(size, 'little', signed=value < 0))
    def pair(at):
        return struct.unpack('<QQ', uc.mem_read(at, 16))
    def manager_provider(machine):
        events.append('manager')
        h.finish(manager)
    def shared_provider(machine):
        returning = integer(reg('RSP'))
        case = state['case']
        if returning == 0x145b4c2c0:
            require(integer(reg('RCX')) == case['key'] and reg('RDX') == 8 and reg('R8') == 0,
                    'hash key, length or seed differs')
            events.append('hash')
            h.finish(case['hash_value'])
        elif returning == 0x145de7945:
            require(reg('RCX') == task, 'task kind receiver differs')
            events.append('kind')
            h.finish(case['kind'])
        else:
            require(returning == 0x145de7916 and reg('RCX') == log_object,
                    'diagnostic virtual release caller or receiver differs')
            events.append('release')
            h.finish()
    def format_log(machine):
        case = state['case']
        require(reg('RDX') == int(context['diagnostic_literal'], 16) and reg('R8') == case['key'],
                'diagnostic format literal/key differs')
        state['formatted'] = reg('RCX')
        h.write(reg('RCX'), struct.pack('<QQ', log_string if case['log_string'] else 0, 0))
        events.append('format')
        h.finish(reg('RCX'))
    def wrap_log(machine):
        case = state['case']
        require(reg('RDX') == state['formatted']
                and pair(reg('RDX')) == (log_string if case['log_string'] else 0, 0),
                'diagnostic wrapped format storage differs')
        state['wrapped'] = reg('RCX')
        h.write(reg('RCX'), struct.pack('<QQ', log_object if case['log_object'] else 0, 0))
        events.append('wrap')
        h.finish(reg('RCX'))
    def emit_log(machine):
        require(reg('RCX') == 0 and reg('RDX') == state['wrapped']
                and pair(reg('RDX')) == (log_object if state['case']['log_object'] else 0, 0),
                'diagnostic emitted level or storage differs')
        events.append('emit')
        h.finish()
    def free_log(machine):
        require(state['case']['log_string'] and reg('RCX') == log_string,
                'diagnostic free receiver differs')
        events.append('free')
        h.finish()
    handlers = dict(manager=manager_provider, shared=shared_provider, format=format_log,
                    wrap=wrap_log, emit=emit_log, free=free_log)
    require(set(handlers) == set(fixtures), 'fixture role scope differs')
    for name, at in fixtures.items():
        h.add_fixture(at, handlers[name])
    # The harness global setter is for object pointers below its stack. This
    # exact .data slot instead holds an approved synthetic function boundary.
    # Setup writes only this declared slot before any native execution; native
    # writes to source storage remain forbidden by the unchanged memory hook.
    hash_slot = int(native_context['handler_global'], 16)
    hash_offset = image.offset(hash_slot - image.pe.base)
    require(bytes(uc.mem_read(hash_slot, 8)) == source[hash_offset:hash_offset + 8],
            'hash slot initial source bytes differ')
    uc.mem_write(hash_slot, struct.pack('<Q', fixtures['shared']))
    results = []
    for case in cases():
        output, progress = output0 + case['alignment'], progress0 + case['alignment']
        state.clear(); state['case'] = case; events.clear()
        regions = ((manager, 256), (nodes, 64), (buckets, 8),
            (slots - 128 * 8, 256 * 8), (task, 80), (task_table, 56),
            (log_string, 16), (log_object, 16), (log_table, 24))
        for at, size in regions:
            uc.mem_write(at - 16, b'G' * 16 + bytes(size) + b'G' * 16)
        uc.mem_write(output - 16, b'O' * 16 + b'\xcc' * 32 + b'O' * 16)
        raw = bytearray(32)
        raw[8] = case['index']
        struct.pack_into('<QQ', raw, 16, case['counter_a'], case['counter_b'])
        uc.mem_write(progress - 16, b'P' * 16 + raw + b'P' * 16)
        mode = case['lookup']
        empty_zero, empty_free = mode == 'empty_zero', mode == 'empty_free'
        put(manager + 0x68, nodes)
        put(manager + 0x70, 0 if empty_zero else 2, 4)
        put(manager + 0x9c, 2 if empty_free else 0, 4)
        put(manager + 0xa8, buckets if case['storage'] == 'external' else 0)
        put(manager + 0xb0, 2, 4)
        bucket_base = buckets if case['storage'] == 'external' else manager + 0xa0
        selected_bucket = case['hash_value'] & 1
        put(bucket_base, 0 if mode == 'empty_bucket' else -1, 4)
        put(bucket_base + 4, 0 if mode == 'empty_bucket' else -1, 4)
        put(bucket_base + selected_bucket * 4, -1 if mode == 'empty_bucket' else 0, 4)
        put(nodes, case['key'] if mode == 'head' else case['key'] ^ 2)
        put(nodes + 0x18, 1, 4)
        put(nodes + 32, case['key'] if mode in ('tail', 'null_task') else case['key'] ^ 4)
        put(nodes + 56, -1, 4)
        for at in (nodes + 8, nodes + 40):
            put(at, slots); put(at + 8, case['count'], 4); put(at + 12, case['count'], 4)
        signed_index = case['index'] if case['index'] < 128 else case['index'] - 256
        put(slots + signed_index * 8, 0 if mode == 'null_task' else task)
        put(task, task_table); put(task + 0x40, case['task_key'])
        put(task_table + 0x30, fixtures['shared'])
        put(log_object, log_table); put(log_table + 0x10, fixtures['shared'])
        immutable = [(at - 16, bytes(uc.mem_read(at - 16, size + 32))) for at, size in regions]
        immutable.append((progress - 16, bytes(uc.mem_read(progress - 16, 64))))
        immutable.append((hash_slot, struct.pack('<Q', fixtures['shared'])))
        h.reset_regions()
        h.allow_write(output, 32)
        h.allow_read(progress, 32)
        for at, size in regions:
            h.allow_read(at, size)
        returned = h.call(int(FUNCTIONS['projection'], 16), output,
                          rdx=case['key'], r8=progress, budget=10000)
        want = expected(case)
        require(returned == output and bytes(uc.mem_read(output, 32)).hex() == want['result'],
                'native result or return pointer differs')
        require(events == want['events'], 'provider or diagnostic order differs')
        require(bytes(uc.mem_read(output - 16, 16)) == b'O' * 16
                and bytes(uc.mem_read(output + 32, 16)) == b'O' * 16, 'output guard changed')
        require(all(bytes(uc.mem_read(at, len(raw))) == raw for at, raw in immutable),
                'projection input, map storage or guard changed')
        results.append(want)
    result = dict(FLAGS, cases=results, metrics=h.validate())
    validate(result)
    return result
