"""Execute current JSON scalar projection with explicit lookup/value providers."""
import math
import struct
from types import SimpleNamespace

UNSET = 0x67676767
CONTROL = {'none': None, 'live1': (1, 1), 'live3': (3, 3),
           'zero1': (0, 1), 'zero3': (0, 3)}
VIRTUAL_RETURN = 0x1415eb639
DESTROY_RETURN = 0x1415eb67b
RELEASE_RETURN = 0x1415eb690


def outcomes():
    numeric = (0.0, -0.0, 1.0, -1.0, 1.9, -1.9,
        2147483647.0, 2147483647.9, 2147483648.0,
        -2147483648.0, -2147483648.5, -2147483649.0,
        9007199254740992.0, float('inf'), -float('inf'), float('nan'))
    result = [dict(label='numeric-' + str(n), bits=struct.pack('<d', value).hex(),
                   writes=True, succeeds=True, error_storage='empty')
              for n, value in enumerate(numeric)]
    result += [dict(label='success-without-write', bits=bytes(8).hex(),
                    writes=False, succeeds=True, error_storage='empty')]
    for label, writes, value, storage in (
            ('failed', False, 0.0, 'empty'),
            ('failed-string-storage', False, 0.0, 'allocated'),
            ('write-then-failed', True, 7.75, 'empty'),
            ('write-then-failed-string-storage', True, -7.75, 'allocated')):
        result.append(dict(label=label, bits=struct.pack('<d', value).hex(),
                           writes=writes, succeeds=False, error_storage=storage))
    return result


def cases():
    result = []
    for alignment in (0, 3):
        for key in (None, '', 'classInfoId', 'класс😀'):
            for presence in ('missing', 'null'):
                result.append(dict(alignment=alignment, key=key, presence=presence,
                    control='none', provider=None))
        for key in ('classInfoId', 'класс😀'):
            for control in CONTROL:
                for provider in outcomes():
                    result.append(dict(alignment=alignment, key=key, presence='present',
                        control=control, provider=provider))
    return result


def truncated(bits):
    value, = struct.unpack('<d', bytes.fromhex(bits))
    if not math.isfinite(value):
        return -0x80000000
    integer = math.trunc(value)
    return integer if -0x80000000 <= integer <= 0x7fffffff else -0x80000000


def expected(case):
    events = ['hash', 'lookup']
    if case['presence'] != 'present':
        return dict(case=case, success=False, output=UNSET,
                    events=events, control=None)
    provider = case['provider']
    events += ['hash', 'lookup', 'try_number']
    if not provider['succeeds']:
        events.append('error_string')
        if provider['error_storage'] == 'allocated':
            events.append('free')
    counter = CONTROL[case['control']]
    after = None
    if counter is not None:
        strong, weak = counter
        if strong == 0:
            events.append('destroy')
            weak -= 1
            if weak == 0:
                events.append('release')
        after = [strong, weak]
    bits = provider['bits'] if provider['writes'] else bytes(8).hex()
    return dict(case=case, success=True, output=truncated(bits),
                events=events, control=after)


def validate(result):
    rows = [expected(case) for case in cases()]
    entries = {'0x1445cd610': len(rows), '0x1415eb520': sum(row['success'] for row in rows),
        '0x141425dc0': sum(row['events'].count('hash') for row in rows),
        '0x141590480': sum(row['events'].count('lookup') for row in rows),
        '0x2803e000': sum(sum(row['events'].count(name) for name in ('try_number', 'destroy', 'release')) for row in rows),
        '0x141426b90': sum(row['events'].count('error_string') for row in rows),
        '0x1414830e0': sum(row['events'].count('free') for row in rows)}
    if (result.get('scope') != 'field_projection_and_numeric_provider'
            or result.get('cases') != rows
            or result.get('json_lookup') != 'fixture'
            or result.get('try_get_number') != 'fixture'
            or result.get('non_null_shared_control_executed') is not True
            or any(result.get(key) is not False for key in (
                'string_conversion_verified', 'fallback_allocation_executed',
                'active_task_verified', 'runtime_admitted', 'network_used'))
            or result.get('metrics', {}).get('call_counts') != len(cases())
            or result['metrics']['abi_checks'] != len(cases())
            or result['metrics'].get('entry_counts') != entries
            or result['metrics'].get('fixture_calls') != sum(count for at, count in entries.items()
                if at not in ('0x1445cd610', '0x1415eb520'))
            or not result['metrics'].get('read_checks') or not result['metrics'].get('write_checks')):
        raise ValueError('Quest scalar projection scope or matrix differs')


def execute(index, root, context, exports, source):
    native = index.extension('build-native-entry-code')
    image = native.Image(source)
    sha = context['native']['source_sha256']

    def selected_source(selected):
        if selected != sha:
            raise ValueError('Quest scalar source differs')
        return source

    def selected_image(api, selected):
        selected_source(selected)
        return image

    store = SimpleNamespace(root=root, source=selected_source, image=selected_image)
    h = index.extension('quest-tutorial-state-harness-v1').make_harness(
        index, store, context['native'], exports, context['literals'])
    uc, x = h.uc, h.x
    base = h.scratch
    pointer, output, root_json, node, value, table, control, control_table, key, error_buffer = [
        base + n for n in (0x1000, 0x2000, 0x3000, 0x4000, 0x5000,
                          0x6000, 0x7000, 0x8000, 0x9000, 0xa000)]
    fixture = {name: int(at, 16) for name, at in context['native']['fixtures'].items()}
    roots = {name: int(at, 16) for name, at in context['native']['functions'].items()}
    selected, events = {}, []
    scalar_sites = {VIRTUAL_RETURN, DESTROY_RETURN, RELEASE_RETURN}

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def require(ok, reason):
        if not ok:
            raise ValueError('Quest scalar: ' + reason)

    def expected_key():
        encoded = None if selected['key'] is None else selected['key'].encode('utf-16le') + b'\0\0'
        return 0 if encoded is None else key, 0 if encoded is None else len(encoded) // 2 - 1

    def hash_key(machine):
        address, count = expected_key()
        require(reg('RCX') == count and reg('RDX') == address, 'hash key/count differs')
        events.append('hash')
        h.finish(0x1234abce)

    def lookup(machine):
        address, count = expected_key()
        require(reg('RCX') == root_json and reg('RDX') == 0x1234abce,
                'lookup object/hash differs')
        view = reg('R8')
        require(struct.unpack('<QI', bytes(uc.mem_read(view, 12))) == (address, count),
                'lookup string view differs')
        events.append('lookup')
        h.finish(0 if selected['presence'] == 'missing' else node)

    def virtual(machine):
        returning, = struct.unpack('<Q', bytes(uc.mem_read(reg('RSP'), 8)))
        require(returning in scalar_sites, 'unexpected virtual caller')
        if returning == VIRTUAL_RETURN:
            require(reg('RCX') == value, 'numeric value receiver differs')
            target = reg('RDX')
            require(bytes(uc.mem_read(target, 8)) == bytes(8), 'numeric output was not zero initialized')
            events.append('try_number')
            provider = selected['provider']
            if provider['writes']:
                h.write(target, bytes.fromhex(provider['bits']))
            h.finish(int(provider['succeeds']))
            return
        require(reg('RCX') == control and selected['control'].startswith('zero'),
                'shared cleanup receiver differs')
        if returning == DESTROY_RETURN:
            require(struct.unpack('<i', bytes(uc.mem_read(control + 8, 4))) == (0,),
                    'destroy before final strong release')
            events.append('destroy')
        else:
            require(reg('RDX') == 1 and bytes(uc.mem_read(control + 8, 8)) == bytes(8),
                    'control release arguments/counters differ')
            events.append('release')
        h.finish()

    def error_string(machine):
        require(reg('RDX') == int(context['error_literal'], 16), 'error literal differs')
        events.append('error_string')
        allocated = selected['provider']['error_storage'] == 'allocated'
        h.write(reg('RCX'), struct.pack('<QII', error_buffer if allocated else 0,
                                        5 if allocated else 0, 6 if allocated else 0))
        h.finish()

    def free_buffer(machine):
        require(reg('RCX') == error_buffer and selected['provider']['error_storage'] == 'allocated',
                'error buffer release differs')
        events.append('free')
        h.finish()

    def excluded_allocator(machine):
        raise ValueError('Quest scalar fallback allocation is outside the present-value matrix')

    callbacks = dict(hash=hash_key, lookup=lookup, virtual=virtual, error=error_string,
                     free=free_buffer, allocate=excluded_allocator)
    require(set(callbacks) == set(fixture), 'fixture roles differ')
    for name, address in fixture.items():
        h.add_fixture(address, callbacks[name])
    results = []
    for case in cases():
        selected.clear()
        selected.update(case)
        events.clear()
        h.reset_regions()
        target = output + case['alignment']
        for at, size in ((pointer, 8), (node + 0x10, 16), (value, 8), (table, 88),
                         (control, 16), (control_table, 16)):
            h.allow_read(at, size)
        h.allow_write(target, 4)
        if CONTROL[case['control']] is not None:
            h.allow_write(control + 8, 8)
        uc.mem_write(pointer, struct.pack('<Q', root_json))
        uc.mem_write(output - 16, b'g' * 64)
        before = bytes(uc.mem_read(output - 16, 64))
        uc.mem_write(node, b'N' * 48)
        uc.mem_write(node + 0x10, struct.pack('<QQ',
            value if case['presence'] == 'present' else 0,
            control if CONTROL[case['control']] is not None else 0))
        uc.mem_write(value, struct.pack('<Q', table))
        uc.mem_write(table, b'T' * 88)
        uc.mem_write(table + 0x50, struct.pack('<Q', fixture['virtual']))
        uc.mem_write(control, struct.pack('<QII', control_table, *(CONTROL[case['control']] or (0, 0))))
        uc.mem_write(control_table, struct.pack('<QQ', fixture['virtual'], fixture['virtual']))
        encoded = None if case['key'] is None else case['key'].encode('utf-16le') + b'\0\0'
        if encoded is not None:
            uc.mem_write(key, encoded)
            h.allow_read(key, len(encoded))
        inputs = {at: bytes(uc.mem_read(at, n)) for at, n in (
            (pointer, 8), (node, 48), (value, 8), (table, 88), (control_table, 16))}
        if encoded is not None:
            inputs[key] = encoded
        expectation = expected(case)
        returned = h.call(roots['accessor'], pointer,
            rdx=key if encoded is not None else 0, r8=target, budget=12000)
        expected_memory = bytearray(before)
        if expectation['success']:
            struct.pack_into('<i', expected_memory, 16 + case['alignment'], expectation['output'])
        require(bool(returned & 255) == expectation['success'], 'success AL differs')
        require(bytes(uc.mem_read(output - 16, 64)) == bytes(expected_memory), 'output or guards differ')
        require(events == expectation['events'], 'provider/cleanup order differs')
        require(all(bytes(uc.mem_read(at, len(data))) == data for at, data in inputs.items()), 'input changed')
        expected_control = CONTROL[case['control']]
        expected_control = (0, 0) if expected_control is None else tuple(expectation['control'])
        require(bytes(uc.mem_read(control, 16)) == struct.pack('<QII', control_table, *expected_control),
                'control counters/vtable differ')
        results.append(expectation)
    return dict(scope='field_projection_and_numeric_provider', cases=results, metrics=h.validate(),
        json_lookup='fixture', try_get_number='fixture', non_null_shared_control_executed=True,
        string_conversion_verified=False, fallback_allocation_executed=False,
        active_task_verified=False, runtime_admitted=False, network_used=False)
