"""Inner SDK boundaries for native Login getters; no SDK runtime or network calls."""
import hashlib
import struct


def install(load, h, sdk, fixture, state, owner, manager, language, flags, handles,
            allocate, release, write_text, read_text, literal, reg):
    rows = load('update-bindings').rows
    native = load('build-native-entry-code')
    functions = {key: int(at, 16) for key, at in sdk['functions'].items()}
    calls = {hex(r['address']): {'target': hex(r['direct_target']) if r['direct_target'] is not None else r['operands']}
             for at in functions.values() for r in rows(native, h.image, at) if r['call']}
    if calls != sdk['call_sites']:
        raise ValueError('Login SDK getter call sites differ')
    leaves = {int(at, 16): bytes.fromhex(spec['bytes']) for at, spec in sdk['leaves'].items()}
    if any(hashlib.sha256(bytes.fromhex(spec['bytes'])).hexdigest() != spec['sha256'] for spec in sdk['leaves'].values()):
        raise ValueError('Login SDK leaf digest differs')
    targets = {fixture[key]: key for key in sdk['native_names']}
    if set(targets) != set(functions.values()) | set(leaves):
        raise ValueError('Login SDK native bindings differ')
    for address, data in leaves.items():
        decoded = list(native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64).disasm(data, address))
        if not decoded or decoded[-1].mnemonic != 'ret' or any(r.mnemonic in ('call', 'jmp') for r in decoded):
            raise ValueError('Login SDK leaf must have a reviewed return and no calls/jumps')
    global_addresses = {key: int(at, 16) for key, at in sdk['globals'].items()}
    inners = {key: int(at, 16) for key, at in sdk['fixtures'].items()}
    metadata = sdk['metadata']
    metadata_rows = rows(native, h.image, int(metadata['collector'], 16))
    metadata_fields = []
    for i, row in enumerate(metadata_rows):
        if len(row['rip_references']) != 1 or row['mnemonic'] != 'lea' or not row['operands'].startswith('rdx, '):
            continue
        address = row['rip_references'][0]
        off = h.image.offset(address - h.image.pe.base)
        if h.raw[off:off + 4] != b'I\0_\0':
            continue
        data = h.raw[off:off + 256]
        end = next((n for n in range(0, len(data), 2) if data[n:n + 2] == b'\0\0'), None)
        if end is None:
            raise ValueError('Login metadata key exceeds literal bound')
        if (i + 5 >= len(metadata_rows) or metadata_rows[i + 2]['direct_target'] != fixture['wide_string']
                or metadata_rows[i + 5]['direct_target'] != int(metadata['consumer'], 16)):
            raise ValueError('Login metadata key consumer link differs')
        metadata_fields.append(dict(key=data[:end].decode('utf-16le'), literal=hex(address),
                                    call_site=hex(metadata_rows[i + 5]['address'])))
    if metadata_fields != metadata['fields']:
        raise ValueError('Login metadata projection differs')
    stores = {'main_store': h.scratch + 0x9000, 'value_store': h.scratch + 0x9200}
    cache = h.scratch + 0x9400
    number_object = h.scratch + 0x9600

    def require(value, message):
        if not value:
            raise ValueError(message)

    def inner(name):
        def execute(machine):
            a, b, c = [reg(k) for k in ('RCX', 'RDX', 'R8')]
            state['sdk_inner_calls'].append(name)
            result = 0
            if name in stores:
                result = stores[name]
            elif name == 'cache_resolve':
                require(a in stores.values(), 'Login SDK resolver receiver differs')
                if state['sdk_cache'] == 'resolve':
                    h.uc.mem_write(a + 0x110, struct.pack('<Q', cache))
            elif name == 'main_string':
                require(a == cache, 'Login SDK main cache differs')
                result = write_text(b, state['main'])
            elif name == 'assign_counted':
                require(a == handles[0] + 0x58 and c <= 1024, 'Login SDK counted string destination/count differs')
                expected_pointer, count, capacity = struct.unpack('<QII', h.uc.mem_read(cache + 0x78, 16))
                require(b == expected_pointer and c == max(count - 1, 0), 'Login SDK counted string source differs')
                text = bytes(h.uc.mem_read(b, c * 2)).decode('utf-16le') if c else ''
                old = int.from_bytes(h.uc.mem_read(a, 8), 'little')
                if old:
                    release(old)
                result = write_text(a, text)
                pointer = int.from_bytes(h.uc.mem_read(a, 8), 'little')
                if pointer:
                    state['sdk_retained'].add(pointer)
            elif name == 'mode_text':
                result = write_text(a, state['sdk_mode_text'])
            else:
                raise ValueError('Unknown Login SDK inner fixture')
            h.finish(result)
        return execute

    for key, at in inners.items():
        h.add_fixture(at, inner(key))
    import unicorn

    def entered(machine, at, size, unused):
        if at in targets:
            name = targets[at]
            state['events'].append(name)
            state['sdk_native_calls'][name] = state['sdk_native_calls'].get(name, 0) + 1
    h.uc.hook_add(unicorn.UC_HOOK_CODE, entered)
    mode_texts = {int(key): literal(int(at, 16), True) for key, at in sdk['mode_literals'].items()}
    require(len(set(mode_texts.values())) == 3, 'Login SDK mode literals not distinct')

    def seed(cache_case, empty):
        state.update(sdk_cache=cache_case, sdk_native_calls={}, sdk_inner_calls=[], sdk_retained=set(),
                     sdk_mode_text=mode_texts.get(state['mode'], 'not-a-supported-mode'), flag=int(not empty))
        # The real leaf returns byte-state == 3, not an arbitrary raw flag.
        h.uc.mem_write(flags, bytes([0x55]) * 0x20)
        h.uc.mem_write(flags + 8, bytes([2 if empty else 3]))
        for handle in handles:
            h.uc.mem_write(handle, bytes([0x44]) * 0x90)
        h.uc.mem_write(handles[2] + 0x39, bytes([state['extra_flag']]))
        h.uc.mem_write(number_object, bytes([0x33]) * 0x280)
        h.uc.mem_write(number_object + 0x270, struct.pack('<I', state['number']))
        h.uc.mem_write(owner + 0x10, struct.pack('<Q', number_object))
        for key, value in (('manager', manager if state['manager_present'] else 0), ('language', language), ('flags', flags)):
            h.uc.mem_write(global_addresses[key], struct.pack('<Q', value))
        for store in stores.values():
            h.uc.mem_write(store, bytes([0x22]) * 0x120)
            h.uc.mem_write(store + 0x110, struct.pack('<Q', cache if cache_case == 'warm' else 0))
        h.uc.mem_write(cache, bytes([0x11]) * 0x90)
        value = '' if empty else 'sdk-cache-Ж🙂'
        write_text(cache + 0x78, value)
        if cache_case == 'absent':
            state['main'] = ''
            value = '' if empty else 'retained-sdk-value-界'
        else:
            value = ''
        write_text(handles[0] + 0x58, value)
        state['sdk_value_expected'] = value if cache_case == 'absent' else read_text(cache + 0x78)
        state['sdk_guards'] = {at: bytes(h.uc.mem_read(at, size)) for at, size in
            ((number_object, 0x280), (cache, 0x90), (flags, 0x20), (handles[1], 0x90), (handles[2], 0x90))}
        state['sdk_main_guard'] = bytes(h.uc.mem_read(handles[0], 0x90))

    def check():
        require(all(bytes(h.uc.mem_read(at, len(data))) == data for at, data in state['sdk_guards'].items()),
                'Login SDK input changed')
        active = state['sdk_native_calls'].get('sdk_value', 0)
        expected_main = bytearray(state['sdk_main_guard'])
        if active:
            expected_main[0x58:0x68] = h.uc.mem_read(handles[0] + 0x58, 16)
            require(read_text(handles[0] + 0x58) == state['sdk_value_expected'], 'Login SDK member string projection differs')
        require(bytes(h.uc.mem_read(handles[0], 0x90)) == bytes(expected_main), 'Login SDK main handle changed outside member')
        for store in stores.values():
            expected = cache if state['sdk_cache'] == 'warm' or (active and state['sdk_cache'] == 'resolve') else 0
            require(int.from_bytes(h.uc.mem_read(store + 0x110, 8), 'little') == expected,
                    'Login SDK cache state differs')
        require(all(at not in state['freed'] for at in state['sdk_retained']), 'Login SDK persistent member freed')
    return seed, check, metadata_fields
