"""Declared primitive entries and direct native Login backend with bounded effects.

Prepared packet fields are explicit fixture inputs. No prepare/publisher is called,
no expected bytes are written to archives, and CRC/XOR are never fixture callbacks.
"""
import copy
import struct
from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec

HERE = Path(__file__).resolve().parent
STRINGS = (0x10, 0x20, 0x30, 0x40, 0x58, 0x68, 0x78, 0x88,
           0xa0, 0xb8, 0xc8, 0xd8, 0xe8, 0x100, 0x110)
WIDTHS = {0x50: 4, 0x98: 1, 0x99: 1, 0xb0: 4, 0xf8: 4,
          0x120: 4, 0x124: 1, 0x128: 8, 0x130: 1, 0x131: 1}


def load(name):
    s = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    m = module_from_spec(s); s.loader.exec_module(m); return m


def require(ok, message):
    if not ok: raise ValueError(message)


def reset_policy(policy, *, preserve_retired=False):
    retired = list(policy.retired) if preserve_retired else []
    policy.reset()
    policy.retired = retired


def backend_observation(sequence):
    return dict(entry_calls=0, return_byte=None, state_getter_calls=0, state_return=None,
        action_calls=0, action_arguments_checked=None, arguments_checked=None,
        sequence_before=sequence, sequence_after=None, id_getter_calls=0,
        request_id=None, platform_first_calls=0, platform_second_calls=0,
        diagnostic_selector_offset=None)


class AllocationLedger:
    """One bounded guarded heap shared by providers, preparation and codec."""
    KINDS = {'utf16', 'utf8', 'cpp', 'archive'}

    def __init__(self, h, state):
        self.h, self.state = h, state

    def allocate(self, size, kind='utf16', owner=None):
        h, state = self.h, self.state
        if (type(size) is not int or not 1 <= size <= 8192 or kind not in self.KINDS
                or state['heap'] < h.scratch + 0x50000
                or state['heap'] + size + 64 > h.scratch + 0x100000):
            raise ValueError('Backend shared allocation bound/kind differs')
        at = state['heap'] + 16
        state['heap'] += (size + 63) & ~15
        h.uc.mem_write(at - 16, b'\xa5' * 16 + b'\x5a' * size + b'\xa6' * 16)
        actual_owner = owner if owner is not None else state.get('fixture_owner', 'input')
        state['allocations'][at] = size
        state['allocation_owners'][at] = actual_owner
        state['allocation_records'][at] = dict(size=size, kind=kind, owner=actual_owner,
            created_by_source_caller=state.get('fixture_callsite'), phase=state.get('phase', 'inputs'),
            retired=False)
        return at

    def release(self, at, expected_kind=None, expected_size=None):
        state, h = self.state, self.h
        record = state['allocation_records'].get(at)
        if record is None or at in state['freed'] or record['retired']:
            raise ValueError('Backend free is foreign or repeated')
        if expected_kind is not None and record['kind'] != expected_kind:
            raise ValueError('Backend free allocation kind differs')
        if expected_size is not None and (type(expected_size) is not int or record['size'] != expected_size):
            raise ValueError('Backend sized free differs')
        size = record['size']
        self.check_canary(at)
        state['freed'].add(at)
        record.update(retired=True, free_caller=state.get('fixture_callsite'),
                      free_owner=state.get('fixture_owner'))
        h.uc.retire(at, size)

    def check_canary(self, at):
        size = self.state['allocations'][at]
        if (bytes(self.h.uc.mem_read(at - 16, 16)) != b'\xa5' * 16
                or bytes(self.h.uc.mem_read(at + size, 16)) != b'\xa6' * 16):
            raise ValueError('Backend shared allocation canary changed')


def seed_packet(h, state, ledger, packet, table, projection):
    """Seed only accepted FString/scalar projection, before native backend entry."""
    require(isinstance(projection, dict) and set(projection['strings']) == {hex(i) for i in STRINGS}
            and set(projection['integers']) == {hex(i) for i in WIDTHS},
            'Integrity prepared packet fields differ')
    data = bytearray(320)
    struct.pack_into('<Q', data, 0, table)
    for offset in STRINGS:
        text = projection['strings'][hex(offset)]
        require(isinstance(text, str) and '\0' not in text, 'Integrity input FString differs')
        if not text: continue
        raw = text.encode('utf-16le') + b'\0\0'
        require(len(raw) <= 2048, 'Integrity input FString budget exceeded')
        pointer = ledger.allocate(len(raw), 'utf16', 'input.packet')
        h.uc.mem_write(pointer, raw)
        struct.pack_into('<QII', data, offset, pointer, len(raw) // 2, len(raw) // 2)
    for offset, width in WIDTHS.items():
        value = projection['integers'][hex(offset)]
        require(type(value) is int and 0 <= value < 1 << (width * 8), 'Integrity input scalar differs')
        data[offset:offset+width] = value.to_bytes(width, 'little')
    h.uc.mem_write(packet - 16, b'\xa5' * 16 + data + b'\xa6' * 16)
    state['packet_snapshot'] = bytes(h.uc.mem_read(packet - 16, 352))
    state['input_buffers'] = {p: bytes(h.uc.mem_read(p - 16, size + 32))
        for p, size in state['allocations'].items()}


def install(h, context, wire, contract, prepared):
    import unicorn
    state = {}
    primitive = {key: int(context['backend'][key], 16)
                 for key in ('checksum_init', 'checksum', 'transform')}
    backend, packet, diagnostic = (h.scratch + n for n in (0xf000, 0xc000, 0x11000))
    functions = {key: int(at, 16) for key, at in context['functions'].items()}
    metadata = {key: int(at, 16) for key, at in context['backend'].items() if key != 'globals'}
    globals_ = {key: int(at, 16) for key, at in context['backend']['globals'].items()}
    flags = int(context['source_inputs']['archive_flags']['address'], 16)
    table = int(wire['packets']['game-login']['table'], 16)
    returns = {}
    native = load('build-native-entry-code')
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    for role, sites in context['call_sites'].items():
        for at, target in sites.items():
            address = int(at, 16); off = h.image.offset(address - h.image.pe.base)
            instruction = next(decoder.disasm(h.raw[off:off+15], address))
            require(instruction.mnemonic == 'call', 'Integrity source call metadata differs')
            ret = address + instruction.size
            require(ret not in returns, 'Integrity source return address repeats')
            returns[ret] = (role, address, target)

    def reg(name): return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))
    def number(at, size=8): return int.from_bytes(h.uc.mem_read(at, size), 'little')
    def caller(address):
        found = returns.get(number(reg('RSP')))
        require(found is not None, 'Integrity helper caller is not source native code')
        role, at, target = found
        require(not target.startswith('0x') or int(target, 16) == address,
                'Integrity source direct helper target differs')
        return role, at

    ledger = AllocationLedger(h, state)
    def check_packet():
        require(bytes(h.uc.mem_read(packet - 16, 352)) == state['packet_snapshot'],
                'Integrity immutable packet changed')
        for pointer, raw in state['input_buffers'].items():
            require(pointer not in state['freed']
                    and bytes(h.uc.mem_read(pointer - 16, len(raw))) == raw,
                    'Integrity immutable FString changed or was freed')
    state['check_packet'] = check_packet
    codec = load('frame-integrity-codec').install(h, context, wire, state,
        ledger.allocate, ledger.release, caller, reg, number)
    require(not set(primitive.values()) & set(codec.fixtures),
            'Integrity native primitive was replaced by a fixture')

    def state_provider(machine):
        require(caller(metadata['state_getter'])[0] == 'backend', 'Integrity state provider owner differs')
        state['backend_observation']['state_getter_calls'] += 1
        state['backend_observation']['state_return'] = 1
        h.finish(0xbadc0ffe00000001)
    def debug_provider(which):
        def execute(machine):
            require(caller(metadata['debug_' + which])[0] == 'backend', 'Integrity debug provider owner differs')
            state['backend_observation']['platform_' + which + '_calls'] += 1
            chosen = 'firsttrue' if which == 'first' else 'secondtrue'
            h.finish(0x123456789abcde00 | int(state['spec']['debug_case'] == chosen))
        return execute
    def unexpected_fallback(machine):
        raise ValueError('Integrity success matrix reached backend fallback boundary')
    callbacks = {metadata['state_getter']: state_provider,
        metadata['debug_first']: debug_provider('first'), metadata['debug_second']: debug_provider('second'),
        metadata['fallback']: unexpected_fallback, **codec.fixtures}
    require(not set(primitive.values()) & set(callbacks), 'Integrity CRC/XOR callback is forbidden')
    for address, callback in callbacks.items():
        def guarded(machine, address=address, callback=callback):
            role, callsite = caller(address)
            require(reg('RSP') & 15 == 8, 'Integrity fixture Win64 alignment differs')
            state.update(fixture_owner=role, fixture_callsite=callsite)
            windows = codec.fixture_writes(address, role) if address in codec.fixtures else []
            h.uc.begin_fixture(windows)
            try: callback(machine)
            finally:
                h.uc.end_fixture()
                state.pop('fixture_owner', None); state.pop('fixture_callsite', None)
        h.add_fixture(address, guarded)

    for item in context['source_inputs'].values():
        at = int(item['address'], 16)
        size = len(bytes.fromhex(item['bytes'])) if 'bytes' in item else item['size_bytes']
        for page in range(at & ~4095, ((at + size - 1) & ~4095) + 4096, 4096): h.map_source(page)
        if 'bytes' in item:
            require(bytes(h.uc.mem_read(at, size)) == bytes.fromhex(item['bytes']),
                    'Integrity source data bytes differ')
    for at in (table, table + 0x30): h.map_source(at)
    require(number(table + 0x10) == functions['wire.login-writer']
            and number(table + 0x28) == metadata['packet_id_getter'],
            'Integrity Login source vtable writer/ID slots differ')
    item = context['integrity']['table']; at = int(item['address'], 16)
    for page in range(at & ~4095, ((at + item['size'] - 1) & ~4095) + 4096, 4096): h.map_source(page)
    require(bytes(h.uc.mem_read(at, item['size'])) == bytes.fromhex(item['bytes']),
            'Integrity source CRC table bytes differ')

    abi = {name: 0xfedcba9876543210 + i for i, name in enumerate(
        ('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}
    abi.update({'XMM' + str(i): 0x123456789abcdef0fedcba9876543210 + i for i in range(6, 16)})
    def abi_seed():
        for name, value in abi.items(): h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + name), value)
    def abi_check():
        require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.return_stack,
                'Integrity native Win64 preserved registers/stack differ')
    def observe(machine, address, size, unused):
        if state.get('mode') != 'backend': return
        step = state['backend_observation']
        if address == functions['backend']:
            require(reg('RCX') == backend and reg('RDX') == packet and number(reg('RSP')) == h.stop,
                    'Integrity direct backend entry arguments differ')
            check_packet(); step.update(entry_calls=step['entry_calls'] + 1, arguments_checked=True)
        elif address == metadata['packet_id_getter']:
            require(caller(address)[0] == 'backend' and reg('RCX') == packet,
                    'Integrity native ID receiver/edge differs')
            step['id_getter_calls'] += 1
        elif address == functions['backend'] + 0x6e:
            require(reg('RBX') == diagnostic and reg('RAX') in (0, 4), 'Integrity diagnostic index differs')
            step['diagnostic_selector_offset'] = reg('RAX')
        codec.observed(address)
    h.uc.hook_add(unicorn.UC_HOOK_CODE, observe)
    h.uc.hook_add(unicorn.UC_HOOK_MEM_READ,
        lambda machine, access, at, size, value, unused: h.uc.readable(at, size, native=True))
    h.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,
        lambda machine, access, at, size, value, unused: h.uc.writable(at, size, native=True))

    def primitive_run(spec):
        reset_policy(h.uc)
        state['mode'] = 'primitive'; codec.spec = None
        h.uc.mem_write(h.scratch + 0x30000, b'\x55' * 0x8200)
        h.uc.native_allow([(h.scratch + 0x30000, 0x8200)])
        h.begin_case(spec); operation = spec['operation']
        source = h.scratch + 0x12000 + spec.get('source_offset', 0)
        target = h.scratch + 0x18000 + spec.get('destination_offset', 0)
        state_at = h.scratch + 0x10000 + spec.get('state_offset', 0)
        payload = bytes.fromhex(spec.get('payload_hex', ''))
        def guard(at, data):
            h.uc.mem_write(at - 16, b'\xa5' * 16 + data + b'\xa6' * 16)
            h.uc.protect([(at - 16, 16), (at + len(data), 16)])
        def check_guards(at, size):
            require(bytes(h.uc.mem_read(at - 16, 16)) == b'\xa5' * 16
                    and bytes(h.uc.mem_read(at + size, 16)) == b'\xa6' * 16,
                    'Integrity primitive buffer canary changed')
        def call(address, *args):
            abi_seed(); value = h.call(address, *args); abi_check(); return value
        if operation == 'init':
            guard(state_at, spec['raw_state_seed'].to_bytes(4, 'little'))
            h.uc.native_allow([(h.scratch + 0x30000, 0x8200), (state_at, 4)])
            h.uc.native_read_allow([(h.scratch + 0x30000, 0x8200), (state_at, 4)])
            value = call(primitive['checksum_init'], state_at)
            require(value == state_at, 'Integrity initializer did not return its state alias')
            check_guards(state_at, 4)
            observation = dict(state_after=number(state_at, 4), returned_state_alias=True,
                               state_write_bytes=4, guards=True, abi=True)
        elif operation == 'crc':
            guard(state_at, spec['raw_state_seed'].to_bytes(4, 'little'))
            if spec['unmapped_source']:
                require(not payload and not any(spec['chunks']),
                        'Integrity unmapped CRC source has a positive read extent')
                source = 0x6000000000
            else:
                guard(source, payload)
                h.uc.protect([(source, len(payload))] if payload else [])
            h.uc.native_allow([(h.scratch + 0x30000, 0x8200), (state_at, 4)])
            init_calls = 0
            stack_state = [(h.scratch + 0x30000, 0x8200), (state_at, 4)]
            h.uc.native_read_allow(stack_state)
            if spec['initialize']:
                require(call(primitive['checksum_init'], state_at) == state_at,
                        'Integrity CRC initializer alias differs'); init_calls = 1
            values, states, consumed = [], [], 0
            for length in spec['chunks']:
                table_input = context['integrity']['table']
                h.uc.native_read_allow(stack_state + [(int(table_input['address'], 16), 1024)]
                    + ([(source + consumed, length)] if length else []))
                value = call(primitive['checksum'], state_at, source + consumed,
                    (spec['r8_high32'] << 32) | length)
                values.append(value); states.append(number(state_at, 4)); consumed += length
                check_guards(state_at, 4)
            if not spec['unmapped_source']:
                check_guards(source, len(payload))
                require(bytes(h.uc.mem_read(source, len(payload))) == payload,
                        'Integrity primitive CRC changed its source')
            observation = dict(values=values, states=states, init_calls=init_calls,
                update_calls=len(spec['chunks']), source_immutable=True, guards=True, abi=True)
        else:
            in_place = spec['in_place']
            if in_place: target = source
            if spec['unmapped_data']:
                source, target = 0x6000000000, 0x6000001000
            else:
                guard(source, payload)
                if not in_place:
                    guard(target, b'\x5a' * len(payload))
                    if payload: h.uc.protect([(source, len(payload))])
                if payload: h.uc.native_allow([(h.scratch + 0x30000, 0x8200), (target, len(payload))])
            h.uc.native_read_allow([(h.scratch + 0x30000, 0x8200)]
                + ([(source, len(payload))] if payload and not spec['unmapped_data'] else []))
            value = call(primitive['transform'], source,
                (spec['rdx_high32'] << 32) | spec['length_bits'], target, spec['key_bits'])
            if not spec['unmapped_data']:
                check_guards(source, len(payload))
                if not in_place: check_guards(target, len(payload))
                if not in_place:
                    require(bytes(h.uc.mem_read(source, len(payload))) == payload,
                            'Integrity disjoint XOR changed its source')
            output = b'' if spec['unmapped_data'] else bytes(h.uc.mem_read(target, len(payload)))
            observation = dict(output_hex=output.hex(), returned=value,
                effective_key_bits=number(h.entry_stack + 0x20),
                disjoint_source_immutable=None if in_place else True, guards=True, abi=True)
        require(h.entries.phase == 'complete', 'Integrity primitive declaration was not fully executed')
        return dict(spec=copy.deepcopy(spec), observation=observation)

    previous = None
    def backend_run(spec):
        nonlocal previous
        reuse = spec['reuse_step'] == 1
        require(not reuse or previous is not None and previous['reuse_step'] == 0
                and previous['prepared_ordinal'] == spec['prepared_ordinal'],
                'Integrity paired reuse has no matching prior native entry')
        reset_policy(h.uc, preserve_retired=reuse)
        if not reuse:
            state.clear(); state.update(heap=h.scratch + 0x50000, allocations={}, allocation_records={},
                allocation_owners={}, freed=set(), events=[], phase='inputs', packet=packet,
                check_packet=check_packet)
            seed_packet(h, state, ledger, packet, table, prepared[spec['prepared_ordinal']])
            data = bytearray(b'\x55' * context['backend_bytes'])
            struct.pack_into('<H', data, 0x240, spec['sequence_seed'])
            data[0x2a5] = data[0x300] = 0
            h.uc.mem_write(backend - 16, b'\xa5' * 16 + data + b'\xa6' * 16)
        else:
            check_packet()
            require(number(backend + 0x240, 2) == spec['sequence_seed'],
                    'Integrity paired sequence was not produced by prior native entry')
        h.uc.mem_write(backend + 0x248, struct.pack('<Q', spec['key_bits']))
        state.update(mode='backend', spec=spec, events=[], phase='delivery',
            backend_observation=backend_observation(number(backend + 0x240, 2)))
        h.uc.mem_write(h.scratch + 0x30000, b'\x55' * 0x8200)
        h.uc.mem_write(globals_['gate'], b'\0')
        h.uc.mem_write(diagnostic, struct.pack('<II', 1, 0))
        h.uc.mem_write(globals_['diagnostic_pointer'], struct.pack('<Q', diagnostic))
        h.uc.mem_write(flags, struct.pack('<I', spec['archive_flags_bits']))
        snapshot = bytes(h.uc.mem_read(backend - 16, context['backend_bytes'] + 32))
        h.uc.protect([(backend - 16, 16), (backend, 0x240),
            (backend + 0x242, context['backend_bytes'] - 0x242 + 16),
            (packet - 16, 352), (diagnostic, 8), (globals_['gate'], 1),
            (globals_['diagnostic_pointer'], 8), (flags, 4)])
        for pointer, raw in state['input_buffers'].items(): h.uc.protect([(pointer - 16, len(raw))])
        for name, item in context['source_inputs'].items():
            if 'bytes' in item and name != 'archive_flags':
                h.uc.protect([(int(item['address'], 16), len(bytes.fromhex(item['bytes'])))])
        h.uc.native_allow([(h.scratch + 0x30000, 0x8200),
                          (h.scratch + 0x50000, 0xb0000), (backend + 0x240, 2)])
        codec.seed(spec, backend); h.begin_case(spec); abi_seed()
        returned = h.call(functions['backend'], backend, packet, budget=3000000); abi_check()
        check_packet(); step = state['backend_observation']
        step.update(return_byte=returned & 255, sequence_after=number(backend + 0x240, 2))
        step['request_id'] = codec.result['request_id']
        expected = bytearray(snapshot); struct.pack_into('<H', expected, 16 + 0x240, step['sequence_after'])
        require(bytes(h.uc.mem_read(backend - 16, len(expected))) == bytes(expected),
                'Integrity backend changed outside native sequence field')
        for pointer in state['allocations']: ledger.check_canary(pointer)
        require(set(state['allocations']) - set(state['input_buffers']) == state['freed'],
                'Integrity archive/temporary leak or input buffer free')
        require(h.entries.phase == 'complete', 'Integrity backend declaration was not fully executed')
        observation = dict(backend=dict(step), wire=codec.check(spec),
            ownership=dict(packet_immutable=True, strings_immutable=True, input_buffers_live=True,
                archive_buffers_released=True, guards=True, abi=True),
            same_backend_as_previous=reuse, same_packet_as_previous=reuse)
        previous = dict(spec)
        return dict(spec=copy.deepcopy(spec), observation=observation)

    def run(spec):
        contract.validate_spec(spec)
        return primitive_run(spec) if spec['entry_mode'] == 'primitive' else backend_run(spec)
    return run
