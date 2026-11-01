"""Run only declared buffer entries with native storage, append and wake gates.

Initial objects and opaque allocation effects are explicit fixtures. All result
bytes come from emulated memory; this module never imports the byte oracle.
"""
import copy
import importlib.util
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(value, message):
    if not value:
        raise ValueError(message)


def install(h, context, contract):
    import unicorn
    memory = load('buffer-transport-memory')
    policy = memory.MemoryPolicy(h.uc)
    h.uc = policy
    functions = {key: int(value, 16) for key, value in context['functions'].items()}
    helpers = {key: int(value, 16) for key, value in context['helpers'].items()}
    leaf = int(next(iter(context['leaves'])), 16)
    role_counts = {'vector.resize': 'resize', 'vector.grow': 'grow',
        'queue.append': 'append', 'transport': 'transport', 'archive.raw': 'archive_raw'}
    entries = {value: key for key, value in functions.items()}
    entries[leaf] = 'set_count'
    state = {}
    body, wake_table, wake_target = (h.scratch + offset for offset in (0x10000, 0x12000, 0x13000))
    native = load('build-native-entry-code')
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    returns, growth_jumps = {}, set()
    for function in h.fragments:
        role = next(key for key, at in functions.items() if at == int(function['address'], 16))
        for row in function['instructions']:
            at, data = int(row['address'], 16), bytes.fromhex(row['bytes'])
            instruction = next(decoder.disasm(data, at))
            if instruction.mnemonic == 'call':
                direct = (instruction.operands[0].imm
                    if instruction.operands[0].type == native.X86_OP_IMM else None)
                require(at + instruction.size not in returns, 'Buffer source return address repeats')
                returns[at + instruction.size] = (role, at, direct)
            elif (instruction.mnemonic == 'jmp' and instruction.operands
                    and instruction.operands[0].type == native.X86_OP_IMM
                    and instruction.operands[0].imm == functions['vector.grow']):
                growth_jumps.add(at)
    require(len(growth_jumps) == 1, 'Buffer native growth tail identity differs')

    def reg(name):
        return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def number(at, size=8):
        return int.from_bytes(h.uc.mem_read(at, size), 'little')

    def caller(address, roles):
        found = returns.get(number(reg('RSP')))
        require(found is not None and found[0] in roles,
                'Buffer provider caller is not the declared native source owner')
        role, site, direct = found
        require(direct is None or direct == address, 'Buffer provider native direct target differs')
        require(reg('RSP') & 15 == 8, 'Buffer provider Win64 stack alignment differs')
        return role, site

    def live_span(at, size):
        if size:
            state['ledger'].containing(at, size)

    def allocation(machine):
        caller(helpers['allocate'], {'vector.grow'})
        size = reg('RCX')
        address = state['ledger'].allocate(size, owner='vector', fixture=True)
        state['events'].append(dict(kind='allocate', size=size))
        h.finish(address)

    def release(machine):
        caller(helpers['free'], {'vector.grow'})
        address, size = reg('RCX'), reg('RDX')
        row = state['ledger'].records.get(address)
        require(row is not None and row['owner'] == 'vector', 'Buffer native free does not own vector storage')
        state['ledger'].release(address, size)
        state['events'].append(dict(kind='free', size=size))
        h.finish(0xfeedface00000000)

    def copy_provider(name):
        def execute(machine):
            owners = {'vector.grow'} if name == 'memmove' else {'queue.append', 'archive.raw'}
            caller(helpers[name], owners)
            destination, source, size = reg('RCX'), reg('RDX'), reg('R8')
            live_span(source, size)
            live_span(destination, size)
            memory.copy_memory(h.uc, destination, source, size, move=name == 'memmove')
            state['events'].append(dict(kind=name, size=size))
            h.finish(destination)
        return execute

    def fill(machine):
        caller(helpers['memset'], {'vector.resize', 'vector.grow'})
        destination, size = reg('RCX'), reg('R8')
        live_span(destination, size)
        require(reg('RDX') & 255 == 0, 'Buffer native resize fill is not zero')
        memory.fill_memory(h.uc, destination, reg('RDX'), size)
        state['events'].append(dict(kind='memset', size=size))
        h.finish(destination)

    def wake(machine):
        role, site = caller(wake_target, {'transport'})
        require(returns[site + 3][2] is None and reg('RCX') == body + 0x50
                and reg('RDX') == body + 0x110 and number(body + 0x50) == wake_table
                and number(wake_table + 0x20) == wake_target
                and number(body + 0x108, 4) == 1 and number(body + 0xc0, 4) == 0,
                'Buffer synthetic wake source ABI/object/slot/predicate differs')
        state['events'].append(dict(kind='wake'))
        state['wake_checked'] = True
        h.finish(0x123456789abcde00)

    for name, handler in dict(allocate=allocation, free=release, memcpy=copy_provider('memcpy'),
            memmove=copy_provider('memmove'), memset=fill).items():
        h.add_fixture(helpers[name], handler)
    h.add_fixture(wake_target, wake)
    # This callback is synthetic; real PE provider/import bytes are untouched.
    policy.mem_write(wake_target, b'\xc3')
    for item in context['source_inputs'].values():
        at, data = int(item['address'], 16), bytes.fromhex(item['bytes'])
        for page in range(at & ~4095, ((at + len(data) - 1) & ~4095) + 4096, 4096):
            h.map_source(page)
        require(bytes(h.uc.mem_read(at, len(data))) == data, 'Buffer source input bytes differ')
    source_table = int(context['source_inputs']['archive_table']['address'], 16)
    require(source_table == int(h.wire['archive']['table'], 16), 'Buffer proved archive vtable differs')
    require(int(h.wire['archive']['raw'], 16) == functions['archive.raw']
            and int(h.wire['archive']['growth'], 16) == functions['vector.resize']
            and int(h.wire['archive_helpers']['set_count_leaf'], 16) == leaf,
            'Buffer proved archive source layout/consumer differs')

    def memory_read(machine, access, address, size, value, unused):
        if h.call_active:
            policy.readable(address, size, native=True)

    def memory_write(machine, access, address, size, value, unused):
        if h.call_active:
            policy.writable(address, size, native=True)
    policy.hook_add(unicorn.UC_HOOK_MEM_READ, memory_read)
    policy.hook_add(unicorn.UC_HOOK_MEM_WRITE, memory_write)

    def observe(machine, address, size, unused):
        if not h.call_active or not state.get('running'):
            return
        if address in entries:
            role = entries[address]
            key = role_counts.get(role, role)
            state['calls'][key] += 1
            if role in ('vector.resize', 'vector.grow'):
                require(reg('RCX') == state['vector'], 'Buffer shared native vector receiver differs')
                if role == 'vector.grow':
                    require(state.get('previous_native') in growth_jumps,
                            'Buffer native growth bypassed source resize tail')
            elif role == 'queue.append':
                require(reg('RCX') == state['queue'] and reg('RDX') == state['source']
                        and reg('R8') & 0xffffffff == state['source_size'],
                        'Buffer native queue append arguments differ')
            elif role in ('transport', 'archive.raw'):
                require(reg('RCX') == body and reg('RDX') == state['source']
                        and reg('R8') & 0xffffffff == state['source_size'],
                        'Buffer native consumer arguments differ')
            elif role == 'set_count':
                caller(leaf, {'archive.raw'})
                require(reg('RCX') == body and reg('RDX') == state['source_size'],
                        'Buffer native set_count arguments differ')
        if any(lo == address for lo, hi in h.instruction_spans):
            state['previous_native'] = address
    policy.hook_add(unicorn.UC_HOOK_CODE, observe)

    abi = {name: 0xfedcba9876543210 + i for i, name in enumerate(
        ('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}
    abi.update({'XMM' + str(i): 0x123456789abcdef0fedcba9876543210 + i for i in range(6, 16)})

    def seed_abi():
        for name, value in abi.items():
            policy.reg_write(getattr(h.x, 'UC_X86_REG_' + name), value)

    def check_abi():
        require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.return_stack,
                'Buffer native Win64 preserved registers/stack differ')

    def seed_storage(initial, mode):
        capacity = initial['capacity']
        payload = bytes.fromhex(initial['payload_hex']) + (b'\0' if initial['sentinel'] else b'')
        logical = capacity if mode == 'archive' else len(payload)
        if not capacity:
            require(not payload and not logical, 'Buffer zero-capacity initial storage differs')
            return 0, 0, 0
        size = capacity + (39 if capacity >= 4096 else 0)
        raw = state['ledger'].allocate(size, owner='vector')
        pointer = (raw + 39) & ~31 if capacity >= 4096 else raw
        if capacity >= 4096:
            policy.mem_write(pointer - 8, struct.pack('<Q', raw))
        if payload:
            policy.mem_write(pointer, payload)
        return pointer, pointer + logical, pointer + capacity

    def descriptor():
        begin, end, limit = struct.unpack('<QQQ', policy.mem_read(state['vector'], 24))
        state['ledger'].check_vector(begin, end, limit)
        return begin, end, limit

    def run(spec):
        contract.validate_spec(spec)
        require(not h.call_active, 'Buffer case begins during native entry')
        policy.reset()
        state.clear()
        mode, initial = spec['mode'], spec['initial']
        extent = {'resize': context['vector_bytes'], 'append': context['queue_bytes'],
            'transport': context['transport_bytes'], 'archive': context['archive_bytes']}[mode]
        vector = body + {'resize': 0, 'append': 8, 'transport': 0x178, 'archive': 0x18}[mode]
        read_windows = [(body, extent), (h.scratch + 0x30000, 0xf000),
            (source_table, len(bytes.fromhex(context['source_inputs']['archive_table']['bytes'])))]
        if mode == 'transport':
            read_windows.append((wake_table, 0x28))
        state.update(vector=vector, queue=body if mode == 'append' else body + 0x170,
            ledger=memory.AllocationLedger(policy, h.scratch + 0x50000,
                h.scratch + 0x1e0000, read_windows=read_windows), running=False)
        policy.native_allow([(h.scratch + 0x30000, 0xf000), (vector, 24)])
        if mode == 'archive':
            policy.native_extend([(body + 8, 4), (body + 0x30, 12)])
        policy.mem_write(body - 16, b'\xa3' * 16 + b'\x6d' * extent + b'\xa4' * 16)
        policy.protect([(body - 16, 16), (body + extent, 16)])
        policy.mem_write(vector, struct.pack('<QQQ', *seed_storage(initial, mode)))
        if mode == 'archive':
            # Source constructor writes only these fields. Padding keeps poison.
            # Native constructor is deliberately outside this five-root proof.
            policy.mem_write(body, struct.pack('<QII', source_table, 0, initial['flags_bits']))
            policy.mem_write(body + 0x10, b'\x01')
            count = len(bytes.fromhex(initial['payload_hex']))
            policy.mem_write(body + 0x30, struct.pack('<III', initial['capacity'], count, count))
        if mode == 'transport':
            policy.mem_write(body + 0x50, struct.pack('<Q', wake_table))
            policy.mem_write(wake_table, b'\x6e' * 0x20 + struct.pack('<Q', wake_target))
            policy.protect([(wake_table, 0x28)])
        h.begin_case(spec)
        observations = []
        for step in spec['steps']:
            state.update(calls=dict.fromkeys(contract.CALL_KEYS, 0), events=[], wake_checked=None,
                previous_native=None, source=0, source_size=0)
            source_base = None
            if mode != 'resize':
                payload = bytes.fromhex(step['payload_hex'])
                allocation_size = max(1, len(payload)) + step['source_offset']
                source_base = state['ledger'].allocate(allocation_size, owner='input')
                source = source_base + step['source_offset']
                if payload:
                    policy.mem_write(source, payload)
                state['ledger'].input_read_span(source_base, step['source_offset'], len(payload))
                source_snapshot = bytes(policy.mem_read(source_base, allocation_size))
                policy.protect([(source_base, allocation_size)])
                state.update(source=source, source_size=len(payload))
                if mode == 'transport':
                    policy.mem_write(body + 0x108, struct.pack('<I', step['state']))
                    policy.mem_write(body + 0xc0, struct.pack('<I', step['busy']))
            old_pointer = descriptor()[0]
            before = policy.snapshot(body, extent)
            seed_abi()
            state['running'] = True
            try:
                role = {'resize': 'vector.resize', 'append': 'queue.append',
                    'transport': 'transport', 'archive': 'archive.raw'}[mode]
                if mode == 'resize':
                    result = h.call(functions[role], vector, step['requested_size'])
                else:
                    result = h.call(functions[role], body, state['source'],
                        (step['r8_high32'] << 32) | state['source_size'])
            finally:
                state['running'] = False
            check_abi()
            begin, end, limit = descriptor()
            if mode != 'resize':
                require(result & 255 == 1, 'Buffer native ordinary return is not AL1')
                require(bytes(policy.mem_read(source_base, allocation_size)) == source_snapshot,
                        'Buffer immutable source changed during native entry')
                state['ledger'].release(source_base, allocation_size)
            # Check every byte outside the explicitly mutable descriptor/counters.
            after = policy.snapshot(body, extent)
            writable = [(vector - body, vector - body + 24)]
            if mode == 'archive':
                writable += [(8, 12), (0x30, 0x3c)]
            require(all(before[i] == after[i] for i in range(extent)
                if not any(lo <= i < hi for lo, hi in writable)),
                'Buffer native consumer changed unrelated object bytes')
            require(policy.snapshot(body - 16, 16) == b'\xa3' * 16
                    and policy.snapshot(body + extent, 16) == b'\xa4' * 16,
                    'Buffer object guard changed')
            state['ledger'].check_guards()
            archive = None
            if mode == 'archive':
                capacity, cursor, count = struct.unpack('<III', policy.mem_read(body + 0x30, 12))
                require(cursor == count <= capacity and capacity == end - begin,
                        'Buffer native archive counters/vector differ')
                archive = dict(capacity=capacity, cursor=cursor, count=count,
                    flags_bits=number(body + 0xc, 4), last_count=number(body + 8, 4),
                    payload_hex=bytes(policy.mem_read(begin, count)).hex() if count else '')
            observations.append(dict(size=end - begin, capacity=limit - begin,
                payload_hex=bytes(policy.mem_read(begin, end - begin)).hex() if end > begin else '',
                spare_hex=bytes(policy.mem_read(end, limit - end)).hex() if limit > end else '',
                pointer_changed=begin != old_pointer, return_al=None if mode == 'resize' else result & 255,
                calls=copy.deepcopy(state['calls']), events=copy.deepcopy(state['events']),
                archive=archive, wake_arguments_checked=state['wake_checked']))
        require(h.entries.phase == 'complete' and len(h.entries.history) == len(spec['steps']),
                'Buffer declared native entries were not all completed')
        # Every surviving raw block belongs to the single retained vector. Input
        # buffers and replaced vector allocations must have been retired.
        begin, end, limit = descriptor()
        live = [(at, row) for at, row in state['ledger'].records.items() if not row['retired']]
        require(len(live) == int(limit > begin) and all(row['owner'] == 'vector'
                and at <= begin and limit <= at + row['size'] for at, row in live),
                'Buffer final retained vector ownership differs')
        return dict(spec=copy.deepcopy(spec), observation=dict(steps=observations,
            guards=True, abi=True, source_immutable=True, ownership_checked=True))

    return run
