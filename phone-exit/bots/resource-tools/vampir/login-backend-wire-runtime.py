"""Native source service publication and Login backend/wire fixture environment."""
from pathlib import Path
import struct
from importlib.util import spec_from_file_location, module_from_spec

HERE = Path(__file__).resolve().parent
STRINGS = (0x10, 0x20, 0x30, 0x40, 0x58, 0x68, 0x78, 0x88,
           0xa0, 0xb8, 0xc8, 0xd8, 0xe8, 0x100, 0x110)
SCENARIOS = (
    ('windows-all', 'Windows', True, True, 7, 1),
    ('windows-mode-zero', 'Windows', True, True, 7, 0),
    ('windows-mode-two', 'Windows', True, True, 7, 2),
    ('windows-mode-negative', 'Windows', True, True, 7, 0xffffffff),
    ('sdk-disabled', 'Windows', False, True, 7, 1),
    ('sdk-absent', 'Windows', True, False, 7, 1),
    ('handles-absent', 'Windows', True, True, 0, 1),
    ('main-absent', 'Windows', True, True, 6, 1),
    ('aux-absent', 'Windows', True, True, 5, 1),
    ('extra-absent', 'Windows', True, True, 3, 1),
    ('android', 'Android', True, True, 7, 1),
    ('ios', 'IOS', True, True, 7, 1),
    ('unknown-platform', 'Linux', True, True, 7, 1),
    ('empty-platform', '', True, True, 7, 1),
)


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pending_layout(name, nodes, buckets, timeout_bits):
    """Synthetic, lookup-consistent pending state; not native insertion proof."""
    if name not in ('empty-count-equal', 'inline-bucket-miss', 'heap-chain-miss', 'heap-chain-hit'):
        raise ValueError('Login pending provider case differs')
    body = bytearray(160)
    heap = name.startswith('heap-')
    hit = name == 'heap-chain-hit'
    struct.pack_into('<I', body, 0x30, timeout_bits)
    struct.pack_into('<Q', body, 0x38, nodes)
    struct.pack_into('<I', body, 0x40, 0 if name == 'empty-count-equal' else 2 if hit else 1)
    struct.pack_into('<I', body, 0x6c, 0)
    struct.pack_into('<ii', body, 0x70, -1, 0 if name == 'inline-bucket-miss' else -1)
    struct.pack_into('<Q', body, 0x78, buckets if heap else 0)
    struct.pack_into('<I', body, 0x80, 4 if heap else 2 if name == 'inline-bucket-miss' else 1)
    node_data = bytearray(64)
    struct.pack_into('<h', node_data, 0, 8 if heap else 5)
    struct.pack_into('<i', node_data, 0x18, 1 if hit else -1)
    struct.pack_into('<h', node_data, 32, 4)
    struct.pack_into('<i', node_data, 32 + 0x18, -1)
    return bytes(body), bytes(node_data), struct.pack('<iiii', 0, -1, -1, -1)


def check_pending_aliases(stack, outpair, pair, key, record):
    values = (stack, outpair, pair, key, record)
    if any(type(value) is not int for value in values) or values[1:] != (
            stack + 0x58, stack + 0x38, stack + 0x68, stack + 0x28):
        raise ValueError('Login pending insert source stack aliases differ')


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


def handoff_state(spec, settings):
    return dict(pending_case=spec['pending_case'], forwarded=settings['forwarded'],
        configured_timeout_bits=settings['timeout_bits'], entry_timeout_bits=0, selected_timeout_bits=None,
        sender_calls=0, sender_returns=0, pending_insert_calls=0, delegate_calls=0,
        service_getter_calls=0, service_calls=0, source_virtual_calls=0, service_same_packet=None,
        packet_immutable=True, strings_immutable=True, source_service_vtable=True,
        sender_arguments_checked=False, fifth_argument_checked=False,
        pending_insert_arguments_checked=None, delegate_arguments_checked=None,
        getter_global_checked=None, service_arguments=None, service_arguments_checked=None,
        thunk_calls=0, thunk_arguments_checked=None, thunk_same_packet=None,
        observed_lookup_keys=[], bucket_storage='not-read')


def publisher_expected(poison, primary_table, secondary_table):
    """Final fields written by the whole publisher; untouched holes stay poison."""
    if type(poison) is not int or not 0 <= poison <= 255:
        raise ValueError('Backend publisher poison differs')
    out = bytearray([poison] * 240)
    struct.pack_into('<Q', out, 0, primary_table)
    struct.pack_into('<Q', out, 8, secondary_table)
    for offset in (0x10, 0x18, 0x28, 0x30, 0x48, 0x68, 0x78, 0x80, 0x88, 0x90,
                   0xa8, 0xc8, 0xe0, 0xe8):
        struct.pack_into('<Q', out, offset, 0)
    for offset in (0x50, 0x5c, 0x70, 0xb0, 0xbc, 0xd0):
        struct.pack_into('<I', out, offset, 0)
    for offset, value in ((0x54, 128), (0x58, 0xffffffff), (0xb4, 128), (0xb8, 0xffffffff)):
        struct.pack_into('<I', out, offset, value)
    return bytes(out)


def fixture_for_owner(address, role, parent_callbacks, codec_callbacks):
    """A shared numeric address never lets the last installer select its ABI."""
    codec_owner = role.startswith('wire.') or (role == 'backend' and address in codec_callbacks)
    callback = codec_callbacks.get(address) if codec_owner else parent_callbacks.get(address)
    if callback is None:
        raise ValueError('Backend fixture has no callback for checked native owner')
    return callback, codec_owner


def install(h, prepare, context, wire, contract):
    sdk, metadata = prepare['native_sdk'], prepare['native_metadata']
    table = int(prepare['packet_table'], 16)
    fixture = {k: int(v, 16) for k, v in prepare['fixtures'].items()}
    globals_ = {k: int(v, 16) for k, v in prepare['globals'].items()}
    owner, manager, language, session, receiver, flags, sdk_value = [h.scratch + n for n in
        (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000)]
    handles = (h.scratch + 0x8000, h.scratch + 0x8100, h.scratch + 0x8200)
    state = {}
    parent_contract = load('login-send-handoff-case-contracts')
    ledger = AllocationLedger(h, state)

    def reg(name):
        return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def allocate(size, kind='utf16', owner=None):
        return ledger.allocate(size, kind, owner)

    def release(at, expected_kind=None, expected_size=None):
        return ledger.release(at, expected_kind, expected_size)

    def write_text(at, text):
        raw = text.encode('utf-16le') + b'\0\0' if text else b''
        pointer = allocate(len(raw)) if raw else 0
        if raw:
            h.uc.mem_write(pointer, raw)
        h.uc.mem_write(at, struct.pack('<QII', pointer, len(raw) // 2, len(raw) // 2))
        return at

    def read_text(at):
        pointer, count, capacity = struct.unpack('<QII', h.uc.mem_read(at, 16))
        if not 0 <= count <= capacity <= 1024 or (count and not pointer):
            raise ValueError('Login string descriptor bound')
        if not count:
            return ''
        if pointer in state['freed']:
            raise ValueError('Login reads freed string')
        raw = bytes(h.uc.mem_read(pointer, count * 2))
        if not raw.endswith(b'\0\0'):
            raise ValueError('Login string terminator differs')
        return raw[:-2].decode('utf-16le')

    def literal(at, wide=False):
        data = bytearray()
        width = 2 if wide else 1
        for i in range(256):
            chunk = bytes(h.uc.mem_read(at + i * width, width))
            if chunk == bytes(width):
                return data.decode('utf-16le' if wide else 'ascii')
            data.extend(chunk)
        raise ValueError('Login literal bound')

    def require(value, message):
        if not value:
            raise ValueError(message)

    def handler(name):
        def execute(machine):
            a, b, c, d = [reg(k) for k in ('RCX', 'RDX', 'R8', 'R9')]
            state['events'].append(name)
            result = 0
            if name == 'platform_text':
                result = write_text(a, state['platform'])
            elif name in ('ascii_string', 'wide_string'):
                result = write_text(a, literal(b, name == 'wide_string'))
            elif name == 'wide_compare':
                result = int(literal(a, True) != literal(b, True))
            elif name == 'copy_string':
                old = int.from_bytes(h.uc.mem_read(a, 8), 'little')
                if old:
                    release(old)
                result = write_text(a, read_text(b))
            elif name == 'resize':
                require(0 <= b <= 1024, 'Login resize bound')
                old, count, capacity = struct.unpack('<QII', h.uc.mem_read(a, 16))
                previous = bytes(h.uc.mem_read(old, min(capacity, b) * 2)) if old else b''
                if old:
                    release(old)
                pointer = allocate(b * 2) if b else 0
                if previous:
                    h.uc.mem_write(pointer, previous)
                h.uc.mem_write(a, struct.pack('<QII', pointer, count, b))
            elif name == 'free':
                release(a)
            elif name == 'nm_provider':
                result = write_text(a, state['nm'])
            elif name == 'selector':
                result = state['selector']
            elif name == 'owner_number':
                require(a == owner, 'Login owner number receiver differs')
                result = state['number']
            elif name == 'language':
                result = language
            elif name == 'sdk_manager':
                result = manager if state['manager_present'] else 0
            elif name == 'sdk_mode':
                require(a == handles[0], 'Login SDK mode handle differs')
                result = state['mode']
            elif name in ('sdk_aux_text', 'sdk_main_text'):
                require(a == handles[1 if name == 'sdk_aux_text' else 0], 'Login SDK text handle differs')
                result = write_text(b, state['aux' if name == 'sdk_aux_text' else 'main'])
            elif name == 'sdk_value':
                require(a == handles[0], 'Login SDK value handle differs')
                result = sdk_value
            elif name == 'flags_manager':
                result = flags
            elif name == 'sdk_flag':
                require(a == flags, 'Login SDK flag receiver differs')
                result = state['flag']
            elif name == 'sdk_extra_flag':
                require(a == handles[2], 'Login SDK extra handle differs')
                result = state['extra_flag']
            elif name == 'session':
                result = session
            elif name == 'log':
                require(state.get('sent'), 'Login log before send')
            elif name == 'post_receiver':
                result = receiver
            elif name == 'format_number':
                require(c == state['number'], 'Login formatted number differs')
                require(literal(b, True) == state['format_literal'], 'Login number format differs')
                result = write_text(a, 'number-fixture')
            elif name == 'post_notify':
                require(a == receiver and read_text(b) == 'number-fixture', 'Login post-send notification differs')
            elif name == 'variant_number':
                require(b == state['number'], 'Login variant number differs')
                h.uc.mem_write(a, struct.pack('<QQQ', b, 0, 0))
            elif name == 'variant_reserve':
                require(b == 1, 'Login variant count differs')
                h.uc.mem_write(a, struct.pack('<QII', allocate(24), 1, 1))
            elif name == 'variant_copy':
                require(c == 1 and int.from_bytes(h.uc.mem_read(b, 8), 'little') == state['number'],
                        'Login variant copy differs')
                h.uc.mem_write(a, bytes(h.uc.mem_read(b, 24)))
            elif name == 'event_object':
                require(literal(b, True) == state['event_literal'], 'Login SDK event name differs')
                pointer, count, capacity = struct.unpack('<QII', h.uc.mem_read(c, 16))
                require(count == capacity == 1 and int.from_bytes(h.uc.mem_read(pointer, 8), 'little') == state['number'],
                        'Login SDK event value differs')
                h.uc.mem_write(a, struct.pack('<QQ', allocate(16), 1))
                result = a
            elif name == 'sdk_event':
                require(a == handles[0] and state.get('sent'), 'Login SDK event receiver/lifecycle differs')
                require(int.from_bytes(h.uc.mem_read(b, 8), 'little') in state['allocations'], 'Login SDK event object differs')
            elif name == 'variant_destroy':
                require(a in state['allocations'] and b == 1, 'Login variant cleanup differs')
            elif name == 'destructor':
                require(a == state['packet'], 'Login destructor receiver differs')
                for off in STRINGS:
                    pointer = int.from_bytes(h.uc.mem_read(a + off, 8), 'little')
                    if pointer:
                        release(pointer)
                state['destroyed'] = True
            else:
                raise ValueError('Unknown Login fixture ' + name)
            h.finish(result)
        return execute

    for name, address in fixture.items():
        if name == 'send':
            continue
        if metadata and name == 'sdk_aux_text':
            if address != int(metadata['functions']['collector'], 16):
                raise ValueError('Login metadata collector binding differs')
            continue
        if sdk and name in sdk['native_names']:
            continue
        h.add_fixture(address, handler(name))
    if sdk:
        seed_sdk, check_sdk, metadata_fields = load('login-sdk-fixtures').install(
            load, h, sdk, fixture, state, owner, manager, language, flags, handles,
            allocate, release, write_text, read_text, literal, reg)
    if metadata:
        metadata_module = load('verify-login-metadata-context')
        def metadata_entered():
            require(reg('RCX') == handles[1], 'Login metadata collector handle differs')
            state['events'].append('sdk_aux_text')
        seed_metadata, check_metadata, metadata_state = metadata_module.session(metadata, h,
            dict(allocate=allocate, release=release, outer=state, entered=metadata_entered))
    tag_pointer = int.from_bytes(h.uc.mem_read(globals_['tag_pointer'], 8), 'little')
    require(tag_pointer == int(prepare['tag_literal'], 16), 'Login tag source pointer differs')
    page = tag_pointer & ~4095
    if not any(lo <= page <= hi for lo, hi, _ in h.uc.mem_regions()):
        h.uc.mem_map(page, 4096)
        off = h.image.offset(page - h.image.pe.base)
        h.uc.mem_write(page, h.raw[off:off + 4096])
    compiled_tag = literal(tag_pointer)
    tag_source=prepare.get('compiled_tag_source')
    if tag_source is None:
        if prepare['source_sha256'] not in (
                'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960',
                'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'):
            raise ValueError('New Login source requires explicit compiled tag metadata')
        tag_source=dict(literal=prepare['tag_literal'],value='32283C4C6485307BCF524765A84409C3')
    require(tag_source.get('literal')==prepare['tag_literal'] and compiled_tag==tag_source.get('value'),
            'Login compiled tag differs')
    format_literal = literal(int(prepare['format_literal'], 16), True)
    event_literal = literal(int(prepare['event_literal'], 16), True)

    sender = {key: int(value, 16) for key, value in context['sender'].items()
              if key not in ('virtual_slot', 'fifth_argument_bits')}
    require(context['sender']['virtual_slot'] == 56 and context['sender']['fifth_argument_bits'] == 0,
            'Login sender source ABI metadata differs')
    nodes, buckets, service, backend, diagnostic = [h.scratch + at for at in
        (0xd000, 0xd100, 0xc000, 0xf000, 0x11000)]
    service_meta = context['service']
    backend_meta = context['backend']
    functions = {key: int(at, 16) for key, at in context['functions'].items()}
    primary_table = int(service_meta['primary_table'], 16)
    secondary_table = int(service_meta['secondary_table'], 16)
    service_thunk = int.from_bytes(bytes.fromhex(context['source_inputs']['service_primary_table']['bytes'])[56:64], 'little')
    h.map_source(sender['service_global'])
    h.map_source(sender['service_global'] + 7)
    returns = {}
    native = load('build-native-entry-code')
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    for role, sites in context['call_sites'].items():
        for text, target in sites.items():
            at = int(text, 16)
            off = h.image.offset(at - h.image.pe.base)
            instruction = next(decoder.disasm(h.raw[off:off + 15], at))
            require(instruction.mnemonic == 'call', 'Login handoff call metadata differs')
            require(at + instruction.size not in returns, 'Login handoff duplicate return address')
            returns[at + instruction.size] = (role, at, target)

    def number(at, size=8):
        return int.from_bytes(h.uc.mem_read(at, size), 'little')

    def caller(address):
        result = returns.get(number(reg('RSP')))
        require(result is not None, 'Login handoff fixture caller is not native source')
        role, at, target = result
        if target.startswith('0x'):
            require(int(target, 16) == address, 'Login handoff fixture direct target differs')
        return role, at

    def packet_snapshot(packet):
        contents = bytes(h.uc.mem_read(packet, 320))
        texts = {}
        for off in STRINGS:
            pointer, count, capacity = struct.unpack_from('<QII', contents, off)
            require(0 <= count <= capacity <= 1024 and (not count or pointer),
                    'Login handoff packet descriptor differs')
            if count:
                require(pointer in state['allocations'] and pointer not in state['freed']
                        and count * 2 <= state['allocations'][pointer], 'Login handoff string ownership differs')
                texts[off] = (pointer, bytes(h.uc.mem_read(pointer, count * 2)))
                require(texts[off][1].endswith(b'\0\0'), 'Login handoff packet string terminator differs')
        return contents, texts

    def check_packet():
        require(packet_snapshot(state['packet']) == state['packet_snapshot'],
                'Login native handoff mutated prepared packet or strings')

    def seed_sender(spec):
        settings = parent_contract.pending_settings(spec['pending_case'])
        state['handoff'] = handoff_state(spec, settings)
        body, node_data, bucket_data = pending_layout(spec['pending_case'], nodes, buckets, settings['timeout_bits'])
        h.uc.mem_write(session - 16, b'\xa5' * 16 + body + b'\xa6' * 16)
        h.uc.mem_write(nodes - 16, b'\xa5' * 16 + node_data + b'\xa6' * 16)
        h.uc.mem_write(buckets - 16, b'\xa5' * 16 + bucket_data + b'\xa6' * 16)
        state['sender_inputs'] = [(at, bytes(h.uc.mem_read(at, size))) for at, size in
            ((session - 16, 192), (nodes - 16, 96), (buckets - 16, 48))]
        h.uc.protect([(at, len(value)) for at, value in state['sender_inputs']])

    def pending_insert(machine):
        role, at = caller(sender['pending_insert'])
        require(role == 'sender' and at == sender['address'] + 0xb9, 'Login pending insert source caller differs')
        require(reg('RCX') == session + 0x38 and reg('R9') == 0,
                'Login pending insert receiver/mode differs')
        pair = reg('R8')
        key, record = number(pair), number(pair + 8)
        check_pending_aliases(reg('RSP'), reg('RDX'), pair, key, record)
        require(number(key, 2) == 4 and number(record + 8) == state['send_capability'],
                'Login pending insert key/capability differs')
        require(number(record, 4) == number(session + 0x30, 4), 'Login sender timeout fallback differs')
        step = state['handoff']
        step['pending_insert_calls'] += 1
        step['selected_timeout_bits'] = number(record, 4)
        step['pending_insert_arguments_checked'] = True
        h.finish(0)

    def delegate_add(machine):
        role, at = caller(sender['delegate_add'])
        require(role == 'sender' and at == sender['address'] + 0xd3 and reg('RCX') == session + 8,
                'Login delegate source caller/receiver differs')
        require(reg('RDX') == reg('RSP') + 0x58, 'Login delegate source stack alias differs')
        require(number(reg('RDX')) == sender['delegate_literal'], 'Login delegate source literal differs')
        state['handoff']['delegate_calls'] += 1
        state['handoff']['delegate_arguments_checked'] = True
        h.finish(0)

    h.add_fixture(sender['pending_insert'], pending_insert)
    h.add_fixture(sender['delegate_add'], delegate_add)

    copy_address = int(context['helpers']['memcpy'], 16)
    def copy_fixture(machine):
        a, b, size = (reg(key) for key in ('RCX', 'RDX', 'R8'))
        require(0 <= size <= 4096 and all(h.scratch <= pointer <= h.scratch + 0x200000 - size
                for pointer in (a, b)), 'Login handoff memcpy bound differs')
        if size:
            h.uc.mem_write(a, bytes(h.uc.mem_read(b, size)))
        h.finish(a)
    h.add_fixture(copy_address, copy_fixture)

    for item in context['source_inputs'].values():
        address = int(item['address'], 16)
        length = len(bytes.fromhex(item['bytes'])) if 'bytes' in item else item['size_bytes']
        for page in range(address & ~4095, ((address + length - 1) & ~4095) + 4096, 4096):
            h.map_source(page)
        if 'bytes' in item:
            require(bytes(h.uc.mem_read(address, length)) == bytes.fromhex(item['bytes']),
                    'Backend source input bytes differ')
    backend_addresses = {key: int(at, 16) for key, at in backend_meta.items() if key != 'globals'}
    backend_globals = {key: int(at, 16) for key, at in backend_meta['globals'].items()}
    publisher_address = functions['publisher']
    backend_address = functions['backend']

    def abi_seed():
        for register, value in abi.items():
            h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + register), value)

    def abi_check():
        require(all(reg(key) == value for key, value in abi.items()) and reg('RSP') == h.return_stack,
                'Backend native setup/delivery ABI differs')

    def service_guards():
        require(bytes(h.uc.mem_read(service - 16, 16)) == b'\xa5' * 16
                and bytes(h.uc.mem_read(service + 240, 16)) == b'\xa6' * 16,
                'Backend native service object guard changed')
        require(bytes(h.uc.mem_read(backend - 16, 16)) == b'\xa5' * 16
                and bytes(h.uc.mem_read(backend + context['backend_bytes'], 16)) == b'\xa6' * 16,
                'Backend ambient object guard changed')

    def publisher_helper(machine):
        role, at = caller(int(service_meta['helper'], 16))
        require(role == 'publisher' and reg('RCX') == service + 8,
                'Backend publisher helper receiver differs')
        require(number(sender['service_global']) == service
                and number(service) == int(service_meta['initial_table'], 16),
                'Backend publisher pre-helper publication differs')
        state['publisher_helper_calls'] += 1
        h.finish(0)

    def state_provider(machine):
        role, at = caller(backend_addresses['state_getter'])
        require(role == 'backend', 'Backend state provider owner differs')
        state['backend_observation']['state_getter_calls'] += 1
        state['backend_observation']['state_return'] = state['spec']['backend_state']
        h.finish(0xbadc0ffe00000000 | state['spec']['backend_state'])

    def debug_provider(which):
        def execute(machine):
            role, at = caller(backend_addresses['debug_' + which])
            require(role == 'backend', 'Backend debug provider owner differs')
            field = 'platform_' + which + '_calls'
            state['backend_observation'][field] += 1
            value = int(state['spec']['debug_case'] == ('firsttrue' if which == 'first' else 'secondtrue'))
            h.finish(0x123456789abcde00 | value)
        return execute

    def fallback_provider(machine):
        role, at = caller(backend_addresses['fallback'])
        require(role == 'backend' and reg('RCX') == backend and reg('RDX') == 0,
                'Backend fallback provider arguments differ')
        step = state['backend_observation']
        step['action_calls'] += 1
        step['action_arguments_checked'] = True
        h.finish(0xfedcba98765432ab)

    for address, callback in ((int(service_meta['helper'], 16), publisher_helper),
            (backend_addresses['state_getter'], state_provider),
            (backend_addresses['debug_first'], debug_provider('first')),
            (backend_addresses['debug_second'], debug_provider('second')),
            (backend_addresses['fallback'], fallback_provider)):
        h.add_fixture(address, callback)

    codec = load('login-backend-wire-codec').install(h, context, wire, state,
                                                   allocate, release, caller, reg, number)
    parent_callbacks = dict(h.fixtures)
    for address in codec.fixtures:
        if address not in h.fixtures:
            h.add_fixture(address, codec.fixtures[address])
    names = {
        'prepare': {at: name for name, at in fixture.items()},
        'sdk': {**{at: name for name, at in fixture.items()},
                **{int(at, 16): name for name, at in sdk['fixtures'].items()}},
        'metadata': {int(at, 16): name for name, at in metadata['fixtures'].items()}}

    def fixture_writes(role, address):
        if role.startswith('wire.') or (role == 'backend' and address in codec.fixtures):
            return codec.fixture_writes(address, role)
        if address == copy_address:
            return [(reg('RCX'), reg('R8'))] if reg('R8') else []
        if role in ('sender', 'publisher', 'backend'):
            return []
        group = role.split('.')[0] if '.' in role else 'prepare'
        name = names[group].get(address)
        require(name is not None, 'Backend fixture caller-owner address differs')
        a, b, c = (reg(key) for key in ('RCX', 'RDX', 'R8'))
        heap = [(h.scratch + 0x50000, 0xb0000)]
        text = {'platform_text', 'ascii_string', 'wide_string', 'copy_string', 'resize',
                'nm_provider', 'format_number', 'format', 'append', 'idfv', 'nm_key', 'adid', 'mode_text'}
        if name in text:
            return [(a, 16)] + heap
        if name in ('main_string', 'value_text', 'device_key'):
            return [(b, 16)] + heap
        if name == 'assign_counted':
            return [(a, 16)] + heap
        if name in ('cache_resolve', 'optional_resolve'):
            return [(a + 0x110, 8)]
        if name in ('construct_info', 'destroy_info'):
            return [(a, 0x250)]
        if name == 'memset':
            return [(a, c)] if c else []
        if name == 'marketing':
            return [(a, 16), (b, 4)] + heap
        if name == 'unwrap_backend':
            return [(a, 8)]
        if name == 'insert':
            return [(a, 8), (b, 4)] + heap
        if name in ('shared_info', 'variant_text'):
            return [(a, 16)]
        if name == 'variant_number':
            return [(a, 16 if group == 'metadata' else 24)]
        if name in ('variant_reserve', 'event_object'):
            return [(a, 16)] + heap
        if name == 'variant_copy':
            return [(a, 24)]
        return []

    for address in tuple(h.fixtures):
        def guarded(machine, address=address):
            role, at = caller(address)
            require(reg('RSP') & 15 == 8, 'Backend fixture ABI alignment differs')
            callback, codec_owner = fixture_for_owner(address, role, parent_callbacks, codec.fixtures)
            if not codec_owner and address in (fixture['free'], fixture['copy_string'], fixture['wide_string'],
                    fixture['ascii_string'], fixture['format_number'],
                    int(sdk['fixtures']['main_store'], 16), int(sdk['fixtures']['cache_resolve'], 16)):
                require(bool(metadata_state.get('active')) == role.startswith('metadata.'),
                        'Backend shared fixture caller-owner differs')
            if address == fixture['free'] and not codec_owner:
                record = state['allocation_records'].get(reg('RCX'))
                require(record is not None and record['kind'] == 'utf16' and not record['retired'],
                        'Backend prepare/metadata free allocation kind differs')
            state.update(fixture_owner=role, fixture_callsite=at)
            h.uc.begin_fixture(fixture_writes(role, address))
            try:
                callback(machine)
            finally:
                h.uc.end_fixture()
                state.pop('fixture_owner', None)
                state.pop('fixture_callsite', None)
        h.fixtures[address] = guarded

    def seed_service(spec):
        state.update(spec=dict(spec), publisher_helper_calls=0, phase='publisher',
            publisher=dict(calls=0, published_singleton=False, vptrs=[], backend_zeroed_before_ambient=False,
                ambient_backend_bound=False, returned_service=False, guards=False, abi=False),
            backend_observation=dict(entry_calls=0, return_byte=None, state_getter_calls=0, state_return=None,
                action_calls=0, action_arguments_checked=None, arguments_checked=None,
                sequence_before=spec['sequence_seed'], sequence_after=None, id_getter_calls=0,
                request_id=None, platform_first_calls=0, platform_second_calls=0,
                diagnostic_selector_offset=None))
        state['check_packet'] = check_packet
        h.uc.mem_write(service - 16, b'\xa5' * 16 + bytes([0x55]) * 240 + b'\xa6' * 16)
        backend_data = bytearray([0x55] * context['backend_bytes'])
        struct.pack_into('<H', backend_data, 0x240, spec['sequence_seed'])
        struct.pack_into('<Q', backend_data, 0x248, contract.KEY_BITS)
        backend_data[0x2a5] = spec['backend_busy']
        backend_data[0x300] = spec['backend_mode']
        h.uc.mem_write(backend - 16, b'\xa5' * 16 + backend_data + b'\xa6' * 16)
        h.uc.mem_write(backend_globals['gate'], bytes([spec['global_disabled']]))
        h.uc.mem_write(diagnostic, struct.pack('<II', 1, 0))
        h.uc.mem_write(backend_globals['diagnostic_pointer'], struct.pack('<Q', diagnostic))
        h.uc.mem_write(sender['service_global'], bytes(8))
        h.uc.native_allow([(h.scratch + 0x30000, 0x8200), (service, 240), (sender['service_global'], 8)])
        h.begin_case()
        codec.spec = None
        abi_seed()
        returned = h.call(publisher_address, service, budget=10000)
        require(returned == service and state['publisher_helper_calls'] == 1,
                'Backend native publisher return/helper count differs')
        expected = publisher_expected(0x55, primary_table, secondary_table)
        require(bytes(h.uc.mem_read(service, 240)) == expected and number(sender['service_global']) == service,
                'Backend whole publisher fields differ')
        service_guards()
        abi_check()
        state['publisher'].update(returned_service=True, guards=True, abi=True,
            backend_zeroed_before_ambient=number(service + 16) == 0)
        require(state['publisher']['backend_zeroed_before_ambient'], 'Backend publisher did not initialize null backend')
        # Explicit ambient provider binding after the complete native publisher.
        h.uc.mem_write(service + 16, struct.pack('<Q', backend))
        state['publisher']['ambient_backend_bound'] = True
        state['service_snapshot'] = bytes(h.uc.mem_read(service - 16, 272))
        state['backend_snapshot'] = bytes(h.uc.mem_read(backend - 16, context['backend_bytes'] + 32))
        h.uc.protect([(service - 16, 272), (sender['service_global'], 8), (diagnostic, 8),
                      (backend_globals['gate'], 1), (backend_globals['diagnostic_pointer'], 8)])
        h.uc.protect([(backend - 16, 16), (backend, 0x240),
                      (backend + 0x242, context['backend_bytes'] - 0x242 + 16)])
        for item in context['source_inputs'].values():
            if 'bytes' in item:
                h.uc.protect([(int(item['address'], 16), len(bytes.fromhex(item['bytes'])))])
        codec.seed(spec, backend)

    import unicorn
    def observed(machine, at, size, unused):
        if at == publisher_address:
            require(state['phase'] == 'publisher' and reg('RCX') == service,
                    'Backend publisher setup entry differs')
            state['publisher']['calls'] += 1
        elif at == publisher_address + 0x1e:
            require(number(service) == int(service_meta['initial_table'], 16)
                    and number(sender['service_global']) == service, 'Backend initial publication differs')
            state['publisher']['published_singleton'] = True
            state['publisher']['vptrs'].append('initial_primary')
        elif at == publisher_address + 0x36:
            require(number(service) == primary_table, 'Backend primary vtable differs')
            state['publisher']['vptrs'].append('primary')
        elif at == publisher_address + 0x41:
            require(number(service + 8) == secondary_table, 'Backend secondary vtable differs')
            state['publisher']['vptrs'].append('secondary')
        elif at == sender['address']:
            require(number(reg('RSP')) == sender['callsite'] + 5 and not state['sent'],
                    'Backend sender source entry differs')
            a, b, c, d = [reg(key) for key in ('RCX', 'RDX', 'R8', 'R9')]
            require(a == session and c == 4 and number(b) == table,
                    'Backend sender receiver/id/packet table differs')
            require(d == number(int(prepare['send_argument_global'], 16))
                    and number(reg('RSP') + 0x28, 4) == 0, 'Backend sender capability/fifth argument differs')
            state.update(sent=True, packet=b, send_capability=d)
            state['packet_snapshot'] = packet_snapshot(b)
            state['strings'] = {hex(off): read_text(b + off) for off in STRINGS}
            state['integers'] = {hex(off): number(b + off, width) for off, width in
                ((0x50, 4), (0x98, 1), (0x99, 1), (0xb0, 4), (0xf8, 4),
                 (0x120, 4), (0x124, 1), (0x128, 8), (0x130, 1), (0x131, 1))}
            h.uc.protect([(b, 320)] + [(pointer, len(raw)) for pointer, raw in
                state['packet_snapshot'][1].values()])
            state['events'].append('sender_entry')
            state['handoff'].update(sender_calls=1, sender_arguments_checked=True, fifth_argument_checked=True)
        elif at == sender['callsite'] + 5:
            check_packet()
            state['handoff']['sender_returns'] += 1
            state['events'].append('sender_return')
        elif at == sender['service_getter']:
            require(number(reg('RSP')) == sender['address'] + 0xdd and number(sender['service_global']) == service,
                    'Backend native service getter caller/global differs')
            state['handoff']['service_getter_calls'] += 1
            state['handoff']['getter_global_checked'] = True
        elif at == sender['virtual_callsite']:
            require(reg('RAX') == service and reg('RCX') == service and reg('RDX') == state['packet']
                    and reg('R8') == primary_table and number(primary_table + 56) == service_thunk,
                    'Backend source virtual handoff edge differs')
            state['handoff']['source_virtual_calls'] += 1
            state['handoff']['service_calls'] += 1
            state['handoff'].update(service_same_packet=True, service_arguments_checked=True,
                service_arguments=dict(receiver='source_service', packet='same_prepared_packet'))
        elif at == service_thunk:
            require(reg('RCX') == service and reg('RDX') == state['packet']
                    and number(reg('RSP')) == sender['virtual_callsite'] + 4, 'Backend source thunk ABI differs')
            check_packet()
            state['handoff']['thunk_calls'] += 1
            state['handoff'].update(thunk_arguments_checked=True, thunk_same_packet=True)
        elif at == backend_address:
            require(reg('RCX') == backend and reg('RDX') == state['packet']
                    and number(reg('RSP')) == sender['virtual_callsite'] + 4, 'Backend source tail entry differs')
            check_packet()
            state['backend_entry_stack'] = reg('RSP')
            require(state.get('backend_return_address') is None, 'Backend source return is already pending')
            state['backend_return_address'] = number(reg('RSP'))
            state['backend_observation']['entry_calls'] += 1
            state['backend_observation']['arguments_checked'] = True
            state['backend_observation']['sequence_before'] = number(backend + 0x240, 2)
            require(state['backend_observation']['sequence_before'] == state['spec']['sequence_seed'],
                    'Backend sequence changed before native backend entry')
            state['events'].append('backend_entry')
        elif at == state.get('backend_return_address'):
            require(state['backend_observation']['entry_calls'] == 1, 'Backend return without entry')
            state['backend_observation']['return_byte'] = reg('RAX') & 255
            state.pop('backend_return_address')
            state['events'].append('backend_return')
            check_packet()
        elif at == sender['address'] + 0x47:
            base = reg('R9')
            require(base in (session + 0x70, buckets), 'Backend pending bucket base differs')
            state['handoff']['bucket_storage'] = 'inline' if base == session + 0x70 else 'heap'
        elif at == sender['address'] + 0x66:
            require(reg('RCX') == nodes and reg('RAX') in (0, 32), 'Backend pending node traversal differs')
            state['handoff']['observed_lookup_keys'].append(number(reg('RCX') + reg('RAX'), 2))
        elif at == backend_addresses['packet_id_getter']:
            role, callsite, target = returns.get(number(reg('RSP')), (None, None, None))
            require(reg('RCX') == state['packet'] and role == 'backend'
                    and callsite in (backend_address + 0x7a, backend_address + 0x83),
                    'Backend packet ID getter receiver/caller differs')
            require(state.get('id_getter_return') is None, 'Backend packet ID getter return is already pending')
            state['id_getter_return'] = number(reg('RSP'))
            state['backend_observation']['id_getter_calls'] += 1
        elif at == state.get('id_getter_return'):
            require(reg('RAX') == 3, 'Backend native packet ID getter return differs')
            state['backend_observation']['request_id'] = reg('RAX')
            state.pop('id_getter_return')
        elif at == backend_address + 0x6e:
            require(reg('RBX') == diagnostic and reg('RAX') in (0, 4), 'Backend diagnostic provider index differs')
            state['backend_observation']['diagnostic_selector_offset'] = reg('RAX')
        codec.observed(at)
    h.uc.hook_add(unicorn.UC_HOOK_CODE, observed)

    def memory_read(machine, access, at, size, value, unused):
        h.uc.readable(at, size)

    def memory_write(machine, access, at, size, value, unused):
        h.uc.writable(at, size, native=True)
    h.uc.hook_add(unicorn.UC_HOOK_MEM_READ, memory_read)
    h.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, memory_write)

    def check_sender(spec):
        step = state['handoff']
        settings = parent_contract.pending_settings(spec['pending_case'])
        count = int(settings['forwarded'])
        require((step['sender_calls'], step['sender_returns']) == (1, 1), 'Backend native sender count differs')
        require(all(step[key] == count for key in ('pending_insert_calls', 'delegate_calls',
                'service_getter_calls', 'service_calls', 'source_virtual_calls', 'thunk_calls')),
                'Backend sender branch calls differ')
        require(step['observed_lookup_keys'] == settings['lookup_keys']
                and step['bucket_storage'] == settings['bucket_storage'], 'Backend pending source branch differs')
        require(state['events'].index('sender_return') < state['events'].index('post_notify')
                < state['events'].index('destructor'), 'Backend source handoff cleanup order differs')
        require(all(bytes(h.uc.mem_read(at, len(value))) == value for at, value in state['sender_inputs']),
                'Backend sender fixture input changed')
        return dict(step)

    def check_publisher():
        service_guards()
        require(bytes(h.uc.mem_read(service - 16, 272)) == state['service_snapshot'],
                'Backend published service changed during delivery')
        require(state['publisher']['calls'] == 1 and state['publisher']['vptrs'] ==
                ['initial_primary', 'primary', 'secondary'], 'Backend native publisher lifecycle differs')
        return dict(state['publisher'])

    def check_backend(spec):
        step = state['backend_observation']
        require(state.get('id_getter_return') is None, 'Backend packet ID getter did not return')
        require(state.get('backend_return_address') is None, 'Backend source call did not return')
        step['sequence_after'] = number(backend + 0x240, 2)
        expected_object = bytearray(state['backend_snapshot'])
        struct.pack_into('<H', expected_object, 16 + 0x240, step['sequence_after'])
        require(bytes(h.uc.mem_read(backend - 16, len(expected_object))) == bytes(expected_object),
                'Backend ambient object changed outside sequence field')
        return dict(step)

    def check_ownership(input_pointers):
        for pointer in state['allocations']:
            ledger.check_canary(pointer)
        packet_pointers = {pointer for pointer, data in state['packet_snapshot'][1].values()}
        require(packet_pointers <= state['freed'], 'Backend prepared packet strings not released')
        require(not input_pointers & state['freed'] and not state.get('sdk_retained', set()) & state['freed'],
                'Backend provider input or retained SDK allocation freed')
        require(set(state['allocations']) - input_pointers - state.get('sdk_retained', set()) == state['freed'],
                'Backend shared heap lifecycle differs')
        return dict(inputs_unchanged=True, retained_sdk_live=True, preparation_temporaries_released=True,
                    packet_strings_released=True, guards=True, abi=True)

    abi = {name: 0xfedcba9876543210 + i for i, name in enumerate(('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}
    abi.update({'XMM'+str(i):0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})

    def run(spec):
        scenario = next(row for row in SCENARIOS if row[0] == spec['scenario'])
        name, platform, enabled, present, mask, mode = scenario
        selector, empty, poison = spec['selector'], spec['empty'], spec['poison']
        cache_case, metadata_case = spec['cache_case'], spec['metadata_case']
        h.uc.reset()
        state.clear()
        state.update(heap=h.scratch + 0x50000, allocations={}, allocation_records={}, allocation_owners={}, freed=set(), events=[], sent=False, phase='inputs',
            platform=platform, manager_present=present, mode=mode, selector=selector,
            nm='' if empty else 'nm-Ж🙂', main='' if empty else 'main-界', aux='' if empty else 'aux-🙂',
            number=0 if empty else 0xfedcba98, flag=0 if empty else 0x80, extra_flag=0 if empty else 0xff,
            format_literal=format_literal, event_literal=event_literal)
        h.uc.mem_write(h.scratch + 0x30000, bytes([poison]) * 0x8000)
        h.uc.mem_write(manager, b'\x77' * 0x80)
        for bit, offset, handle in zip((1, 2, 4), (0x38, 0x48, 0x68), handles):
            h.uc.mem_write(manager + offset, struct.pack('<Q', handle if mask & bit else 0))
        h.uc.mem_write(language, b'\x66' * 0x20)
        h.uc.mem_write(language + 0x18, bytes([0 if empty else 0xf3]))
        owner_bytes = bytearray([poison] * 0x180)
        h.uc.mem_write(owner - 16, b'\xa5' * 16 + owner_bytes + b'\xa6' * 16)
        for off, text in ((0xe0, 'owner-e0'), (0xf0, 'owner-f0'), (0x100, 'owner-100')):
            write_text(owner + off, '' if empty else text + '-🙂')
        write_text(globals_['text'], '' if empty else 'global-Ж')
        write_text(sdk_value, '' if empty else 'sdk-value-界')
        h.uc.mem_write(globals_['enabled'], bytes([int(enabled)]))
        h.uc.mem_write(globals_['enum'], struct.pack('<I', 0 if empty else 0xffffffff))
        h.uc.mem_write(globals_['number'], struct.pack('<I', 0 if empty else 0x89abcdef))
        if sdk:
            seed_sdk(cache_case, empty)
        if metadata:
            backend_case, pattern, marketing = metadata_case
            seed_metadata(backend_case, pattern, present and bool(mask & 1), marketing, poison)
        seed_sender(spec)
        seed_service(spec)
        input_pointers = set(state['allocations'])
        inputs = {at: bytes(h.uc.mem_read(at, size)) for at, size in
                  ((owner - 16, 0x1a0), (manager, 0x80), (language, 0x20), (sdk_value, 16), (globals_['text'], 16))}
        input_buffers = {at: bytes(h.uc.mem_read(at - 16, size + 32)) for at, size in state['allocations'].items()}
        for register, value in abi.items():
            h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + register), value)
        h.uc.protect([(at - 16, size + 32) for at, size in state['allocations'].items()])
        h.uc.protect([(at, len(value)) for at, value in inputs.items()])
        h.uc.protect([(at, len(value)) for at, value in state['sdk_guards'].items()])
        h.uc.protect([(at, len(value)) for at, value in metadata_state['seed']['guards'].items()])
        h.uc.native_allow([(h.scratch + 0x30000, 0x8200), (h.scratch + 0x50000, 0xb0000),
            (handles[0] + 0x58, 16), (h.scratch + 0xb000, 16), (backend + 0x240, 2)])
        state['phase'] = 'delivery'
        h.call(int(prepare['prepare'], 16), owner, budget=3000000)
        if sdk:
            check_sdk()
        main = enabled and present and bool(mask & 1)
        aux = enabled and present and bool(mask & 2)
        extra = enabled and present and bool(mask & 4)
        if metadata:
            require(metadata_state['native_calls'].get('collector', 0) == int(aux),
                    'Login metadata collector call count differs')
            state['aux'] = check_metadata() if aux else ''
        expected = {hex(off): '' for off in STRINGS}
        expected.update({'0x10': '' if empty else 'owner-f0-🙂', '0x20': '' if empty else 'owner-e0-🙂',
            '0x30': state['main'] if main else '', '0x40': '' if empty else 'global-Ж', '0x78': state['nm'],
            '0x88': '' if empty else 'owner-100-🙂',
            '0xa0': (state['sdk_value_expected'] if sdk else read_text(sdk_value)) if main else '',
            '0xd8': state['aux'] if aux else '', '0x110': compiled_tag})
        os_code = 0 if platform == 'Android' else 1 if platform == 'IOS' else 6 if platform == 'Windows' and main and mode == 1 else 3
        integers = {'0x50': 0 if empty else 0x89abcdef, '0x98': {1: 1, 2: 2, 3: 3, 4: 5}.get(selector, 0),
            '0x99': os_code, '0xb0': state['number'], '0xf8': 207, '0x120': 0 if empty else 0xffffffff,
            '0x124': 0 if empty else 0xf3, '0x128': 0, '0x130': state['flag'] if enabled else 0,
            '0x131': state['extra_flag'] if extra else 0}
        require(state['sent'] and state['strings'] == expected and state['integers'] == integers,
                'Login prepared fields differ: ' + name + ' ' + repr(state.get('integers')))
        events = state['events']
        require(state.get('destroyed') and events.count('sender_entry') == 1 and events.count('post_notify') == 1
                and events.count('sdk_event') == int(main) and events.count('owner_number') == 2 + int(main),
                'Login post-send lifecycle differs')
        require(events.index('sender_entry') < events.index('post_notify') < events.index('destructor'), 'Login cleanup order differs')
        if main:
            require(events.index('post_notify') < events.index('sdk_event') < events.index('destructor'), 'Login SDK event order differs')
        require(events.count('sdk_mode') == int(platform == 'Windows' and main), 'Login SDK mode branch differs')
        require(events.count('sdk_aux_text') == int(aux) and events.count('sdk_main_text') == int(main)
                and events.count('sdk_value') == int(main) and events.count('sdk_flag') == int(enabled)
                and events.count('sdk_extra_flag') == int(extra), 'Login SDK projection branches differ')
        require(set(state['allocations']) - input_pointers - state.get('sdk_retained', set()) == state['freed'],
                'Login preparation leak or input free')
        require(all(bytes(h.uc.mem_read(at, len(data))) == data for at, data in inputs.items())
                and all(bytes(h.uc.mem_read(at - 16, len(data))) == data for at, data in input_buffers.items()), 'Login input changed')
        require(all(reg(k) == v for k, v in abi.items()) and reg('RSP') == h.return_stack, 'Login prepare ABI differs')
        row = dict(spec, strings=state['strings'], integers=state['integers'], guards=True,
            sdk_event=main, lifecycle=['sender_entry', 'post_notify'] + (['sdk_event'] if main else []) + ['destructor'])
        if sdk:
            row.update(cache_case=cache_case, native_calls=dict(state['sdk_native_calls']))
        if metadata:
            row.update(metadata_case=list(metadata_case), metadata_calls=dict(metadata_state['native_calls']))
        row.update(handoff=check_sender(spec), publisher=check_publisher(), backend=check_backend(spec),
            wire=codec.check(spec), ownership=check_ownership(input_pointers))
        return row

    return run
