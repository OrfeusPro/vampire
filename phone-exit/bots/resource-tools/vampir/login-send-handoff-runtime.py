"""Bounded Login preparation and native sender handoff fixture environment."""
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


def install(h, prepare, context, contract):
    sdk, metadata = prepare['native_sdk'], prepare['native_metadata']
    table = int(prepare['packet_table'], 16)
    fixture = {k: int(v, 16) for k, v in prepare['fixtures'].items()}
    globals_ = {k: int(v, 16) for k, v in prepare['globals'].items()}
    owner, manager, language, session, receiver, flags, sdk_value = [h.scratch + n for n in
        (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000)]
    handles = (h.scratch + 0x8000, h.scratch + 0x8100, h.scratch + 0x8200)
    state = {}

    def reg(name):
        return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def allocate(size):
        if not 1 <= size <= (8192 if metadata else 2048) or state['heap'] + size + 64 > h.scratch + 0x30000:
            raise ValueError('Login allocation bound')
        at = state['heap'] + 16
        state['heap'] += (size + 63) & ~15
        h.uc.mem_write(at - 16, b'\xa5' * 16 + b'\x5a' * size + b'\xa6' * 16)
        state['allocations'][at] = size
        state['allocation_owners'][at] = state.get('fixture_owner', 'input')
        return at

    def release(at):
        if at not in state['allocations'] or at in state['freed']:
            raise ValueError('Login unowned or repeated free')
        size = state['allocations'][at]
        if bytes(h.uc.mem_read(at - 16, 16)) != b'\xa5' * 16 or bytes(h.uc.mem_read(at + size, 16)) != b'\xa6' * 16:
            raise ValueError('Login allocation canary changed')
        state['freed'].add(at)
        h.uc.retire(at, size)

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
    nodes, buckets, service, service_table, sink = [h.scratch + at for at in
        (0xd000, 0xd100, 0xc000, 0xc100, 0xe100)]
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
        settings = contract.pending_settings(spec['pending_case'])
        state.update(handoff=dict(pending_case=spec['pending_case'], forwarded=settings['forwarded'],
            configured_timeout_bits=settings['timeout_bits'], entry_timeout_bits=0, selected_timeout_bits=None,
            sender_calls=0, sender_returns=0, pending_insert_calls=0, delegate_calls=0,
            service_getter_calls=0, sink_calls=0, source_virtual_calls=0, sink_same_packet=None,
            packet_immutable=True, strings_immutable=True, synthetic_service_vtable=True,
            sender_arguments_checked=False, fifth_argument_checked=False,
            pending_insert_arguments_checked=None, delegate_arguments_checked=None,
            getter_global_checked=None, sink_arguments=None, sink_arguments_checked=None,
            observed_lookup_keys=[], bucket_storage='not-read'))
        body, node_data, bucket_data = pending_layout(spec['pending_case'], nodes, buckets, settings['timeout_bits'])
        h.uc.mem_write(session - 16, b'\xa5' * 16 + body + b'\xa6' * 16)
        h.uc.mem_write(nodes - 16, b'\xa5' * 16 + node_data + b'\xa6' * 16)
        h.uc.mem_write(buckets - 16, b'\xa5' * 16 + bucket_data + b'\xa6' * 16)
        h.uc.mem_write(service, struct.pack('<Q', service_table))
        h.uc.mem_write(service_table, bytes(56) + struct.pack('<Q', sink))
        h.uc.mem_write(sender['service_global'], struct.pack('<Q', service))
        state['sender_inputs'] = [(at, bytes(h.uc.mem_read(at, size))) for at, size in
            ((session - 16, 192), (nodes - 16, 96), (buckets - 16, 48),
             (service, 8), (service_table, 64), (sender['service_global'], 8))]
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

    def service_sink(machine):
        role, at = caller(sink)
        require(role == 'sender' and at == sender['virtual_callsite'] and
                reg('RCX') == service and reg('RDX') == state['packet'],
                'Login synthetic service sink arguments differ')
        check_packet()
        step = state['handoff']
        step['sink_calls'] += 1
        step['sink_same_packet'] = True
        step['sink_arguments_checked'] = True
        step['sink_arguments'] = dict(receiver='synthetic_service', packet='same_prepared_packet')
        h.finish(0)

    h.add_fixture(sender['pending_insert'], pending_insert)
    h.add_fixture(sender['delegate_add'], delegate_add)
    h.add_fixture(sink, service_sink)

    copy_address = int(context['helpers']['memcpy'], 16)
    def copy_fixture(machine):
        a, b, size = (reg(key) for key in ('RCX', 'RDX', 'R8'))
        require(0 <= size <= 4096 and all(h.scratch <= pointer <= h.scratch + 0x200000 - size
                for pointer in (a, b)), 'Login handoff memcpy bound differs')
        if size:
            h.uc.mem_write(a, bytes(h.uc.mem_read(b, size)))
        h.finish(a)
    h.add_fixture(copy_address, copy_fixture)

    # A shared address is dispatched only after validating its concrete source
    # caller. The frozen metadata bridge remains active solely for metadata roots.
    callbacks = dict(h.fixtures)
    names = {
        'prepare': {at: name for name, at in fixture.items()},
        'sdk': {**{at: name for name, at in fixture.items()},
                **{int(at, 16): name for name, at in sdk['fixtures'].items()}},
        'metadata': {int(at, 16): name for name, at in metadata['fixtures'].items()}}

    def fixture_writes(role, address):
        if address == copy_address:
            return [(reg('RCX'), reg('R8'))] if reg('R8') else []
        if role == 'sender':
            return []
        group = role.split('.')[0] if '.' in role else 'prepare'
        name = names[group].get(address)
        require(name is not None, 'Login fixture caller-owner address differs')
        a, b, c = (reg(key) for key in ('RCX', 'RDX', 'R8'))
        heap = [(h.scratch + 0x10000, 0x20000)]
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
        if name in ('unwrap_backend',):
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

    for address, callback in callbacks.items():
        def guarded(machine, address=address, callback=callback):
            role, at = caller(address)
            require(reg('RSP') & 15 == 8, 'Login fixture ABI alignment differs')
            if address in (fixture['free'], fixture['copy_string'], fixture['wide_string'],
                           fixture['ascii_string'], fixture['format_number'],
                           int(sdk['fixtures']['main_store'], 16), int(sdk['fixtures']['cache_resolve'], 16)):
                require(bool(metadata_state.get('active')) == role.startswith('metadata.'),
                        'Login shared fixture caller-owner differs')
            if address == fixture['free']:
                pointer = reg('RCX')
                require(pointer in state['allocation_owners'] and pointer not in state['freed'],
                        'Login free lacks live allocation owner')
            state['fixture_owner'] = role
            h.uc.begin_fixture(fixture_writes(role, address))
            try:
                callback(machine)
            finally:
                h.uc.end_fixture()
                state.pop('fixture_owner', None)
        h.fixtures[address] = guarded

    import unicorn
    def observed(machine, at, size, unused):
        if at == sender['address']:
            require(number(reg('RSP')) == sender['callsite'] + 5 and not state['sent'],
                    'Login sender source entry differs')
            a, b, c, d = [reg(key) for key in ('RCX', 'RDX', 'R8', 'R9')]
            require(a == session and c == 4 and number(b) == table,
                    'Login sender receiver/id/packet table differs')
            require(d == number(int(prepare['send_argument_global'], 16)) and
                    number(reg('RSP') + 0x28, 4) == 0, 'Login sender capability/fifth argument differs')
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
                    'Login native service getter caller/global differs')
            state['handoff']['service_getter_calls'] += 1
            state['handoff']['getter_global_checked'] = True
        elif at == sender['virtual_callsite']:
            require(reg('RAX') == service and reg('RCX') == service and reg('RDX') == state['packet']
                    and reg('R8') == service_table and number(service_table + 56) == sink,
                    'Login source virtual handoff edge differs')
            state['handoff']['source_virtual_calls'] += 1
        elif at == sender['address'] + 0x47:
            base = reg('R9')
            require(base in (session + 0x70, buckets), 'Login pending bucket base differs')
            state['handoff']['bucket_storage'] = 'inline' if base == session + 0x70 else 'heap'
        elif at == sender['address'] + 0x66:
            require(reg('RCX') == nodes and reg('RAX') in (0, 32), 'Login pending node traversal differs')
            state['handoff']['observed_lookup_keys'].append(number(reg('RCX') + reg('RAX'), 2))
    h.uc.hook_add(unicorn.UC_HOOK_CODE, observed)

    def memory_read(machine, access, at, size, value, unused):
        h.uc.readable(at, size)

    def memory_write(machine, access, at, size, value, unused):
        h.uc.writable(at, size, native=True)
    h.uc.hook_add(unicorn.UC_HOOK_MEM_READ, memory_read)
    h.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, memory_write)

    def check_sender(spec):
        step = state['handoff']
        settings = contract.pending_settings(spec['pending_case'])
        count = int(settings['forwarded'])
        require((step['sender_calls'], step['sender_returns']) == (1, 1), 'Login native sender count differs')
        require(all(step[key] == count for key in ('pending_insert_calls', 'delegate_calls',
                'service_getter_calls', 'sink_calls', 'source_virtual_calls')), 'Login sender branch calls differ')
        require(step['observed_lookup_keys'] == settings['lookup_keys']
                and step['bucket_storage'] == settings['bucket_storage'], 'Login pending source branch differs')
        require(state['events'].index('sender_return') < state['events'].index('post_notify')
                < state['events'].index('destructor'), 'Login source handoff cleanup order differs')
        require(all(bytes(h.uc.mem_read(at, len(value))) == value for at, value in state['sender_inputs']),
                'Login sender fixture input changed')
        return dict(step)
    abi = {name: 0xfedcba9876543210 + i for i, name in enumerate(('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}
    abi.update({'XMM'+str(i):0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})

    def run(spec):
        scenario = next(row for row in SCENARIOS if row[0] == spec['scenario'])
        name, platform, enabled, present, mask, mode = scenario
        selector, empty, poison = spec['selector'], spec['empty'], spec['poison']
        cache_case, metadata_case = spec['cache_case'], spec['metadata_case']
        h.uc.reset()
        state.clear()
        state.update(heap=h.scratch + 0x10000, allocations={}, allocation_owners={}, freed=set(), events=[], sent=False,
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
        h.uc.native_allow([(h.scratch + 0x30000, 0x8200), (h.scratch + 0x10000, 0x20000),
            (handles[0] + 0x58, 16), (h.scratch + 0xb000, 16)])
        h.call(int(prepare['prepare'], 16), owner, budget=100000)
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
        row = dict(scenario=name, selector=selector, empty=empty, poison=poison,
                          strings=state['strings'], integers=state['integers'], guards=True,
                          sdk_event=main, lifecycle=['sender_entry', 'post_notify'] + (['sdk_event'] if main else []) + ['destructor'])
        if sdk:
            row.update(cache_case=cache_case, native_calls=dict(state['sdk_native_calls']))
        if metadata:
            row.update(metadata_case=list(metadata_case), metadata_calls=dict(metadata_state['native_calls']))
        row.update(pending_case=spec['pending_case'], handoff=check_sender(spec))
        return row

    return run
