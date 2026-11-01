"""Observe native Login archives, CRC and XOR; bounded storage and transport fixtures.

The coordinator never calls a writer or fills an archive with expected bytes.
All payload observations below are copied from the native-produced buffers.
"""
import struct


OPAQUE_TRANSPORT_RAX = 0xfedcba9876543200


def require(ok, message):
    if not ok:
        raise ValueError(message)


def blank_observation():
    result = {name: 0 for name in ('writer_calls', 'request_id_calls',
        'archive_constructor_calls', 'archive_cleanup_calls', 'initial_growth_calls',
        'checksum_calls', 'transform_calls', 'transport_calls', 'append_calls', 'checksum_init_calls')}
    result.update({name: None for name in ('writer_prefix_hex', 'writer_delta_hex',
        'inner_hex', 'plaintext_frame_hex', 'frame_hex', 'transport_hex', 'checksum_input_hex',
        'writer_entry_count', 'writer_return_count', 'inner_bytes', 'frame_bytes',
        'checksum_value', 'transform_offset', 'transform_size', 'transform_key_bits',
        'transport_return_al', 'request_id', 'archive_flags_bits', 'same_packet', 'writer_source_edge',
        'packet_immutable', 'strings_immutable', 'prefix_immutable', 'transform_in_place',
        'transform_identity', 'transport_before_cleanup', 'checksum_initial_state',
        'checksum_final_state', 'transform_return_value', 'transform_effective_key_bits')})
    result.update(initial_growth_sizes=[], cleanup_order=[], guards=True,
        wire_temporaries_released=True, archive_buffers_released=True, ownership_checked=True)
    return result


class Codec:
    def __init__(self, h, context, wire, state, allocate, release, caller, reg, number):
        self.h, self.c, self.wire, self.state = h, context, wire, state
        self.allocate, self.release, self.caller = allocate, release, caller
        self.reg, self.number = reg, number
        self.functions = {key: int(at, 16) for key, at in context['functions'].items()}
        self.backend = {key: int(at, 16) for key, at in context['backend'].items()
                        if key != 'globals'}
        self.archive = {key: int(at, 16) for key, at in wire['archive'].items()}
        self.fixture_addresses = {key: int(at, 16) for key, at in wire['fixtures'].items()
                                  if key != 'archive_slot'}
        self.fixture_addresses.update({name: self.backend[name]
            for name in ('transport',)})
        self.fixture_addresses['growth'] = self.archive['growth']
        self.fixture_addresses['memcpy'] = int(context['helpers']['memcpy'], 16)
        callbacks = dict(utf8_allocate=self.utf8_allocate, cpp_allocate=self.cpp_allocate,
            utf8_free=self.utf8_free, cpp_free=self.cpp_free, security_check=self.security,
            growth=self.growth, transport=self.transport, memcpy=self.memcpy)
        self.fixtures = {self.fixture_addresses[name]: callback for name, callback in callbacks.items()}
        require(len(self.fixtures) == len(callbacks), 'Backend codec fixture addresses alias')
        self.return_sites = {}
        for role in ('backend', 'wire.append'):
            for at, target in context['call_sites'][role].items():
                if target.startswith('0x'):
                    # Whole source contract pins these direct CALL instructions as E8.
                    self.return_sites[int(at, 16) + 5] = (role, int(target, 16))
        self.spec, self.backend_object = None, None

    def seed(self, spec, backend):
        self.spec, self.backend_object = spec, backend
        self.result = blank_observation()
        self.archives, self.created, self.pending_returns = {}, set(), {}
        self.backend_stack, self.checksum_state = None, None
        self.writer_prefix, self.append_prefix, self.before_transform = None, None, None
        self.transport_seen, self.backend_returned = False, False
        self.active_cleanup = None
        self.transform_home, self.transformed_frame = None, None

    def source_caller(self, address, roles):
        role, at = self.caller(address)
        require(role in roles, 'Backend codec fixture source caller differs')
        return role, at

    def heap_write_window(self):
        return [(self.h.scratch + 0x50000, 0xb0000)]

    def fixture_writes(self, address, role):
        if address == self.fixture_addresses['memcpy']:
            return [(self.reg('RCX'), self.reg('R8'))] if self.reg('R8') else []
        if address == self.fixture_addresses['growth']:
            return [(self.reg('RCX'), 24)] + self.heap_write_window()
        if address == self.fixture_addresses['utf8_allocate']:
            return [(self.reg('RCX'), 8)] + self.heap_write_window()
        if address == self.fixture_addresses['cpp_allocate']:
            return self.heap_write_window()
        return []

    def memcpy(self, machine):
        self.source_caller(self.fixture_addresses['memcpy'], {'wire.archive.raw', 'wire.string-writer'})
        destination, source, size = self.reg('RCX'), self.reg('RDX'), self.reg('R8')
        require(0 <= size <= 4096 and all(self.h.scratch <= at <= self.h.scratch + 0x200000 - size
                for at in (destination, source)), 'Backend wire memcpy extent differs')
        if size:
            self.h.uc.mem_write(destination, bytes(self.h.uc.mem_read(source, size)))
        self.h.finish(destination)

    def new_allocation(self, size, kind, owner):
        pointer = self.allocate(size, kind=kind, owner=owner)
        require(pointer not in self.created, 'Backend codec reused allocation address')
        self.created.add(pointer)
        return pointer

    def owned(self, pointer, kind=None, size=None):
        record = self.state['allocation_records'].get(pointer)
        require(record is not None and pointer not in self.state['freed'],
                'Backend codec buffer is not live and owned')
        require(kind is None or record['kind'] == kind, 'Backend codec allocation kind differs')
        require(size is None or record['size'] == size, 'Backend codec allocation extent differs')
        return record

    def archive_name(self, address):
        matches = [name for name, item in self.archives.items() if item['object'] == address]
        require(len(matches) == 1, 'Backend archive receiver differs')
        return matches[0]

    def contents(self, name):
        item = self.archives[name]
        at = item['object']
        pointer, end, limit = struct.unpack('<QQQ', self.h.uc.mem_read(at + 0x18, 24))
        capacity, cursor, count = struct.unpack('<III', self.h.uc.mem_read(at + 0x30, 12))
        require(cursor == count and 0 <= count <= capacity <= 1024,
                'Backend native archive counters differ')
        if not capacity:
            require(pointer == end == limit == count == 0, 'Backend empty archive storage differs')
            return b''
        self.owned(pointer, 'archive', capacity)
        require(end == limit == pointer + capacity,
                'Backend archive vector descriptor differs')
        require(item.get('buffer') == pointer, 'Backend archive ownership differs')
        return bytes(self.h.uc.mem_read(pointer, count))

    def growth(self, machine):
        self.source_caller(self.fixture_addresses['growth'], {'wire.archive.raw'})
        at, capacity = self.reg('RCX') - 0x18, self.reg('RDX')
        name = self.archive_name(at)
        require(capacity == 1024 and 'buffer' not in self.archives[name],
                'Backend storage fixture permits one initial 1024-byte growth only')
        require(bytes(self.h.uc.mem_read(at + 0x18, 24)) == bytes(24)
                and self.number(at + 0x30, 4) == capacity
                and self.number(at + 0x34, 4) == self.number(at + 0x38, 4) == 0,
                'Backend initial growth old descriptor/counters differ')
        pointer = self.new_allocation(capacity, 'archive', 'wire.' + name)
        self.h.uc.mem_write(at + 0x18, struct.pack('<QQQ', pointer, pointer + capacity, pointer + capacity))
        self.archives[name]['buffer'] = pointer
        self.result['initial_growth_calls'] += 1
        self.result['initial_growth_sizes'].append(capacity)
        self.h.finish(0)

    def utf8_allocate(self, machine):
        self.source_caller(self.fixture_addresses['utf8_allocate'], {'wire.string-writer'})
        size = self.reg('R8')
        require(self.reg('RDX') == 0 and self.reg('R9') == 1 and 1 <= size <= 8192,
                'Backend UTF8 allocation arguments differ')
        require(self.number(self.reg('RCX')) == 0, 'Backend UTF8 storage was already allocated')
        pointer = self.new_allocation(size, 'utf8', 'wire.string-writer')
        self.h.uc.mem_write(self.reg('RCX'), struct.pack('<Q', pointer))
        self.h.finish(0)

    def cpp_allocate(self, machine):
        self.source_caller(self.fixture_addresses['cpp_allocate'], {'wire.string-writer'})
        size = self.reg('RCX')
        require(1 <= size < 4096, 'Backend aligned/OOM C++ allocation is outside fixture')
        self.h.finish(self.new_allocation(size, 'cpp', 'wire.string-writer'))

    def utf8_free(self, machine):
        self.source_caller(self.fixture_addresses['utf8_free'], {'wire.string-writer'})
        pointer = self.reg('RCX')
        require(pointer in self.created, 'Backend UTF8 free does not belong to this codec invocation')
        self.owned(pointer, 'utf8')
        self.release(pointer, expected_kind='utf8')
        self.h.finish(0)

    def cpp_free(self, machine):
        role, _ = self.source_caller(self.fixture_addresses['cpp_free'], {'wire.string-writer', 'wire.cleanup'})
        pointer, size = self.reg('RCX'), self.reg('RDX')
        kind = 'archive' if role == 'wire.cleanup' else 'cpp'
        require(pointer in self.created, 'Backend sized free does not belong to this codec invocation')
        if kind == 'archive':
            require(self.active_cleanup in self.archives
                    and self.archives[self.active_cleanup].get('buffer') == pointer,
                    'Backend sized free does not own the active cleanup archive')
        require(1 <= size < 4096, 'Backend aligned archive delete is outside fixture')
        self.owned(pointer, kind, size)
        self.release(pointer, expected_kind=kind, expected_size=size)
        self.h.finish(0)

    def security(self, machine):
        self.source_caller(self.fixture_addresses['security_check'], {'wire.string-writer'})
        cookie = int(self.wire['writer_metadata']['cookie'], 16)
        off = self.h.image.offset(cookie - self.h.image.pe.base)
        require(self.reg('RCX') == int.from_bytes(self.h.raw[off:off + 8], 'little'),
                'Backend wire security cookie differs')
        self.h.finish(self.reg('RAX'))

    def native_integrity_entry(self, address):
        """Observe source calls only; never replace CRC/XOR or call them here."""
        if address not in {self.backend[k] for k in ('checksum_init', 'checksum', 'transform')}:
            return
        self.source_caller(address, {'backend'})
        ret = self.number(self.reg('RSP'))
        require(ret not in self.pending_returns, 'Integrity native return already pending')
        if address == self.backend['checksum_init']:
            require(self.reg('RCX') == self.checksum_state, 'Integrity initializer state alias differs')
            self.result['checksum_init_calls'] += 1
            self.pending_returns[ret] = ('native-crc-init', None)
        elif address == self.backend['checksum']:
            inner = self.contents('inner')
            require(self.reg('RCX') == self.checksum_state
                    and self.reg('RDX') == self.archives['inner']['buffer']
                    and self.reg('R8') == len(inner), 'Integrity CRC native source arguments differ')
            require(self.result['checksum_initial_state'] == 0xffffffff,
                    'Integrity CRC ran without the source initializer')
            self.result['checksum_calls'] += 1
            self.result['checksum_input_hex'] = inner.hex()
            self.pending_returns[ret] = ('native-crc-update', None)
        else:
            frame = self.contents('outer')
            pointer = self.archives['outer']['buffer']
            require(self.reg('RCX') == self.reg('R8') == pointer + 3
                    and self.reg('RDX') == len(frame) - 3
                    and self.reg('R9') == self.number(self.backend_object + 0x248) == self.spec['key_bits'],
                    'Integrity native transform alias/range/key differs')
            self.before_transform = frame
            self.transform_home = self.reg('RSP') + 0x20
            self.result.update(transform_calls=self.result['transform_calls'] + 1,
                plaintext_frame_hex=frame.hex(), transform_offset=3, transform_size=len(frame) - 3,
                transform_key_bits=self.reg('R9'), transform_in_place=True, transform_identity=False)
            capacity = self.state['allocation_records'][pointer]['size']
            self.h.uc.protect([(pointer, 3)])
            if capacity > len(frame):
                self.h.uc.protect([(pointer + len(frame), capacity - len(frame))])
            self.pending_returns[ret] = ('native-transform', None)

    def transport(self, machine):
        self.source_caller(self.backend['transport'], {'backend'})
        frame = self.contents('outer')
        pointer = self.archives['outer']['buffer']
        require(self.reg('RCX') == self.backend_object and self.reg('RDX') == pointer
                and self.reg('R8') == len(frame), 'Backend transport source arguments differ')
        require(self.transformed_frame == frame and not self.result['cleanup_order'],
                'Integrity transport changed after native transform or cleanup')
        self.transport_seen = True
        self.result.update(frame_hex=frame.hex(), transport_hex=bytes(frame).hex(), frame_bytes=len(frame),
            transport_calls=self.result['transport_calls'] + 1, transport_before_cleanup=True,
            transport_return_al=self.spec['transport_result_byte'])
        self.state['events'].append('transport_capture')
        self.h.uc.protect([(pointer, self.state['allocation_records'][pointer]['size'])])
        self.h.finish(OPAQUE_TRANSPORT_RAX | self.spec['transport_result_byte'])

    def observe_return(self, address):
        event = self.pending_returns.pop(address, None)
        if event is None:
            return
        kind, name = event
        if kind == 'native-crc-init':
            require(self.reg('RAX') == self.checksum_state and self.number(self.checksum_state, 4) == 0xffffffff,
                    'Integrity native CRC initializer result differs')
            self.result['checksum_initial_state'] = self.number(self.checksum_state, 4)
        elif kind == 'native-crc-update':
            value, state = self.reg('RAX'), self.number(self.checksum_state, 4)
            require(value <= 0xffffffff and value == (state ^ 0xffffffff),
                    'Integrity native CRC state/return relationship differs')
            self.result.update(checksum_value=value, checksum_final_state=state)
        elif kind == 'native-transform':
            frame = self.contents('outer')
            require(frame[:3] == self.before_transform[:3]
                    and self.reg('RAX') == len(frame) - 3,
                    'Integrity native XOR prefix/return differs')
            self.transformed_frame = frame
            self.result.update(transform_return_value=self.reg('RAX'),
                transform_effective_key_bits=self.number(self.transform_home))
        elif kind == 'constructor':
            at = self.archives[name]['object']
            require(self.reg('RAX') == at and self.number(at) == self.archive['table']
                    and self.contents(name) == b'', 'Backend native archive constructor differs')
        elif kind == 'writer':
            inner = self.contents('inner')
            require(self.reg('RAX') & 255 == 1 and inner.startswith(self.writer_prefix),
                    'Backend native writer return/prefix differs')
            self.state['check_packet']()
            self.result.update(writer_return_count=len(inner), inner_bytes=len(inner),
                writer_delta_hex=inner[len(self.writer_prefix):].hex(), inner_hex=inner.hex(),
                packet_immutable=True, strings_immutable=True, prefix_immutable=True)
            require(all(self.state['allocation_records'][p]['kind'] not in ('utf8', 'cpp')
                        or p in self.state['freed'] for p in self.created),
                    'Backend wire temporary survives writer return')
            pointer = self.archives['inner']['buffer']
            self.h.uc.protect([(pointer, self.state['allocation_records'][pointer]['size'])])
        elif kind == 'packet-id':
            value = self.reg('RAX')
            self.result['request_id'] = value
            require(value == 3, 'Backend actual native packet-ID return differs')
        elif kind == 'append':
            require(self.contents('outer') == self.append_prefix + self.contents('inner'),
                    'Backend native append bytes/prefix differ')
        elif kind == 'cleanup':
            item = self.archives[name]
            at = item['object']
            require(bytes(self.h.uc.mem_read(at + 0x18, 24)) == bytes(24)
                    and self.number(at + 0x30, 4) == 0
                    and item['buffer'] in self.state['freed']
                    and self.number(at) == int(self.c['source_inputs']['cleanup_final_table']['address'], 16),
                    'Backend archive cleanup fields/ownership differ')
            self.active_cleanup = None

    def observed(self, address):
        if self.spec is None:
            return
        self.observe_return(address)
        self.native_integrity_entry(address)
        if address == self.functions['backend']:
            require(self.backend_stack is None and self.reg('RCX') == self.backend_object,
                    'Backend codec native entry differs')
            self.backend_stack = self.reg('RSP')
            self.checksum_state = self.backend_stack - 0xa8
            self.archives = {name: dict(object=self.backend_stack - offset)
                for name, offset in (('inner', 0x58), ('outer', 0x98))}
        elif address == self.archive['constructor']:
            self.source_caller(address, {'backend'})
            name = self.archive_name(self.reg('RCX'))
            flags = self.number(int(self.c['source_inputs']['archive_flags']['address'], 16), 4)
            require('constructed' not in self.archives[name]
                    and self.reg('RDX') == flags,
                    'Backend native archive constructor arguments differ')
            require(self.result['archive_flags_bits'] in (None, flags),
                    'Backend shared archive flags changed between constructors')
            self.result['archive_flags_bits'] = flags
            self.archives[name]['constructed'] = True
            self.result['archive_constructor_calls'] += 1
            self.pending_returns[self.number(self.reg('RSP'))] = ('constructor', name)
        elif address == self.backend['packet_id_getter']:
            self.source_caller(address, {'backend'})
            require(self.reg('RCX') == self.state['packet'], 'Backend request-ID receiver differs')
            self.result['request_id_calls'] += 1
            self.pending_returns[self.number(self.reg('RSP'))] = ('packet-id', None)
        elif address == self.functions['wire.login-writer']:
            role, callsite = self.source_caller(address, {'backend'})
            require(self.reg('RCX') == self.state['packet']
                    and self.reg('RDX') == self.archives['inner']['object'],
                    'Backend writer source packet/archive arguments differ')
            self.writer_prefix = self.contents('inner')
            require(len(self.writer_prefix) == 4, 'Backend writer native prefix extent differs')
            self.result.update(writer_calls=self.result['writer_calls'] + 1,
                writer_prefix_hex=self.writer_prefix.hex(), writer_entry_count=len(self.writer_prefix),
                same_packet=True, writer_source_edge=True)
            self.pending_returns[self.number(self.reg('RSP'))] = ('writer', 'inner')
        elif address == self.functions['wire.append']:
            self.source_caller(address, {'backend'})
            require(self.reg('RCX') == self.archives['outer']['object']
                    and self.reg('RDX') == self.archives['inner']['object'],
                    'Backend append archive arguments differ')
            self.append_prefix = self.contents('outer')
            self.result['append_calls'] += 1
            self.pending_returns[self.number(self.reg('RSP'))] = ('append', 'outer')
        elif address == self.functions['wire.append'] + 66:
            require(self.reg('RAX') == self.archive['raw']
                    and self.reg('RCX') == self.archives['outer']['object']
                    and self.reg('RDX') == self.archives['inner']['buffer']
                    and self.reg('R8') == len(self.contents('inner')),
                    'Backend append indirect native tail differs')
        elif address == self.functions['wire.cleanup']:
            name = self.archive_name(self.reg('RCX'))
            require(self.transport_seen and self.active_cleanup is None and name not in self.result['cleanup_order'],
                    'Backend cleanup precedes transport or repeats')
            self.active_cleanup = name
            self.result['archive_cleanup_calls'] += 1
            self.result['cleanup_order'].append(name)
            self.state['events'].append('archive_cleanup_' + name)
            self.pending_returns[self.number(self.reg('RSP'))] = ('cleanup', name)

    def check(self, spec):
        require(spec == self.spec and not self.pending_returns, 'Backend codec incomplete return observation')
        require(all(pointer in self.state['freed'] for pointer in self.created),
                'Backend codec allocation leak')
        if self.result['writer_calls']:
            require(self.result['cleanup_order'] == ['outer', 'inner'] and self.transport_seen,
                    'Backend codec ownership lifecycle differs')
        return dict(self.result)


def install(h, context, wire, state, allocate, release, caller, reg, number):
    return Codec(h, context, wire, state, allocate, release, caller, reg, number)
