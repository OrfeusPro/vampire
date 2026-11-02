"""Explicit opaque member/storage providers; native ownership logic stays native."""
import struct


def require(ok, message):
    if not ok:
        raise ValueError(message)


class Providers:
    def __init__(self, h, context, state, reg, number, caller):
        self.h, self.c, self.s, self.reg, self.number, self.caller = h, context, state, reg, number, caller
        self.addresses = {key: int(value, 16) for key, value in context['fixtures'].items()}

    @property
    def ledger(self):
        return self.s['ledger']

    def write(self, windows, action):
        self.h.uc.begin_fixture(windows)
        try:
            return action()
        finally:
            self.h.uc.end_fixture()

    def put(self, at, data):
        self.write([(at, len(data))], lambda: self.h.uc.mem_write(at, data))

    def new_owner(self, size, kind, name):
        return self.ledger.allocate(size, kind, name, fixture=True)

    def receiver(self, kind, offsets):
        at = self.reg('RCX')
        base, row = self.ledger.owner(at)
        require(row['kind'] == kind and at - base in offsets, 'Lifecycle member receiver/owner differs')
        return base, row, at - base

    def install(self):
        for key in self.addresses:
            handler = getattr(self, key, None)
            require(handler is not None, 'Lifecycle opaque provider not implemented: ' + key)
            def execute(machine, key=key, handler=handler):
                require(self.s.get('running'), 'Lifecycle provider outside declared native entry')
                require(self.reg('RSP') & 15 == 8, 'Lifecycle provider Win64 alignment differs')
                self.s['provider_caller'] = self.caller(self.addresses[key])
                handler()
            self.h.add_fixture(self.addresses[key], execute)

    def allocate_native_name(self, role, site, size):
        if role == 'service.assign':
            if size == 800:
                self.s['backend_serial'] += 1
                return 'backend', 'backend' + str(self.s['backend_serial'])
            require(size == 24, 'Lifecycle assignment allocation size differs')
            return 'control', 'control' + str(self.s['backend_serial'])
        backend = self.s['current_backend']
        if role == 'backend.base_constructor':
            offsets = self.s['base_sentinel_offsets']
            index = self.s['base_allocate_index'].get(backend, 0)
            require(index < 4 and size == 16, 'Lifecycle base sentinel allocation sequence differs')
            self.s['base_allocate_index'][backend] = index + 1
            return 'sentinel', self.ledger.name(backend) + '.sentinel' + format(offsets[index], 'x')
        require(role == 'backend.constructor' and size == 16,
                'Lifecycle native allocator source role/size differs')
        locality = 'local' if self.s['last_find_kind'] == 'local' else 'global'
        return 'registration_node', self.ledger.name(backend) + '.' + locality + '.node'

    def allocate(self):
        role, site = self.s['provider_caller']
        size = self.reg('RCX')
        kind, name = self.allocate_native_name(role, site, size)
        address = self.ledger.allocate(size, kind, name, fixture=True)
        self.s['native_allocations'].append(size)
        self.h.finish(address)

    def native_free(self, sized):
        role, site = self.s['provider_caller']
        at = self.reg('RCX')
        row = self.ledger.record(at)
        size = self.reg('RDX') if sized else row['size']
        allowed = {
            'control.deleting': {'control'}, 'backend.deleting': {'backend'},
            'service.deleting': {'service', 'service_storage'},
            'backend.destructor': {'callback', 'derived_storage'},
            'backend.base_destructor': {'sentinel', 'string'},
            'backend.string_ring_clear': {'ring_heap', 'ring_node', 'ring_map'}}
        require(role in allowed and row['kind'] in allowed[role], 'Lifecycle native free caller/kind differs')
        require(not sized or size == row['size'], 'Lifecycle native sized free extent differs')
        self.s['native_frees'].append(dict(owner=row['name'], size=row['size']))
        self.ledger.release(at, size=size if sized else None)
        self.h.finish(0xfeedface00000000)

    def sized_free(self):
        self.native_free(True)

    def unsized_free(self):
        self.native_free(False)

    def service_init(self):
        base, row, offset = self.receiver('service', {8})
        require(self.s['provider_caller'][0] == 'service.publisher', 'Lifecycle service init caller differs')
        # The source publisher subsequently writes all service-owned fields.
        # This engine member's opaque fixture is a strict no-op.
        self.h.finish(self.reg('RCX'))

    def service_engine_destroy(self):
        self.receiver('service', {8})
        require(self.s['provider_caller'][0] == 'service.deleting', 'Lifecycle engine destroy caller differs')
        self.h.finish(0)

    def service_member_destroy(self):
        self.receiver('service', {0x88})
        require(self.s['provider_caller'][0] == 'service.deleting', 'Lifecycle service member caller differs')
        self.h.finish(0)

    def service_container_destroy(self):
        self.receiver('service', {0x28})
        require(self.s['provider_caller'][0] == 'service.deleting', 'Lifecycle service container caller differs')
        self.h.finish(0)

    def observer_init(self):
        base, row, offset = self.receiver('backend', {0x38, 0x50, 0x200, 0x218})
        role = self.s['provider_caller'][0]
        require((role == 'backend.base_constructor' and offset in (0x38, 0x50))
                or (role == 'backend.constructor' and offset in (0x200, 0x218)),
                'Lifecycle observer initializer caller differs')
        pair, control = 0, 0
        if offset in (0x200, 0x218):
            name = 'local' if offset == 0x200 else 'global'
            pair = 0xabc000 + (1 if name == 'local' else 2)
            if self.s['observer_present']:
                control = self.new_owner(24, 'observer_control', row['name'] + '.' + name + '_observer')
                self.put(control, struct.pack('<QIIQ', self.s['tables']['control'], 1, 3, 0))
        self.put(base + offset, struct.pack('<QQQ', 0, pair, control))
        self.h.finish(base + offset)

    def derived_storage_init(self):
        base, row, offset = self.receiver('backend', {0x250})
        require(self.s['provider_caller'][0] == 'backend.constructor', 'Lifecycle derived init caller differs')
        self.put(base + offset, bytes(32))
        self.h.finish(base + offset)

    def vector_init(self):
        base, row, offset = self.receiver('backend', {0x178, 0x198, 0x1b8})
        require(self.s['provider_caller'][0] == 'backend.base_constructor', 'Lifecycle vector initializer caller differs')
        self.put(base + offset, bytes(24))
        self.h.finish(base + offset)

    def vector_destroy(self):
        base, row, offset = self.receiver('backend', {0x170, 0x190, 0x1b0, 0x250})
        role = self.s['provider_caller'][0]
        require(role in ('backend.destructor', 'backend.base_destructor'), 'Lifecycle vector destroy caller differs')
        at = base + offset + 8
        begin, end, limit = struct.unpack('<QQQ', self.h.uc.mem_read(at, 24))
        require(begin <= end <= limit, 'Lifecycle vector destroy descriptor ordering differs')
        if begin:
            self.ledger.release(begin, size=limit - begin, kind='queue')
        else:
            require(end == limit == 0, 'Lifecycle null vector descriptor differs')
        self.put(at, bytes(24))
        self.h.finish(0)

    def global_container(self):
        require(self.s['provider_caller'][0] in ('backend.constructor', 'backend.destructor'),
                'Lifecycle global container provider caller differs')
        self.h.finish(self.s['global_container'])

    def iterator_find(self):
        role, site = self.s['provider_caller']
        # Source LEAs and frame prologues fix all three iterator spans relative
        # to provider-entry RSP (after CALL pushed its return address).  Check
        # these before even reading input descriptors: put() grants only the
        # requested fixture window and cannot establish that the output is stack.
        source_aliases = {
            ('backend.constructor', 0x198): (0x88, 0x70, 0x58, 0x208),
            ('backend.constructor', 0x272): (0xa0, 0x28, 0x40, 0x220),
            ('backend.destructor', 0xb3): (0x58, 0x28, 0x40, 0x220),
            ('backend.destructor', 0x144): (0x58, 0x28, 0x40, 0x208),
            ('backend.reset', 0x68): (0x58, 0x28, 0x40, 0x40),
            ('backend.reset', 0xfe): (0x58, 0x28, 0x40, 0x58)}
        functions = self.c['functions']
        require(role in functions, 'Lifecycle iterator find caller differs')
        aliases = source_aliases.get((role, site - int(functions[role], 16)))
        require(aliases is not None, 'Lifecycle iterator find callsite differs')
        output, first, last, pair = (self.reg(name) for name in ('RCX', 'RDX', 'R8', 'R9'))
        stack = self.reg('RSP')
        lower, upper = self.h.scratch + 0x30000, self.h.scratch + 0x3f000
        require(lower <= stack and stack + 8 <= upper
                and all(lower <= at and at + 24 <= upper for at in (output, first, last)),
                'Lifecycle iterator stack span differs')
        require((output, first, last) == tuple(stack + offset for offset in aliases[:3]),
                'Lifecycle iterator source stack aliases differ')
        backend, row = self.ledger.owner(pair, 16)
        require(row['kind'] == 'backend', 'Lifecycle iterator observed pair owner differs')
        offset = pair - backend
        require(offset == aliases[3], 'Lifecycle iterator source pair alias differs')
        locality = {0x208: 'local', 0x220: 'global', 0x40: 'reset_d0', 0x58: 'reset_118'}.get(offset)
        require(locality is not None, 'Lifecycle iterator observed pair offset differs')
        container = (backend + 8 if locality == 'local' else self.s['global_container'] + 0x10
            if locality == 'global' else backend + (0xd0 if locality == 'reset_d0' else 0x118))
        expected_head = self.number(container)
        require(self.number(first) == self.number(last) == expected_head,
                'Lifecycle iterator input aliases/head differ')
        require(self.number(first + 8) == self.number(last + 8) == 0,
                'Lifecycle iterator input reserved fields differ')
        start, count = self.number(container + 0x18), self.number(container + 0x20)
        require(self.number(first + 16) == start and self.number(last + 16) == start + count,
                'Lifecycle iterator input positions differ')
        decision = self.s['iterator_model'][locality] if role == 'backend.constructor' else self.s['cleanup_find']
        require(decision in ('found','end'), 'Lifecycle iterator fixture decision differs')
        position = start + count if decision == 'end' else start + count + 1
        self.put(output, struct.pack('<QQQ', expected_head, 0, position))
        self.s['last_find_kind'] = locality
        self.h.finish(output)

    def reserve(self):
        require(self.s['provider_caller'][0] == 'backend.constructor' and self.reg('RDX') == 1,
                'Lifecycle reserve caller/count differs')
        container = self.reg('RCX')
        backend = self.s['current_backend']
        locality = 'local' if container == backend + 8 else 'global'
        require(locality == 'local' or container == self.s['global_container'] + 0x10,
                'Lifecycle reserve receiver differs')
        self.initialize_registration_storage(container, self.ledger.name(backend) + '.' + locality, 4)
        self.s['reserve_seen'].append(locality)
        self.h.finish(0)

    def initialize_registration_storage(self, container, name, capacity):
        old = self.number(container + 8)
        if old:
            self.ledger.release(old, kind='registration_map')
        pointer = self.new_owner(capacity * 8, 'registration_map', name + '.map')
        self.put(pointer, bytes(capacity * 8))
        self.put(container + 8, struct.pack('<QQQQ', pointer, capacity, 0, 0))

    def iterator_remove(self):
        raise ValueError('Lifecycle unmodelled iterator remove path reached')

    def observer_destroy(self):
        self.receiver('backend', {0x38, 0x50, 0x200, 0x218})
        require(self.s['provider_caller'][0] in ('backend.destructor', 'backend.base_destructor'),
                'Lifecycle observer destroy caller differs')
        # Opaque observer release is deliberately not presented as native
        # reference-count mutation. Synthetic observer controls remain retained.
        self.h.finish(0)

    def string_destroy(self):
        self.receiver('backend', {0x68})
        require(self.s['provider_caller'][0] == 'backend.base_destructor', 'Lifecycle string destroy caller differs')
        self.h.finish(0)

    def member_d0_destroy(self):
        self.destroy_empty_member(0xc8, 0xd0)

    def member_118_destroy(self):
        self.destroy_empty_member(0x110, 0x118)

    def destroy_empty_member(self, offset, sentinel_offset):
        base, row, actual = self.receiver('backend', {offset})
        require(self.s['provider_caller'][0] == 'backend.base_destructor', 'Lifecycle member destroy caller differs')
        pointer = self.number(base + sentinel_offset)
        self.ledger.release(pointer, size=16, kind='sentinel')
        self.put(base + sentinel_offset, bytes(8))
        self.h.finish(0)

    def list_clear(self):
        base, row, offset = self.receiver('backend', {8})
        require(self.s['provider_caller'][0] == 'backend.base_destructor', 'Lifecycle list clear caller differs')
        container = base + 8
        map_at, capacity = self.number(container + 8), self.number(container + 16)
        if map_at:
            for index in range(capacity):
                node = self.number(map_at + index * 8)
                if node:
                    self.ledger.release(node, size=16, kind='registration_node')
            self.ledger.release(map_at, size=capacity * 8, kind='registration_map')
            self.put(container + 8, bytes(32))
        self.h.finish(0)

    def callback_allocate(self):
        require(self.s['provider_caller'][0] == 'service.assign' and self.reg('RCX') == 48,
                'Lifecycle callback allocator source/size differs')
        output = self.reg('RDX')
        backend, row = self.ledger.owner(output, 12)
        require(row['kind'] == 'backend' and output - backend == 0x308,
                'Lifecycle callback allocator output alias differs')
        if not self.s['callback_present']:
            self.h.finish(0)
            return
        pointer = self.new_owner(48, 'callback', row['name'] + '.callback')
        self.put(output, struct.pack('<QI', pointer, 1))
        self.h.finish(pointer)

    def callback_token(self):
        require(self.s['provider_caller'][0] == 'service.assign', 'Lifecycle callback token source differs')
        self.h.finish(0x123456789abcdef0)

    def callback_resize(self):
        require(self.s['provider_caller'][0] == 'backend.destructor'
                and self.reg('RDX') == self.reg('R8') == 0 and self.reg('R9') == 16,
                'Lifecycle callback resize ABI differs')
        backend, row = self.ledger.owner(self.reg('RCX'), 8)
        require(row['kind'] == 'backend' and self.reg('RCX') - backend == 0x308,
                'Lifecycle callback resize output owner differs')
        self.h.finish(0)

    def callback_destroy(self):
        require(self.s['provider_caller'][0] == 'backend.destructor' and self.reg('RDX') == 0,
                'Lifecycle callback destructor ABI differs')
        row = self.ledger.record(self.reg('RCX'), 48, 'callback')
        require(self.number(self.reg('RCX')) == self.s['tables']['callback'],
                'Lifecycle callback source vtable differs')
        self.h.finish(0)
