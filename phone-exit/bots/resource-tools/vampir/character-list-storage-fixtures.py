"""Bounded storage only for a shared list replay; no wire parsing in fixtures."""
import struct


def install(h, context, state, allocate):
    uc, x = h.uc, h.x
    packet = state['packet']

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def number(at, size):
        return int.from_bytes(uc.mem_read(at, size), 'little')

    def put(at, fmt, *values):
        uc.mem_write(at, struct.pack('<' + fmt, *values))

    def owner():
        value = state['record']
        require(h.scratch + 0x30000 <= value <= h.scratch + 0x38000 - 0x170, 'List record storage owner differs')
        return value

    def init_map(address):
        require(address == owner() + 0x120, 'List map reset receiver differs')
        # A reused stack address must not overwrite a previously copied record.
        key = (state['generation'], address)
        if key not in state['map_storage']:
            state['map_storage'][key] = allocate(8 * 0x38)
        pointer = state['map_storage'][key]
        uc.mem_write(address, bytes(0x50)); uc.mem_write(pointer, bytes(8 * 0x38))
        put(address, 'QII', pointer, 0, 8); put(address + 0x2c, 'I', 128)
        put(address + 0x30, 'ii', -1, 0); put(address + 0x38, 'i', -1); put(address + 0x48, 'I', 1)

    def rehash(address):
        require(address == owner() + 0x120, 'List map rehash receiver differs')
        pointer, count, buckets = number(address, 8), number(address + 8, 4), number(address + 0x48, 4)
        require(count <= 8 and buckets in (1, 2, 4, 8, 16), 'List map bucket/count budget')
        heads = [-1] * buckets
        for index in range(count):
            node = pointer + index * 0x38; key = number(node, 1); bucket = key & (buckets - 1)
            put(node + 0x30, 'iI', heads[bucket], bucket); heads[bucket] = index
        if buckets > 1:
            data = allocate(buckets * 4); uc.mem_write(data, struct.pack('<' + 'i' * buckets, *heads))
            put(address + 0x40, 'Q', data)
        else:
            put(address + 0x38, 'i', heads[0]); put(address + 0x40, 'Q', 0)
        state['rehashes'].append(dict(generation=state['generation'], buckets=buckets))

    def fixture(machine, name):
        a, b = reg('RCX'), reg('RDX')
        result = 0
        if name in ('list_clear', 'appearance_clear'):
            require(b == 0, 'List initial storage cleanup count differs')
        elif name == 'list_allocate':
            require(a == packet + 0x18 and b <= 4, 'List allocation receiver/count budget')
            pointer = allocate(b * 0x170) if b else 0
            put(a, 'Q', pointer); put(a + 0xc, 'I', b)
            state['list_storage'] = (pointer, b)
        elif name == 'list_copy':
            pointer, count = state['list_storage']
            require(b == owner() and pointer <= a < pointer + count * 0x170
                    and (a - pointer) % 0x170 == 0, 'List shallow-copy source/destination differs')
            uc.mem_write(a, bytes(uc.mem_read(b, 0x170))); result = a
            state['copies'].append(dict(destination=a, generation=state['generation']))
        elif name == 'record_cleanup':
            require(a == owner(), 'List record cleanup receiver differs')
        elif name == 'appearance_allocate':
            require(a == owner() + 0xe0 and b <= 8, 'List appearance allocation receiver/count budget')
            put(a, 'Q', allocate(b * 16) if b else 0); put(a + 0xc, 'I', b)
        elif name in ('list_grow', 'appearance_grow', 'map_grow'):
            raise ValueError('List reserved storage budget exceeded')
        elif name in ('map_init', 'map_clear'):
            if name == 'map_clear':
                require(b == 0, 'List optional clear argument differs')
            init_map(a)
        elif name == 'map_rehash':
            rehash(a)
        elif name == 'bit_append':
            require(a == owner() + 0x130 and b == 0, 'List map bit append differs')
        elif name == 'insert_predicate':
            require(a == owner() + 0x120, 'List map insert receiver differs')
            pointer, count = number(a, 8), number(a + 8, 4)
            require(1 <= count <= 8 and not any(number(pointer + i * 0x38, 1) == b for i in range(count - 1)),
                    'Duplicate list map key reached insertion')
            state['insertions'].append(dict(generation=state['generation'], key=b))
        elif name == 'value_cleanup':
            require(h.scratch + 0x30000 <= a < h.scratch + 0x38000, 'List value cleanup receiver differs')
        else:
            raise ValueError('Unsupported list storage fixture')
        h.finish(result)

    protected = {int(at, 16) for at in context['functions'].values()} | {int(at, 16) for at in context['leaves']}
    for name, at in context['fixtures'].items():
        require(int(at, 16) not in protected, 'List storage fixture overlaps native code')
        h.add_fixture(int(at, 16), lambda machine, name=name: fixture(machine, name))
