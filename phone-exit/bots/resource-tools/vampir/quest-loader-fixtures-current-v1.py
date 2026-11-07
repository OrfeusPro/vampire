"""Versioned bounded storage providers for current mixed QuestTask loading."""
from types import SimpleNamespace
import struct


def create_fixture_state(h, addresses, columns, *, manager=None):
    """Install explicit CSV/storage providers and an isolated no-RU override slot."""
    uc, x, base = h.uc, h.x, h.scratch
    if len(columns) != 17 or columns[16] != 'ServerServiceGroupId':
        raise ValueError('Mixed loader needs the exact QuestTask schema')
    manager = base + 0x1000 if manager is None else manager
    if manager != base + 0x1000:
        raise ValueError('Mixed loader manager outside reserved storage')
    primary, group, cells = manager + 0x18, manager + 0x68, base + 0x3000
    stream_object, stream_table = base + 0x2000, base + 0x2100
    read_callback, hash_callback = base + 0x2200, base + 0x2300
    locale_buffer, cloned_table, override_callback = base + 0x2400, base + 0x2500, base + 0x2600
    state, blocks, counts = {}, {}, {}
    cursor = [base + 0x8000]

    def address(old):
        try:
            return int(addresses[hex(old)], 16)
        except KeyError as error:
            raise ValueError('Unbound mixed loader address ' + hex(old)) from error

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def get(at, size=8):
        return int.from_bytes(uc.mem_read(at, size), 'little')

    def put(at, value, size=8):
        uc.mem_write(at, (int(value) % (1 << (size * 8))).to_bytes(size, 'little'))

    def count(name):
        counts[name] = counts.get(name, 0) + 1

    def allocate(size):
        if not 0 < size <= 16384:
            raise ValueError('Mixed loader allocation size budget')
        at = (cursor[0] + 31) & ~15
        cursor[0] = at + ((size + 15) & ~15) + 16
        if cursor[0] >= base + 0x33000:
            raise ValueError('Mixed loader allocation arena budget')
        uc.mem_write(at - 16, b'L' * 16 + bytes(size) + b'R' * 16)
        blocks[at] = size
        return at

    def free(at):
        size = blocks.pop(at, None)
        if size is None or bytes(uc.mem_read(at - 16, 16)) != b'L' * 16 or bytes(uc.mem_read(at + size, 16)) != b'R' * 16:
            raise ValueError('Mixed loader allocation ownership or guards differ')

    def raw_string(ptr):
        for size in range(2048):
            if bytes(uc.mem_read(ptr + size, 1)) == b'\0':
                return bytes(uc.mem_read(ptr, size))
        raise ValueError('Mixed loader CString budget')

    def string(at):
        size, capacity = get(at + 16), get(at + 24)
        if size > capacity or capacity > 2047:
            raise ValueError('Mixed loader cell capacity differs')
        data = bytes(uc.mem_read(at if capacity <= 15 else get(at), size + 1))
        if data[-1:] != b'\0':
            raise ValueError('Mixed loader cell terminator differs')
        return data[:-1]

    def assign(at, data, capacity=0):
        capacity = max(15, len(data), capacity)
        uc.mem_write(at, bytes(32))
        ptr = at if capacity == 15 else allocate(capacity + 1)
        uc.mem_write(ptr, data + b'\0')
        if ptr != at:
            put(at, ptr)
        put(at + 16, len(data))
        put(at + 24, capacity)

    def clear_cells():
        parser = state['parser']
        for at in range(get(parser + 0x28), get(parser + 0x30), 32):
            string(at)
            if get(at + 24) > 15:
                free(get(at))
        put(parser + 0x30, cells)

    def csv_init(machine):
        if state.get('parser') is not None:
            raise ValueError('Mixed loader opened more than one parser')
        state['parser'] = reg('RCX')
        uc.mem_write(reg('RCX'), bytes(64))
        h.finish(reg('RCX'))

    def file_load(machine):
        if reg('RCX') != manager + 8 or reg('RDX') != state['parser'] or counts.get('file_load'):
            raise ValueError('Mixed loader file provider scope differs')
        parser = state['parser']
        put(parser + 8, stream_object)
        put(parser + 0x20, 17)
        put(parser + 0x28, cells)
        put(parser + 0x30, cells)
        put(parser + 0x38, cells + 17 * 32)
        put(manager + 16, 16, 2)
        count('file_load')
        h.finish(1)

    def read_byte(machine):
        if reg('RCX') != stream_object or reg('R8') != 1:
            raise ValueError('Mixed loader byte stream contract differs')
        position = state['position']
        if position == len(state['raw']):
            h.finish(0)
        else:
            uc.mem_write(reg('RDX'), state['raw'][position:position + 1])
            state['position'] += 1
            h.finish(1)

    def cell_copy(machine):
        if not cells <= reg('RCX') < cells + 17 * 32:
            raise ValueError('Mixed loader cell destination differs')
        assign(reg('RCX'), string(reg('RDX')))
        h.finish(reg('RCX'))

    def cell_grow(machine):
        at = reg('RCX')
        if reg('RDX') != 1:
            raise ValueError('Mixed loader cell growth count differs')
        old = get(at) if get(at + 24) > 15 else 0
        data = string(at) + bytes([reg('R9') & 255])
        assign(at, data, min(2047, max(len(data), get(at + 24) * 2)))
        if old:
            free(old)
        h.finish(at)

    def cell_clear(machine):
        parser = state['parser']
        if (reg('RCX'), reg('RDX'), reg('R8')) != (cells, get(parser + 0x30), parser + 0x28):
            raise ValueError('Mixed loader cell reset scope differs')
        clear_cells()
        h.finish()

    def cell_pointer(machine):
        if reg('RCX') != state['parser'] or reg('RDX') >= 17:
            raise ValueError('Mixed loader column getter scope differs')
        string(cells + reg('RDX') * 32).decode('utf-8')
        h.finish(cells + reg('RDX') * 32)

    def column(machine):
        if reg('RCX') != state['parser']:
            raise ValueError('Mixed loader header lookup receiver differs')
        name = string(reg('RDX')).decode('ascii')
        count('column')
        h.finish(columns.index(name) if name in columns else 0xffffffff)

    def wide_read(ptr):
        if not ptr:
            return b''
        for size in range(2048):
            if bytes(uc.mem_read(ptr + size * 2, 2)) == b'\0\0':
                return bytes(uc.mem_read(ptr, size * 2))
        raise ValueError('Mixed loader wide string budget')

    def wide_init(machine):
        at, source = reg('RCX'), reg('RDX')
        data = wide_read(source) if source else b''
        uc.mem_write(at, bytes(16))
        if data:
            ptr = allocate(len(data) + 2)
            uc.mem_write(ptr, data + b'\0\0')
            put(at, ptr)
            put(at + 8, len(data) // 2 + 1, 4)
            put(at + 12, len(data) // 2 + 1, 4)
        h.finish(at)

    def wide_copy(machine):
        if bytes(uc.mem_read(reg('RDX'), 16)) != bytes(16):
            raise ValueError('Mixed loader constructor wide source is not empty')
        uc.mem_write(reg('RCX'), bytes(16))
        h.finish(reg('RCX'))

    def wide_count(machine):
        data = raw_string(reg('RDX'))
        if reg('RCX') or reg('R8') != len(data):
            raise ValueError('Mixed loader UTF8 count contract differs')
        h.finish(len(data.decode('utf-8').encode('utf-16le')) // 2)

    def wide_convert(machine):
        data = raw_string(reg('R8'))
        wide = data.decode('utf-8').encode('utf-16le') + b'\0\0'
        if reg('RDX') * 2 < len(wide) or reg('R9') != len(data) + 1:
            raise ValueError('Mixed loader UTF8 conversion contract differs')
        uc.mem_write(reg('RCX'), wide)
        h.finish(len(wide) // 2)

    def array_resize(machine):
        at, size = reg('RCX'), reg('RDX')
        if size > 2048:
            raise ValueError('Mixed loader FString array budget')
        old = get(at)
        put(at, allocate(size * 2) if size else 0)
        if old:
            free(old)
        put(at + 12, size, 4)
        h.finish()

    def node_resize(machine):
        old, size = reg('RCX'), reg('RDX')
        if reg('R8') != 8 or old and old not in blocks:
            raise ValueError('Mixed loader node resize contract differs')
        at = allocate(size)
        if old:
            uc.mem_write(at, bytes(uc.mem_read(old, min(size, blocks[old]))))
        count('node_resize')
        h.finish(at)

    def map_clear(machine):
        at = reg('RCX')
        if at not in (primary, group) or reg('RDX') or get(at + 8, 4):
            raise ValueError('Mixed loader fresh map clear differs')
        uc.mem_write(at, bytes(80))
        put(at + 0x2c, 128, 4)
        put(at + 0x30, -1, 4)
        h.finish()

    def bit_append(machine):
        at = reg('RCX') - 0x10
        if at not in (primary, group) or reg('RDX') or get(at + 0x28, 4) >= 128:
            raise ValueError('Mixed loader inline bit append differs')
        size = get(at + 0x28, 4)
        put(at + 0x28, size + 1, 4)
        h.finish(size)

    def bucket_alloc(machine):
        at, size = reg('RCX') - 0x38, reg('R8')
        if at not in (primary, group) or reg('RDX') or reg('R9') != 4:
            raise ValueError('Mixed loader bucket allocation differs')
        put(at + 0x40, allocate(size * 4) if size > 2 else 0)
        h.finish()

    def buffer_resize(machine):
        at, size, width = reg('RCX'), reg('R8'), reg('R9')
        if reg('RDX'):
            raise ValueError('Mixed loader buffer resize old size differs')
        if at in (primary + 0x40, group + 0x40) and size == 0 and width == 4:
            put(at, 0)
        elif width == 2 and size <= 2048:
            put(at, allocate(size * 2) if size else 0)
        else:
            raise ValueError('Mixed loader buffer resize contract differs')
        h.finish()

    def group_array(machine):
        at = reg('RCX')
        size = get(at + 8, 4)
        if size != reg('RDX') + 1 or size > 128:
            raise ValueError('Mixed loader group append contract differs')
        old, capacity = get(at), max(4, size * 2)
        ptr = allocate(capacity * 8)
        if old:
            uc.mem_write(ptr, bytes(uc.mem_read(old, (size - 1) * 8)))
        put(at, ptr)
        put(at + 12, capacity, 4)
        count('group_array_resize')
        h.finish()

    def copy(machine):
        target, source, size = reg('RCX'), reg('RDX'), reg('R8')
        if size > 4096 or not base <= target <= base + 0x40000 - size:
            raise ValueError('Mixed loader copy destination differs')
        uc.mem_write(target, bytes(uc.mem_read(source, size)))
        h.finish(target)

    def zero(machine):
        at, value, size = reg('RCX'), reg('RDX'), reg('R8')
        if value or size != 0xa0 or not base + 0x35000 < at < base + 0x38000 - size:
            raise ValueError('Mixed loader temporary memset differs')
        uc.mem_write(at, bytes(size))
        h.finish(at)

    def destroy_parser(machine):
        if reg('RCX') != state['parser']:
            raise ValueError('Mixed loader parser cleanup scope differs')
        clear_cells()
        h.finish()

    def locale_get(machine):
        uc.mem_write(locale_buffer, bytes(16))
        h.finish(locale_buffer)

    def override_noop(machine):
        if reg('RCX') != manager + 8 or reg('RDX') != locale_buffer:
            raise ValueError('Mixed loader no-RU override arguments differ')
        count('override_fixture')
        h.finish()

    def hash_key(machine):
        if reg('RDX') != 8:
            raise ValueError('Mixed loader hash length differs')
        h.finish(1)

    def free_callback(machine):
        free(reg('RCX'))
        h.finish()

    def empty_object(size):
        def callback(machine):
            uc.mem_write(reg('RCX'), bytes(size))
            h.finish(reg('RCX'))
        return callback

    callbacks = {
        address(0x1445f5a40): csv_init, address(0x145a6e600): file_load,
        read_callback: read_byte, hash_callback: hash_key, override_callback: override_noop,
        address(0x1421e7340): cell_grow, address(0x1445df320): cell_copy,
        address(0x1445de2a0): cell_clear, address(0x1445f6840): column,
        address(0x1445f5fc0): cell_pointer, address(0x141426950): wide_init,
        address(0x141426b30): wide_init, address(0x1414266a0): wide_copy,
        address(0x14144c440): wide_count, address(0x1414466a0): wide_convert,
        address(0x141436ed0): array_resize, address(0x145b53b10): map_clear,
        address(0x141448fd0): map_clear, address(0x1414923d0): node_resize,
        address(0x141429680): bit_append, address(0x141436bc0): bucket_alloc,
        address(0x141436cc0): buffer_resize, address(0x14141c080): group_array,
        address(0x1487f5ab9): copy, address(0x1487f5ac5): zero,
        address(0x141431f80): free_callback, address(0x141483080): free_callback,
        address(0x1445f5b40): destroy_parser, address(0x145a4dc20): locale_get,
        address(0x1414aeff0): empty_object(24), address(0x1445df5a0): empty_object(40),
        address(0x145b74820): lambda machine: h.finish(0),
        address(0x143b7f400): lambda machine: h.finish(0),
        address(0x1445df7c0): lambda machine: h.finish(),
        address(0x146908950): lambda machine: h.finish(allocate(reg('RCX'))),
        address(0x1487e8ce0): lambda machine: h.finish(reg('RAX')),
        address(0x145b547a0): lambda machine: h.finish(manager),
    }
    if len(callbacks) != 37:
        raise ValueError('Mixed loader provider addresses overlap')
    for at, callback in callbacks.items():
        h.add_fixture(at, callback)

    original_table = address(0x1499f69e8)
    table_offset = h.image.offset(original_table - h.image.pe.base)
    table_bytes = h.raw[table_offset:table_offset + 0x80]
    dispatch = {
        0x145b5fab7: 'e844dceeff', 0x145b5fabc: '84c0', 0x145b5fabe: '0f8558040000',
        0x145b5ff2d: 'e8fee0eeff', 0x145b5ff32: '4d8b0424',
        0x145b5ff36: '488bd0', 0x145b5ff39: '498bcc', 0x145b5ff3c: '41ff5040',
    }
    for at, expected in dispatch.items():
        offset = h.image.offset(at - h.image.pe.base)
        if h.raw[offset:offset + len(bytes.fromhex(expected))].hex() != expected:
            raise ValueError('Mixed loader source override dispatch differs')
    if len(table_bytes) != 0x80 or struct.unpack_from('<Q', table_bytes, 0x40)[0] != address(0x145b69ca0):
        raise ValueError('Mixed loader source override slot differs')
    record_table = address(0x1499f67f8)
    record_offset = h.image.offset(record_table - h.image.pe.base)
    for offset in range(0x68, 0xf0, 8):
        if struct.unpack_from('<Q', h.raw, record_offset + offset)[0] != address(0x141403b70):
            raise ValueError('Mixed loader record setter callback source differs')
    if struct.unpack_from('<Q', h.raw, record_offset + 0x30)[0] != address(0x145b55aa0):
        raise ValueError('Mixed loader record Type getter source differs')
    main_table_offset = h.image.offset(address(0x1499f6948) - h.image.pe.base)
    if struct.unpack_from('<Q', h.raw, main_table_offset + 0x30)[0] != address(0x140bb4a10):
        raise ValueError('Mixed loader post-load callback source differs')
    source = dict(original_table=hex(original_table), cloned_table=hex(cloned_table),
                  replaced_slot=64, original_override=hex(address(0x145b69ca0)),
                  fixture_override=hex(override_callback), dispatch={hex(at): raw for at, raw in dispatch.items()})

    def reset(raw_rows):
        raw = raw_rows if isinstance(raw_rows, bytes) else b''.join(raw_rows)
        if not 0 < len(raw) <= 8192:
            raise ValueError('Mixed loader source row payload budget')
        uc.mem_write(base + 0x1000, bytes(0x32000))
        blocks.clear()
        counts.clear()
        state.clear()
        state.update(raw=raw, position=0)
        cursor[0] = base + 0x8000
        uc.mem_write(cloned_table, table_bytes)
        put(cloned_table + 0x40, override_callback)
        put(manager, address(0x1499f6948))
        put(manager + 8, cloned_table)
        put(primary + 0x48, 2, 4)
        put(group + 0x48, 2, 4)
        put(stream_object, stream_table)
        put(stream_table + 0x20, read_callback)
        put(address(0x14b0c2b00), hash_callback)

    def numeric_input():
        ptr = reg('RCX')
        if not cells <= ptr < cells + 17 * 32 and ptr not in blocks:
            raise ValueError('Mixed loader CRT input outside owned cells or allocations')
        data = raw_string(ptr)
        if len(data) > 128:
            raise ValueError('Mixed loader numeric input budget')
        return data

    def check_guards():
        for at, size in blocks.items():
            if bytes(uc.mem_read(at - 16, 16)) != b'L' * 16 or bytes(uc.mem_read(at + size, 16)) != b'R' * 16:
                raise ValueError('Mixed loader final heap guards differ')
        expected_table = bytearray(table_bytes)
        struct.pack_into('<Q', expected_table, 0x40, override_callback)
        if bytes(uc.mem_read(cloned_table, len(expected_table))) != expected_table:
            raise ValueError('Mixed loader isolated override table changed')

    provider = address(0x14b2f01c8)
    rva = provider - h.image.pe.base
    if not any(section['name'] == '.data' and section['raw_size'] <= rva - section['rva'] <= section['size'] - 8
               for section in h.image.pe.sections) or get(provider) != 0:
        raise ValueError('Mixed loader alternate heap provider is not virtual zero')
    return SimpleNamespace(address=address, get=get, put=put, reg=reg, allocate=allocate,
        free=free, wide_read=wide_read, raw_string=raw_string, blocks=blocks, counts=counts,
        state=state, manager=manager, primary=primary, group=group, cells=cells,
        numeric_input=numeric_input, reset=reset, check_guards=check_guards, source=source)
