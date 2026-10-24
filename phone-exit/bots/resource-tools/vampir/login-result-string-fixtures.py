"""Only storage boundaries for real FString/std::string/UTF-8 input methods."""
import struct


def install(load, h, context, state, packet, string_offsets):
    fixtures = {key: int(at, 16) for key, at in context['string_fixtures'].items()}
    cookie = int(context['cookie'], 16)

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def reg(name):
        return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def allocate(size):
        require(0 < size <= 4096 and state['heap'] + size + 64 < h.scratch + 0x30000, 'Reader string allocation bound')
        pointer = state['heap'] + 16
        state['heap'] += (size + 63) & ~15
        h.uc.mem_write(pointer - 16, b'\xa5' * 16 + b'\x5a' * size + b'\xa6' * 16)
        state['allocations'][pointer] = size
        return pointer

    def free(pointer, size=None):
        require(pointer in state['allocations'] and pointer not in state.setdefault('string_freed', set()),
                'Reader string unowned or repeated free')
        if size is not None:
            require(size == state['allocations'][pointer], 'Reader string free size differs')
        state['string_freed'].add(pointer)

    def handler(name):
        def execute(machine):
            a, b, c, d = [reg(key) for key in ('RCX', 'RDX', 'R8', 'R9')]
            result = 0
            if name == 'growth':
                length, capacity = struct.unpack('<QQ', h.uc.mem_read(a + 16, 16))
                require(b == 1 and length == capacity and length <= 2048, 'Reader std-string growth arguments differ')
                old = int.from_bytes(h.uc.mem_read(a, 8), 'little') if capacity > 15 else a
                data = bytes(h.uc.mem_read(old, length))
                new_capacity = (capacity + 1) * 2 - 1
                pointer = allocate(new_capacity + 1)
                h.uc.mem_write(pointer, data + bytes([d & 255, 0]))
                if capacity > 15:
                    free(old, capacity + 1)
                h.uc.mem_write(a, struct.pack('<QQQQ', pointer, 0, length + 1, new_capacity))
                result = a
            elif name == 'utf16_allocate':
                require(b == 0 and d == 2 and 0 < c <= 2048
                        and int.from_bytes(h.uc.mem_read(a, 8), 'little') == 0, 'Reader UTF16 scratch allocation differs')
                h.uc.mem_write(a, struct.pack('<Q', allocate(c * 2)))
            elif name == 'assign':
                owner = packet() if callable(packet) else packet
                require(a - owner in string_offsets and int.from_bytes(h.uc.mem_read(a, 8), 'little') == 0,
                        'Reader FString assignment destination differs')
                data = bytearray()
                if b:
                    for index in range(2048):
                        pair = bytes(h.uc.mem_read(b + 2 * index, 2))
                        if pair == b'\0\0':
                            break
                        data.extend(pair)
                    else:
                        raise ValueError('Reader FString assignment terminator bound')
                pointer = allocate(len(data) + 2) if data else 0
                if pointer:
                    h.uc.mem_write(pointer, bytes(data) + b'\0\0')
                count = len(data) // 2 + 1 if data else 0
                h.uc.mem_write(a, struct.pack('<QII', pointer, count, count))
                result = a
            elif name == 'free':
                free(a)
            elif name == 'cpp_free':
                free(a, b)
            elif name == 'security':
                require(a == int.from_bytes(h.uc.mem_read(cookie, 8), 'little'), 'Reader stack cookie differs')
                result = reg('RAX')
            else:
                raise ValueError('Unknown reader string storage fixture')
            h.finish(result)
        return execute
    for key, address in fixtures.items():
        h.add_fixture(address, handler(key))
