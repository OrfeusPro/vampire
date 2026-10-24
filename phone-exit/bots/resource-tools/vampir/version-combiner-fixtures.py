"""Checked boundaries for native FString combiners; allocation/copy fixtures only."""
import struct
from pathlib import Path


def install(load, h, context, state, allocate, release, reg):
    if context['source_sha256'] != h.sha or Path(context['source']).resolve() != h.source.resolve():
        raise ValueError('Combiner source differs')
    native = load('build-native-entry-code'); rows = load('update-bindings').rows
    calls = {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
             for at in context['functions'].values() for r in rows(native, h.image, int(at, 16)) if r['call']}
    if calls != context['call_sites']: raise ValueError('Combiner call sites differ')
    fixtures = {key: int(value, 16) for key, value in context['fixtures'].items()}

    def reallocate(descriptor, size):
        if not 0 <= size <= 1024: raise ValueError('Combiner allocation bound')
        pointer, count, capacity = struct.unpack('<QII', h.uc.mem_read(descriptor, 16))
        if pointer:
            if pointer not in state['allocations'] or pointer in state['freed']:
                raise ValueError('Combiner reallocation ownership differs')
            previous = bytes(h.uc.mem_read(pointer, min(state['allocations'][pointer], size * 2)))
            release(pointer)
        else: previous = b''
        pointer = allocate(size * 2) if size else 0
        if previous: h.uc.mem_write(pointer, previous)
        h.uc.mem_write(descriptor, struct.pack('<QII', pointer, count, size))

    def handler(name):
        def execute(machine):
            a, b, c = [reg(key) for key in ('RCX', 'RDX', 'R8')]; result = 0
            state.setdefault('combiner_events', []).append(name)
            if name == 'copy':
                if c > 2048 or not all(h.scratch <= p <= h.scratch + 0x40000 - c for p in (a, b)):
                    raise ValueError('Combiner internal copy bound')
                if c: h.uc.mem_write(a, bytes(h.uc.mem_read(b, c)))
                result = a
            elif name == 'resize': reallocate(a, b)
            elif name == 'append_grow':
                count = int.from_bytes(h.uc.mem_read(a + 8, 4), 'little'); reallocate(a, count)
            elif name == 'quantize':
                # Only RCX byte count and RDX alignment belong to this ABI.
                if b != 2 or not 0 <= a <= 2048: raise ValueError('Combiner size quantization differs')
                result = (a + 15) & ~15
            elif name == 'allocator':
                stack = reg('RSP')
                if c > 1024 or reg('R9') != 2 or int.from_bytes(h.uc.mem_read(stack + 0x28, 4), 'little') != 2:
                    raise ValueError('Combiner allocator arguments differ')
                reallocate(a, c)
            elif name == 'overflow': raise ValueError('Native combiner length overflow')
            else: raise ValueError('Unknown combiner fixture')
            h.finish(result)
        return execute
    for key, address in fixtures.items(): h.add_fixture(address, handler(key))
