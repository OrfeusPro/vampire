"""Whole current CPU formatter/getters/native trim; initialized CPU cache and CRT fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from importlib.util import spec_from_file_location, module_from_spec

HERE = Path(__file__).resolve().parent


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec); spec.loader.exec_module(module)
    return module


def verify(context, root):
    functions = {int(value, 16) for value in context['functions'].values()}
    h = load('update-native-harness').make_harness(context, context['exports'], functions, root=root)
    native = load('build-native-entry-code'); rows = load('update-bindings').rows
    calls = {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
             for at in functions for r in rows(native, h.image, at) if r['call']}
    if calls != context['call_sites']: raise ValueError('CPU helper call sites differ')
    slot = int(context['space_slot'], 16)
    if load('build-object-zero-init-code').import_at(h.raw, h.image, slot)['name'] != 'iswspace':
        raise ValueError('CPU whitespace import differs')
    fixture = {key: int(value, 16) for key, value in context['fixtures'].items()}
    offset = h.image.offset(fixture['move'] - h.image.pe.base)
    if h.raw[offset:offset + 2] != b'\xff\x25': raise ValueError('CPU memmove thunk differs')
    move_slot = fixture['move'] + 6 + struct.unpack_from('<i', h.raw, offset + 2)[0]
    if load('build-object-zero-init-code').import_at(h.raw, h.image, move_slot)['name'] != 'memmove':
        raise ValueError('CPU memmove import differs')
    vendor, brand = [int(context[key], 16) for key in ('vendor', 'brand')]
    output = h.scratch + 0x1000
    state = {}

    def reg(name): return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))
    def literal(pointer, wide=True):
        result = bytearray(); width = 2 if wide else 1
        for i in range(256):
            item = bytes(h.uc.mem_read(pointer + i * width, width))
            if item == bytes(width): return result.decode('utf-16le' if wide else 'ascii')
            result.extend(item)
        raise ValueError('CPU text fixture bound')
    def text(at):
        pointer, count, capacity = struct.unpack('<QII', h.uc.mem_read(at, 16))
        if not 0 <= count <= capacity <= 256: raise ValueError('CPU FString bound')
        return literal(pointer) if count else ''
    def make(at, value):
        if not value and not state['allocate_empty']:
            h.uc.mem_write(at, b'\0' * 16); return at
        data = (value + '\0').encode('utf-16le'); pointer = state['heap'] + 16
        state['heap'] += (len(data) + 63) & ~15
        if state['heap'] > h.scratch + 0x30000: raise ValueError('CPU allocation budget')
        h.uc.mem_write(pointer - 16, b'\xa5' * 16 + data + b'\xa6' * 16)
        state['allocations'][pointer] = len(data)
        h.uc.mem_write(at, struct.pack('<QII', pointer, len(data) // 2, len(data) // 2))
        return at
    def hook(name):
        def execute(machine):
            a, b, c, d = [reg(key) for key in ('RCX', 'RDX', 'R8', 'R9')]
            result = 0
            if name == 'ascii':
                if b not in (vendor, brand): raise ValueError('CPU cache pointer differs')
                result = make(a, literal(b, False))
            elif name == 'wide':
                if literal(b) != 'Unknown': raise ValueError('CPU compiled third input differs')
                result = make(a, 'Unknown')
            elif name == 'space':
                state['space_calls'] += 1
                result = int(a in (9, 10, 11, 12, 13, 32))
            elif name == 'move':
                if c > 512 or not all(h.scratch <= p <= h.scratch + 0x40000 - c for p in (a, b)):
                    raise ValueError('CPU memmove bound')
                h.uc.mem_write(a, bytes(h.uc.mem_read(b, c))); result = a
            elif name == 'shrink':
                text(a)  # Native methods already changed count and moved the NUL.
            elif name == 'free':
                if a not in state['allocations'] or a in state['freed']: raise ValueError('CPU unowned/repeated free')
                state['freed'].add(a)
            elif name == 'format':
                if a != output or literal(b) != '%s|%s': raise ValueError('Unexpected CPU format branch')
                values = [literal(c), literal(d)]; state['format_arguments'] = values
                result = make(a, '|'.join(values))
            else: raise ValueError('Unknown CPU fixture')
            h.finish(result)
        return execute
    for key, address in fixture.items(): h.add_fixture(address, hook(key))
    h.uc.mem_write(slot, struct.pack('<Q', fixture['space']))
    profiles = [('GenuineIntel', 'Fixture CPU'), ('AuthenticAMD', '  Fixture CPU  '),
                (' Vendor ', '\t\r\nSpaced CPU\t\r\n'), ('', ''), ('GenuineIntel', ' \t\r\n\v\f'),
                ('GenuineIntel', 'Unknown'), ('GenuineIntel', 'A|B|C'), ('GenuineIntel', 'A\0Hidden'),
                ('GenuineIntel', 'X' * 63)]
    abi = {key: 0xfedcba9876543200 + i for i, key in enumerate(('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}
    cases = []
    for poison in (0, 0x55, 0xaa, 0xff):
        for first, second in profiles:
            for allocated in (False, True):
                state.update(heap=h.scratch + 0x10000, allocations={}, freed=set(), space_calls=0,
                             allocate_empty=allocated, format_arguments=None)
                for pointer, value, size in ((vendor, first, 13), (brand, second, 64)):
                    h.uc.mem_write(pointer, (value + '\0').encode('ascii').ljust(size, b'\0'))
                before = bytes(h.uc.mem_read(vendor, 77))
                h.uc.mem_write(output - 16, b'\xa5' * 16 + bytes((poison,)) * 16 + b'\xa6' * 16)
                for key, value in abi.items(): h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + key), value)
                if h.call(int(context['functions']['formatter'], 16), output) != output:
                    raise ValueError('CPU formatter result pointer differs')
                values = [s.split('\0')[0].strip(' \t\r\n\v\f') for s in (first, second)]
                if text(output) != '|'.join(values) or state['format_arguments'] != values:
                    raise ValueError('CPU formatted result differs')
                if bytes(h.uc.mem_read(vendor, 77)) != before: raise ValueError('CPU cache modified')
                for pointer, size in state['allocations'].items():
                    if bytes(h.uc.mem_read(pointer - 16, 16)) != b'\xa5' * 16 or bytes(h.uc.mem_read(pointer + size, 16)) != b'\xa6' * 16:
                        raise ValueError('CPU allocation canary differs')
                pointer = int.from_bytes(h.uc.mem_read(output, 8), 'little')
                if set(state['allocations']) - state['freed'] != {pointer}:
                    raise ValueError('CPU temporary allocation leaked')
                if (bytes(h.uc.mem_read(output - 16, 16)) != b'\xa5' * 16 or bytes(h.uc.mem_read(output + 16, 16)) != b'\xa6' * 16
                        or any(reg(key) != value for key, value in abi.items()) or reg('RSP') != h.scratch + 0x38008):
                    raise ValueError('CPU output guards/ABI differ')
                cases.append(dict(poison=poison, vendor=first, brand=second, allocate_empty=allocated,
                                  result=text(output), space_calls=state['space_calls']))
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases,
        evidence=h.evidence, network_used=False, host_identity_read=False, profile_activated=False,
        runtime=load('update-native-harness').runtime_inputs(), limits=[
            'Whole formatter, both getters, trim wrapper/start/end. CPU ASCII buffers are initialized synthetic state, not CPUID initialization.',
            'ASCII/wide FString constructors, allocator/free, memmove, shrink, printf and ASCII iswspace classification remain fixtures.',
            'Compiled third input is Unknown: actual two-part branch executed; alternate third-input branches not claimed.',
            'No general CRT/Unicode/locale behavior, whole Version/Login integration, host fingerprint, auth or sockets.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args(); report = verify(json.loads(args.context.read_text('utf-8')), args.root)
    report['context_sha256'] = hashlib.sha256(args.context.read_bytes()).hexdigest()
    report['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    target = load('research-workflow').snapshot(args.root, 'native-version-cpu-checks', report)
    print(json.dumps(dict(report=str(target), cases=len(report['cases']))))
