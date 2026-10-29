"""Portable LoginResult constructor and nested readers with explicit primitive fixtures."""
import argparse
import json
import struct
from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec

HERE = Path(__file__).resolve().parent
ORDER = [('u32', 0x10), ('string', 0x18), ('string', 0x28), ('string', 0x38),
         ('u16', 0x48), ('u64', 0x58), ('u16', 0x60), ('u64', 0x68),
         ('string', 0x70), ('u64', 0x80), ('bool', 0x88), ('string', 0x90),
         ('bool', 0xa0), ('u64', 0xb0), ('string', 0xb8), ('string', 0xc8),
         ('bool', 0xe0), ('u64', 0xf0), ('u64', 0x100), ('u64', 0x110),
         ('u64', 0x120), ('bool', 0x128), ('raw32', 0x130), ('raw32', 0x134),
         ('bool', 0x138), ('string', 0x140), ('raw32', 0x150), ('raw32', 0x154)]
WIDTH = dict(u32=4, raw32=4, u16=2, u64=8, bool=1, string=16)


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(context, root):
    load('login-input-transfer-rules').roots('login-nested', context)
    functions = {k: int(v, 16) for k, v in context['functions'].items()}
    h = load('verify-login-input-harness').make_harness(context, context['exports'], set(functions.values()),
        leaves={int(k, 16): v for k, v in context['leaves'].items()}, root=root)
    tables = [int(context[k], 16) for k in ('packet_table', 'time_table', 'period_table')]
    for table, role in zip(tables, ('reader', 'time_reader', 'period_reader')):
        if struct.unpack_from('<Q', h.raw, h.image.offset(table - h.image.pe.base) + 0x20)[0] != functions[role]:
            raise ValueError('Nested table/reader link differs')
    getter = int(context['id_getter'], 16)
    if struct.unpack_from('<Q', h.raw, h.image.offset(tables[0] - h.image.pe.base) + 0x28)[0] != getter or h.call(getter) != 4:
        raise ValueError('Nested packet ID link differs')
    packet, archive, archive_table = [h.scratch + n for n in (0x1000, 0x2000, 0x3000)]
    state = {}

    def reg(name):
        return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def empty_string(machine):
        require(reg('RCX') == packet + 0x140, 'Constructor string destination differs')
        state['string_ctor'] += 1
        h.uc.mem_write(reg('RCX'), bytes(16))
        h.finish(reg('RCX'))

    h.add_fixture(int(context['string_constructor'], 16), empty_string)

    def primitive(kind):
        def execute(machine):
            i = len(state['seen'])
            require(i < len(ORDER) and (kind, reg('RDX') - packet) == ORDER[i] and reg('RCX') == archive,
                    'Nested primitive order/destination differs')
            state['seen'].append(i)
            if state['fail_at'] == i:
                h.finish(0)
                return
            width, offset = WIDTH[kind], ORDER[i][1]
            # Explicit archive/string semantics; actual primitive decoding is separate.
            value = bytes(16) if kind == 'string' else (state['flag'] if kind == 'bool' else i + 0x100).to_bytes(width, 'little')
            h.uc.mem_write(packet + offset, value)
            state['expected'][offset:offset + width] = value
            h.finish(state['truthy'])
        return execute

    slots = {0x28: 'u64', 0x50: 'u64', 0x58: 'u32', 0x60: 'raw32', 0x70: 'u16', 0x88: 'bool'}
    for slot, kind in slots.items():
        target = h.scratch + 0x6000 + slot
        h.uc.mem_write(archive_table + slot, struct.pack('<Q', target))
        h.add_fixture(target, primitive(kind))
    h.add_fixture(int(context['string_reader'], 16), primitive('string'))
    h.uc.mem_write(archive - 16, b'\xa5' * 16 + struct.pack('<Q', archive_table) + b'\xa6' * 16)
    archive_guard = bytes(h.uc.mem_read(archive - 16, 40))
    abi = {n: 0xfedcba9876543210 + i for i, n in enumerate(('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}
    abi.update({'XMM' + str(i): 0x123456789abcdef0fedcba9876543210 + i for i in range(6, 16)})

    def guarded_call(address, receiver):
        for name, value in abi.items():
            h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + name), value)
        result = h.call(address, receiver)
        require(all(reg(name) == value for name, value in abi.items())
                and reg('RSP') == h.scratch + 0x38008, 'Nested constructor/reader ABI differs')
        return result

    cases = []
    for poison in (0x55, 0xaa):
        for flag in (0, 255):
            for truthy in (1, 0x101):
                for fail_at in [None] + list(range(len(ORDER))):
                    state.clear()
                    state.update(seen=[], expected=bytearray([poison] * 0x160), fail_at=fail_at, truthy=truthy, flag=flag, string_ctor=0)
                    h.uc.mem_write(packet - 16, b'\xa5' * 16 + bytes(state['expected']) + b'\xa6' * 16)
                    require(guarded_call(functions['constructor'], packet) == packet, 'Constructor return differs')
                    require(state['string_ctor'] == 1, 'Constructor string call differs')
                    # Constructor writes zero/default fields, nested native vptrs and new trailing string/u64.
                    expected_ctor = bytearray([poison] * 0x160)
                    for kind, offset in ORDER:
                        expected_ctor[offset:offset + WIDTH[kind]] = bytes(WIDTH[kind])
                    for offset, table in ((0, tables[0]), (0x50, tables[1]), (0xa8, tables[1]), (0xd8, tables[2]),
                                          (0xe8, tables[1]), (0xf8, tables[1]), (0x108, tables[1]), (0x118, tables[1])):
                        expected_ctor[offset:offset + 8] = struct.pack('<Q', table)
                    for key, value in context['constructor_defaults'].items():
                        offset, at = int(key, 16), int(value, 16)
                        off = h.image.offset(at - h.image.pe.base)
                        expected_ctor[offset:offset + 4] = h.raw[off:off + 4]
                    require(bytes(h.uc.mem_read(packet, 0x160)) == expected_ctor, 'Constructor field/padding layout differs')
                    state['expected'] = expected_ctor
                    h.uc.reg_write(h.x.UC_X86_REG_RDX, archive)
                    returned = guarded_call(functions['reader'], packet) & 255
                    require(returned == int(fail_at is None), 'Nested reader return differs')
                    require(state['seen'] == list(range(len(ORDER) if fail_at is None else fail_at + 1)), 'Nested reader failure propagation differs')
                    expected = b'\xa5' * 16 + bytes(state['expected']) + b'\xa6' * 16
                    require(bytes(h.uc.mem_read(packet - 16, len(expected))) == expected, 'Nested reader fields/guards differ')
                    require(bytes(h.uc.mem_read(archive - 16, 40)) == archive_guard and all(reg(n) == v for n, v in abi.items()), 'Nested ABI/archive guards differ')
                    cases.append(dict(poison=poison, flag=flag, truthy=truthy, fail_at=fail_at,
                        operations=len(state['seen']), returned=returned, guards=True, constructor_guards=True, abi_guards=True))
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases, operations=ORDER,
                evidence=h.evidence, runtime=load('update-native-harness').runtime_inputs(),
                network_used=False, profile_activated=False, runtime_activated=False,
                native_nested_used=True, native_scalars_used=False, native_strings=False, native_buffer_construction=False,
                limits=['Actual whole packet constructor/reader, time/period constructors/readers and virtual dispatch thunk.',
                        'Archive primitives, strings and empty trailing-string constructor are explicit fixtures; wire and handler separate.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--context', type=Path, required=True)
    args = parser.parse_args()
    context = json.loads(args.context.read_bytes())
    result = verify(context, args.root)
    path = load('research-workflow').snapshot(args.root, 'portable-login-nested', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']))))
