"""Portable whole LoginResult with native scalar/string/UTF-8 readers and buffer construction."""
import argparse
import itertools
import json
import struct
from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec

HERE = Path(__file__).resolve().parent


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(context, root):
    nested = load('verify-login-nested-context')
    order, widths = nested.ORDER, nested.WIDTH
    functions = {k: int(v, 16) for k, v in context['functions'].items()}
    input_ = {k: int(v, 16) for k, v in context['input']['functions'].items()}
    native_strings = context.get('native_strings', False)
    if native_strings is not True:
        raise ValueError('Portable Login input requires native strings and buffer construction')
    load('login-input-transfer-rules').roots('login-strings-buffer', context)
    h = load('verify-login-input-harness').make_harness(context, context['exports'], set(functions.values()) | set(input_.values()),
        leaves={int(k, 16): v for k, v in context['leaves'].items()}, root=root)
    packet, archive, buffer, heap = [h.scratch + n for n in (0x1000, 0x2000, 0x5000, 0x10000)]
    table = int(context['input']['table'], 16)
    off = h.image.offset(table - h.image.pe.base)
    for slot, role in ((0x28, 'time'), (0x50, 'u64'), (0x58, 'u32'), (0x60, 'u32'), (0x70, 'u16'), (0x88, 'bool'), (0x90, 'raw')):
        if struct.unpack_from('<Q', h.raw, off + slot)[0] != input_[role]:
            raise ValueError('Native input virtual slot differs')
    if native_strings:
        require_table = bytes.fromhex(context['input']['table_bytes'])
        if h.raw[off:off + len(require_table)] != require_table or struct.unpack_from('<Q', h.raw, off + 0x30)[0] != input_['std_string']:
            raise ValueError('Native input string table differs')
        native, bindings = load('build-native-entry-code'), load('update-bindings')
        calls = {hex(r['address']): {'target': hex(r['direct_target']) if r['direct_target'] is not None else r['operands']}
                 for at in input_.values() for r in bindings.rows(native, h.image, at) if r['call']}
        if calls != context['input']['call_sites']:
            raise ValueError('Native input string call sites differ')
    state = {}

    def reg(name):
        return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def position():
        value = int.from_bytes(h.uc.mem_read(archive + 0x30, 8), 'little') - buffer
        require(0 <= value <= len(state['body']), 'Native input cursor bound')
        return value

    def empty(machine):
        require(reg('RCX') == packet + 0x140, 'Native input constructor string bound')
        h.uc.mem_write(reg('RCX'), bytes(16))
        h.finish(reg('RCX'))

    def string(machine):
        dest = reg('RDX')
        require(reg('RCX') == archive and dest - packet in [off for kind, off in order if kind == 'string'], 'String fixture destination bound')
        pos = position()
        if pos + 2 > len(state['body']):
            h.finish(0)
            return
        size = int.from_bytes(state['body'][pos:pos + 2], 'little')
        pos += 2
        h.uc.mem_write(archive + 0x30, struct.pack('<Q', buffer + pos))
        if pos + size > len(state['body']):
            h.finish(0)
            return
        text = state['body'][pos:pos + size].decode('utf-8')
        data = text.encode('utf-16le') + b'\0\0' if text else b''
        pointer = state['heap'] + 16 if data else 0
        require(len(data) <= 1024 and state['heap'] + len(data) + 32 < h.scratch + 0x30000, 'String fixture allocation bound')
        if data:
            h.uc.mem_write(pointer - 16, b'\xa5' * 16 + data + b'\xa6' * 16)
            state['fixture_allocations'].append((pointer - 16, b'\xa5' * 16 + data + b'\xa6' * 16))
            state['heap'] += (len(data) + 63) & ~15
        descriptor = struct.pack('<QII', pointer, len(data) // 2, len(data) // 2)
        h.uc.mem_write(dest, descriptor)
        state['strings'][dest - packet] = descriptor
        h.uc.mem_write(archive + 0x30, struct.pack('<Q', buffer + pos + size))
        h.finish(1)

    h.add_fixture(int(context['string_constructor'], 16), empty)
    if native_strings:
        load('login-result-string-fixtures').install(load, h, context['input'], state, packet,
            [at for kind, at in order if kind == 'string'])
    else:
        h.add_fixture(int(context['string_reader'], 16), string)
    abi = {n: 0xfedcba9876543210 + i for i, n in enumerate(('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}
    abi.update({'XMM' + str(i): 0x123456789abcdef0fedcba9876543210 + i for i in range(6, 16)})
    allowed_packet = {i for kind, at in order for i in range(at, at + widths[kind])}

    def guarded_call(address, receiver, budget=30000):
        for name, value in abi.items():
            h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + name), value)
        result = h.call(address, receiver, budget=budget)
        require(all(reg(name) == value for name, value in abi.items())
                and reg('RSP') == h.scratch + 0x38008, 'Native input constructor/reader ABI differs')
        return result

    def payload(text, code, flag):
        body, values = [], {}
        for i, (kind, at) in enumerate(order):
            if kind == 'string':
                encoded = text.encode('utf-8')
                body.append(struct.pack('<H', len(encoded)) + encoded)
            else:
                value = flag if kind == 'bool' else code if at == 0x10 else ((0xfedcba9876543210 + i) & ((1 << (8 * widths[kind])) - 1))
                body.append(value.to_bytes(widths[kind], 'little'))
                values[at] = (int(value != 0) if kind == 'bool' else value).to_bytes(widths[kind], 'little')
        return b''.join(body), values

    def read(body, poison, expected=None, consumed=None, text=None, observe=False):
        require(len(body) <= 4096, 'Input body fixture bound')
        state.clear()
        state.update(body=body, heap=heap, allocations={}, fixture_allocations=[], strings={})
        if native_strings:
            h.uc.mem_write(h.scratch + 0x30000, bytes(0x8000))
        h.uc.mem_write(packet - 16, b'\xa5' * 16 + bytes([poison]) * 0x160 + b'\xa6' * 16)
        require(guarded_call(functions['constructor'], packet) == packet, 'Native packet constructor return differs')
        before = bytes(h.uc.mem_read(packet, 0x160))
        h.uc.mem_write(archive - 16, b'\xa5' * 16 + bytes([poison]) * 0x40 + b'\xa6' * 16)
        h.uc.mem_write(buffer - 16, b'\xa5' * 16 + body + b'\xa6' * 16)
        if native_strings:
            h.uc.reg_write(h.x.UC_X86_REG_RDX, buffer)
            h.uc.reg_write(h.x.UC_X86_REG_R8, len(body))
            h.uc.reg_write(h.x.UC_X86_REG_R9, 1)
            h.uc.mem_write(h.scratch + 0x38028, struct.pack('<Q', 0))
        require(guarded_call(input_['constructor'], archive) == archive, 'Native archive constructor return differs')
        require(int.from_bytes(h.uc.mem_read(archive, 8), 'little') == table, 'Native archive constructor table differs')
        if native_strings:
            require(bytes(h.uc.mem_read(archive + 0x20, 12)) == struct.pack('<QI', buffer, len(body))
                    and position() == 0, 'Native buffer construction differs')
        else:
            h.uc.mem_write(archive + 0x20, struct.pack('<QI', buffer, len(body)))
            h.uc.mem_write(archive + 0x30, struct.pack('<Q', buffer))
        archive_before = bytes(h.uc.mem_read(archive - 16, 0x60))
        h.uc.reg_write(h.x.UC_X86_REG_RDX, archive)
        # Same bounded instruction allowance as the reviewed string integration
        # in verify-login-result-context; scalar-only scenarios keep 30000.
        returned = guarded_call(functions['reader'], packet, budget=1000000 if native_strings else 30000) & 255
        after = bytes(h.uc.mem_read(packet, 0x160))
        require(all(a == b for i, (a, b) in enumerate(zip(before, after)) if i not in allowed_packet), 'Native input changed packet padding/vptrs')
        require(bytes(h.uc.mem_read(packet - 16, 16)) == b'\xa5' * 16 and bytes(h.uc.mem_read(packet + 0x160, 16)) == b'\xa6' * 16, 'Native input packet canaries differ')
        mutable = set(range(0x20, 0x24)) | set(range(0x40, 0x48))
        archive_after = bytes(h.uc.mem_read(archive - 16, 0x60))
        require(all(a == b for i, (a, b) in enumerate(zip(archive_before, archive_after)) if i not in mutable), 'Native input archive writes outside cursor/bookkeeping')
        require(bytes(h.uc.mem_read(buffer - 16, len(body) + 32)) == b'\xa5' * 16 + body + b'\xa6' * 16, 'Native input source buffer changed')
        require(all(bytes(h.uc.mem_read(at, len(data))) == data for at, data in state['fixture_allocations']), 'String fixture allocation guards differ')
        for pointer, size in state['allocations'].items():
            require(bytes(h.uc.mem_read(pointer - 16, 16)) == b'\xa5' * 16 and bytes(h.uc.mem_read(pointer + size, 16)) == b'\xa6' * 16,
                    'Native string allocation guards differ')
        require(all(reg(n) == v for n, v in abi.items()) and reg('RSP') == h.scratch + 0x38008, 'Native input ABI differs')
        if expected is not None:
            require(returned == 1 and position() == consumed, 'Native scalar full consumption differs')
            for at, data in {**expected, **state['strings']}.items():
                require(after[at:at + len(data)] == data, 'Native scalar field projection differs')
            if native_strings:
                for kind, at in order:
                    if kind != 'string':
                        continue
                    pointer, count, capacity = struct.unpack_from('<QII', after, at)
                    require(count == capacity and count <= 1024, 'Native string descriptor differs')
                    value = bytes(h.uc.mem_read(pointer, count * 2))[:-2].decode('utf-16le') if count else ''
                    require(value == text, 'Native UTF8/UTF16 projection differs')
        elif not observe:
            require(returned == 0, 'Native scalar accepted truncated body')
        case = dict(size=len(body), consumed=position(), returned=returned, guards=True,
                    constructor_guards=True, abi_guards=True)
        if expected is not None:
            case['scalar_values'] = {hex(at): after[at:at + len(data)].hex() for at, data in expected.items()}
        if native_strings:
            pointer, count, capacity = struct.unpack_from('<QII', after, 0x18)
            require(count == capacity and count <= 1024, 'Native first-string descriptor bound')
            case['first_string_utf16'] = bytes(h.uc.mem_read(pointer, count * 2)).hex() if count else ''
        return case

    cases = []
    for text, code, flag, poison in itertools.product(('', 'ASCII', 'Ж界🙂', 'x' * 128), (0, 16, 58, 0xffffffff), (0, 1, 2, 255), (0x55, 0xaa)):
        body, values = payload(text, code, flag)
        cases.append(dict(read(body, poison, values, len(body), text), text=text, code=code, flag=flag, poison=poison))
    truncated = []
    for text in ('', 'x', '🙂'):
        body, _ = payload(text, 0, 255)
        for size in range(len(body)):
            truncated.append(dict(read(body[:size], 0x55), text=text, code=0, flag=255, poison=0x55))
    body, values = payload('', 0, 0)
    trailing = dict(read(body + b'extra', 0xaa, values, len(body), ''), text='', code=0, flag=0, poison=0xaa)
    boundaries, special = [], []
    if native_strings:
        for size in (15, 16, 127, 128):
            body, values = payload('x' * size, 0, 255)
            boundaries.append(dict(read(body, 0xaa, values, len(body), 'x' * size), text='x' * size,
                                   code=0, flag=255, poison=0xaa))
        minimal, _ = payload('', 0, 0)
        for data in (b'\xff', b'\xc0\xaf', b'\xed\xa0\x80', b'\xf4\x90\x80\x80', b'a\0b', b'\xef\xbf\xbe'):
            body = minimal[:4] + struct.pack('<H', len(data)) + data + minimal[6:]
            case = read(body, 0x55, observe=True)
            case.update(input_hex=data.hex(), code=0, flag=0, poison=0x55)
            special.append(case)
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases, truncated=truncated, trailing=trailing,
                exports=context['exports'], runtime=load('update-native-harness').runtime_inputs(), network_used=False,
                profile_activated=False, runtime_activated=False,
                native_strings=native_strings, native_buffer_construction=native_strings,
                native_nested_used=True, native_scalars_used=True, operations=order,
                boundaries=boundaries, special=special,
                limits=(['Native packet/nested/scalar/string/UTF8 readers and buffer construction; bounded memcpy and string storage/assignment/growth/free/security remain fixtures.',
                         'Empty trailing string construction fixture; handler/network/runtime separate.'] if native_strings else
                        ['Native whole packet/nested/scalar readers and input archive constructor; memcpy explicit bounded copy fixture.',
                        'Input buffer supplied explicitly after constructor. String decoding/allocation and trailing string construction remain fixtures.',
                        'No actual UTF-8 decoder, handler, network or complete runtime claim.']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--context', type=Path, required=True)
    args = parser.parse_args()
    context = json.loads(args.context.read_bytes())
    result = verify(context, args.root)
    path = load('research-workflow').snapshot(args.root, 'portable-login-strings-buffer', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']), truncated=len(result['truncated']), trailing=1,
                         boundaries=len(result['boundaries']), special=result['special'])))
