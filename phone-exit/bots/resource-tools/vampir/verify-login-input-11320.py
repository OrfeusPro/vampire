"""Whole current LoginResult using native input scalar readers; strings explicit fixtures."""
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
    nested = load('verify-login-nested-11320')
    order, widths = nested.ORDER, nested.WIDTH
    functions = {k: int(v, 16) for k, v in context['functions'].items()}
    input_ = {k: int(v, 16) for k, v in context['input']['functions'].items()}
    if context['source_sha256'] != load('discover-login-result-11320').SOURCE or len(input_) != 7:
        raise ValueError('Explicit current scalar scope required')
    h = load('update-native-harness').make_harness(context, context['exports'], set(functions.values()) | set(input_.values()),
        leaves={int(k, 16): v for k, v in context['leaves'].items()}, root=root)
    packet, archive, buffer, heap = [h.scratch + n for n in (0x1000, 0x2000, 0x5000, 0x10000)]
    table = int(context['input']['table'], 16)
    off = h.image.offset(table - h.image.pe.base)
    for slot, role in ((0x28, 'time'), (0x50, 'u64'), (0x58, 'u32'), (0x60, 'u32'), (0x70, 'u16'), (0x88, 'bool'), (0x90, 'raw')):
        if struct.unpack_from('<Q', h.raw, off + slot)[0] != input_[role]:
            raise ValueError('Native input virtual slot differs')
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
            state['allocations'].append((pointer - 16, b'\xa5' * 16 + data + b'\xa6' * 16))
            state['heap'] += (len(data) + 63) & ~15
        descriptor = struct.pack('<QII', pointer, len(data) // 2, len(data) // 2)
        h.uc.mem_write(dest, descriptor)
        state['strings'][dest - packet] = descriptor
        h.uc.mem_write(archive + 0x30, struct.pack('<Q', buffer + pos + size))
        h.finish(1)

    h.add_fixture(int(context['string_constructor'], 16), empty)
    h.add_fixture(int(context['string_reader'], 16), string)
    abi = {n: 0xfedcba9876543210 + i for i, n in enumerate(('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}
    allowed_packet = {i for kind, at in order for i in range(at, at + widths[kind])}

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

    def read(body, poison, expected=None, consumed=None):
        state.clear()
        state.update(body=body, heap=heap, allocations=[], strings={})
        h.uc.mem_write(packet - 16, b'\xa5' * 16 + bytes([poison]) * 0x160 + b'\xa6' * 16)
        h.call(functions['constructor'], packet)
        before = bytes(h.uc.mem_read(packet, 0x160))
        h.uc.mem_write(archive - 16, b'\xa5' * 16 + bytes([poison]) * 0x40 + b'\xa6' * 16)
        require(h.call(input_['constructor'], archive) == archive, 'Native archive constructor return differs')
        require(int.from_bytes(h.uc.mem_read(archive, 8), 'little') == table, 'Native archive constructor table differs')
        h.uc.mem_write(buffer - 16, b'\xa5' * 16 + body + b'\xa6' * 16)
        h.uc.mem_write(archive + 0x20, struct.pack('<QI', buffer, len(body)))
        h.uc.mem_write(archive + 0x30, struct.pack('<Q', buffer))
        archive_before = bytes(h.uc.mem_read(archive - 16, 0x60))
        for name, value in abi.items():
            h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + name), value)
        h.uc.reg_write(h.x.UC_X86_REG_RDX, archive)
        returned = h.call(functions['reader'], packet) & 255
        after = bytes(h.uc.mem_read(packet, 0x160))
        require(all(a == b for i, (a, b) in enumerate(zip(before, after)) if i not in allowed_packet), 'Native input changed packet padding/vptrs')
        require(bytes(h.uc.mem_read(packet - 16, 16)) == b'\xa5' * 16 and bytes(h.uc.mem_read(packet + 0x160, 16)) == b'\xa6' * 16, 'Native input packet canaries differ')
        mutable = set(range(0x20, 0x24)) | set(range(0x40, 0x48))
        archive_after = bytes(h.uc.mem_read(archive - 16, 0x60))
        require(all(a == b for i, (a, b) in enumerate(zip(archive_before, archive_after)) if i not in mutable), 'Native input archive writes outside cursor/bookkeeping')
        require(bytes(h.uc.mem_read(buffer - 16, len(body) + 32)) == b'\xa5' * 16 + body + b'\xa6' * 16, 'Native input source buffer changed')
        require(all(bytes(h.uc.mem_read(at, len(data))) == data for at, data in state['allocations']), 'String fixture allocation guards differ')
        require(all(reg(n) == v for n, v in abi.items()) and reg('RSP') == h.scratch + 0x38008, 'Native input ABI differs')
        if expected is not None:
            require(returned == 1 and position() == consumed, 'Native scalar full consumption differs')
            for at, data in {**expected, **state['strings']}.items():
                require(after[at:at + len(data)] == data, 'Native scalar field projection differs')
        else:
            require(returned == 0, 'Native scalar accepted truncated body')
        return dict(size=len(body), consumed=position(), returned=returned, guards=True)

    cases = []
    for text, code, flag, poison in itertools.product(('', 'ASCII', 'Ж界🙂', 'x' * 128), (0, 16, 58, 0xffffffff), (0, 1, 2, 255), (0x55, 0xaa)):
        body, values = payload(text, code, flag)
        cases.append(read(body, poison, values, len(body)))
    truncated = []
    for text in ('', 'x', '🙂'):
        body, _ = payload(text, 0, 255)
        for size in range(len(body)):
            truncated.append(read(body[:size], 0x55))
    body, values = payload('', 0, 0)
    trailing = read(body + b'extra', 0xaa, values, len(body))
    return dict(schema=1, source_sha256=context['source_sha256'], cases=cases, truncated=truncated, trailing=trailing,
                exports=context['exports'], runtime=load('update-native-harness').runtime_inputs(), network_used=False,
                profile_activated=False, runtime_activated=False,
                limits=['Native whole packet/nested/scalar readers and input archive constructor; memcpy explicit bounded copy fixture.',
                        'Input buffer supplied explicitly after constructor. String decoding/allocation and trailing string construction remain fixtures.',
                        'No actual UTF-8 decoder, handler, network or complete runtime claim.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    context = json.loads((HERE / 'knowledge/native-contexts/login-input-11320.json').read_bytes())
    result = verify(context, args.root)
    path = load('research-workflow').snapshot(args.root, 'login-input-11320', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']), truncated=len(result['truncated']), trailing=1)))
