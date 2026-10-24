"""Current ID 102 envelope/vector on native input IO; record boundary remains explicit."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RecordBoundary(Exception):
    pass


def verify(context, root):
    functions = {name: int(at, 16) for name, at in context['functions'].items()}
    h = load('update-native-harness').make_harness(context, context['exports'], set(functions.values()),
        leaves={int(at, 16): code for at, code in context['leaves'].items()}, root=root)
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    calls = {name: {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
                   for r in bindings.rows(native, h.image, at) if r['call']} for name, at in functions.items()}
    if calls != context['call_sites']:
        raise ValueError('Character list call sites differ')

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def data(at, size):
        off = h.image.offset(at - h.image.pe.base)
        return h.raw[off:off + size]

    b = {name: int(at, 16) for name, at in context['bindings'].items()}
    for block in context['blocks']:
        payload = bytes.fromhex(block['bytes'])
        require(data(int(block['address'], 16), len(payload)) == payload
                and hashlib.sha256(payload).hexdigest() == block['sha256'], 'Character list source block differs')
    for at, offset, expected in ((b['packet_table'], 0x20, functions['reader']),
                                 (b['packet_table'], 0x28, b['id_getter']),
                                 (b['archive_table'], 0x18, functions['vector']),
                                 (b['vector_table'], 8, functions['resize']),
                                 (b['vector_table'], 0x10, functions['record_thunk'])):
        require(struct.unpack('<Q', data(at + offset, 8))[0] == expected, 'Character list table link differs')
    require(h.call(b['id_getter']) == 102, 'Character list ID differs')
    packet, archive, buffer, items = [h.scratch + n for n in (0x1000, 0x2000, 0x4000, 0x8000)]
    uc, x = h.uc, h.x
    current, operations, events = {}, [], []

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def put(at, fmt, *values):
        uc.mem_write(at, struct.pack('<' + fmt, *values))

    def position():
        value = int.from_bytes(uc.mem_read(archive + 0x30, 8), 'little') - buffer
        require(0 <= value <= len(current['body']), 'Character list cursor outside input')
        return value

    def fixture(machine, name):
        if name == 'clear':
            require(reg('RDX') == 0, 'Character list cleanup count differs')
        elif name == 'allocate':
            require(reg('RCX') == packet + 0x18, 'Character list allocation receiver differs')
            count = reg('RDX') & 0xffffffff
            if count > 4:
                raise RecordBoundary('count_budget')
            put(packet + 0x18, 'Q', items if count else 0); put(packet + 0x24, 'I', count)
            events.append(dict(action='allocate', count=count))
        elif name == 'record_constructor':
            events.append(dict(action='record_boundary'))
            raise RecordBoundary('record_reader_not_ported')
        else:
            raise ValueError('Unsupported character list fixture')
        h.finish()
    protected = set(functions.values()) | {int(at, 16) for at in context['leaves']}
    for name, at in context['fixtures'].items():
        require(int(at, 16) not in protected, 'Character list fixture overlaps native root')
        h.add_fixture(int(at, 16), lambda machine, name=name: fixture(machine, name))
    import unicorn
    scalar = {functions[key]: key for key in ('u16', 'u32', 'u64')}
    def entered(machine, at, size, unused):
        if at in scalar:
            require(reg('RCX') == archive, 'Character list scalar receiver differs')
            operations.append(dict(kind=scalar[at], consumed=position()))
            if len(operations) - 1 == current['fail_at']:
                h.finish(0)
    uc.hook_add(unicorn.UC_HOOK_CODE, entered)
    sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
    from vampir_core.character_list import decode_character_list, preferred_character_index

    def run(body, fail_at=None, poison=0x55):
        current.update(body=body, fail_at=fail_at); operations.clear(); events.clear()
        uc.mem_write(packet - 16, b'\xa5' * 16 + bytes([poison]) * 0x48 + b'\xa6' * 16)
        require(h.call(b['packet_constructor'], packet) == packet, 'Character list constructor return differs')
        require(int.from_bytes(uc.mem_read(packet, 8), 'little') == b['packet_table'], 'Character list constructor table differs')
        uc.mem_write(archive - 16, b'\xa7' * 16 + bytes([poison]) * 0x40 + b'\xa8' * 16)
        uc.mem_write(buffer - 16, b'\xa9' * 16 + body + b'\xaa' * 16)
        uc.reg_write(x.UC_X86_REG_RDX, buffer); uc.reg_write(x.UC_X86_REG_R8, len(body)); uc.reg_write(x.UC_X86_REG_R9, 1)
        put(h.scratch + 0x38028, 'Q', 0)
        h.call(functions['archive_constructor'], archive)
        input_before = bytes(uc.mem_read(archive - 16, 0x60))
        before = bytes(uc.mem_read(packet, 0x48))
        abi = {name: 0x1234567800000000 + i for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
        for name, value in abi.items():
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
        uc.reg_write(x.UC_X86_REG_RDX, archive)
        try:
            returned = h.call(functions['reader'], packet) & 255
        except RecordBoundary as error:
            require(int.from_bytes(uc.mem_read(packet + 0x20, 4), 'little') == 0, 'Boundary returned partial records')
            return dict(status=str(error), consumed=position(), accepted=False, events=events.copy())
        require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.scratch + 0x38008,
                'Character list ABI differs')
        after = bytes(uc.mem_read(packet, 0x48))
        mutable = set(range(0x10, 0x48)) - set(range(0x34, 0x38))
        require(all(a == z for i, (a, z) in enumerate(zip(before, after)) if i not in mutable)
                and bytes(uc.mem_read(packet - 16, 16)) == b'\xa5' * 16
                and bytes(uc.mem_read(packet + 0x48, 16)) == b'\xa6' * 16, 'Character list object guards differ')
        input_after = bytes(uc.mem_read(archive - 16, 0x60))
        mutable_input = set(range(0x20, 0x24)) | set(range(0x40, 0x48))
        require(all(a == z for i, (a, z) in enumerate(zip(input_before, input_after)) if i not in mutable_input)
                and bytes(uc.mem_read(buffer - 16, len(body) + 32)) == b'\xa9' * 16 + body + b'\xaa' * 16,
                'Character list input buffer/guards differ')
        code, raw14 = struct.unpack_from('<II', after, 0x10)
        tail = tuple(int.from_bytes(after[a:a + n], 'little') for a, n in ((0x28, 8), (0x30, 4), (0x38, 8), (0x40, 8)))
        count = int.from_bytes(after[0x20:0x24], 'little')
        if returned:
            decoded = decode_character_list(body[:38], max_payload_size=4096, max_characters=4, max_extension_items=32)
            require((decoded.result_code, decoded.raw14, len(decoded.records), decoded.tail) == (code, raw14, count, tail)
                    and preferred_character_index(decoded) is None and position() == 38,
                    'Character list runtime envelope differs')
        return dict(status='complete' if returned else 'rejected', accepted=bool(returned), consumed=position(),
                    result_code=code, count=count, tail=tail, operations=operations.copy())

    cases = []
    for code in (0, 1, 58, 0xffffffff):
        for raw in (0, 0x80000000, 0xffffffff):
            for poison in (0x55, 0xaa):
                body = struct.pack('<IIHQIQQ', code, raw, 0, 0xffffffffffffffff, 0x80000000, 123456789, 987654321)
                result = run(body, poison=poison); require(result['accepted'], 'Character list full envelope rejected'); cases.append(result)
    body = struct.pack('<IIHQIQQ', 0, 123, 0, 456, 789, 123456, 654321)
    truncated = [run(body[:size]) for size in range(38)]
    failures = [run(body, fail_at=i) for i in range(7)]
    require(all(not r['accepted'] for r in truncated + failures), 'Character list incomplete envelope accepted')
    require(all(len(r['operations']) == i + 1 for i, r in enumerate(failures)), 'Character list did not stop on read failure')
    nonempty = [run(struct.pack('<IIH', 0, 123, count) + bytes(64)) for count in (1, 2, 4, 65535)]
    require(all(not r['accepted'] and r['status'] in ('count_budget', 'record_reader_not_ported') for r in nonempty),
            'Character list nonempty boundary became accepted empty list')
    extra = run(body + b'extra')
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases,
                truncated=truncated, failures=failures, nonempty=nonempty, extra=extra, evidence=h.evidence,
                network_used=False, profile_activated=False,
                limits=['Empty-list envelope, scalar/raw input, count/vector and resize execute; allocation/cleanup are bounded fixtures.',
                        'Nonempty input stops explicitly at CharacterRecord constructor or local count budget, never accepted as empty.',
                        'Record fields/extensions, registration, result handler, network and creation are not verified here.',
                        'Native accepts trailing bytes; portable decoder exact-size policy is unchanged. No profile promotion.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    result = verify(json.loads(args.context.read_text('utf-8')), args.root)
    result.update(context_sha256=hashlib.sha256(args.context.read_bytes()).hexdigest(), tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    path = load('research-workflow').snapshot(args.root, 'native-character-list-envelope-checks', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']), truncated=len(result['truncated']), failures=len(result['failures']))))
