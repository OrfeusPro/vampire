"""Current CharacterRecord with native input/strings and explicit extension boundaries."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
STRINGS = (0x18, 0x50, 0xc8)
U64 = (8, 0x28, 0x40, 0x48, 0x80, 0x88, 0x98, 0xa0, 0xa8, 0xf0, 0xf8, 0x100)


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def body_for(text='', enum=0, appearance=0, flag=0, seed=0, appearance_count=0, optional=0):
    texts = [text, text + '-second' if text else '', text + '-look' if text else '']
    strings = [struct.pack('<H', len(t.encode('utf-8'))) + t.encode('utf-8') for t in texts]
    q = [struct.pack('<Q', (seed + i * 0x123456789abcdef) & 0xffffffffffffffff) for i in range(12)]
    i = [struct.pack('<I', (seed + n * 0x1020304) & 0xffffffff) for n in (1, 2)]
    quad = struct.pack('<4H', 0, 0x7fff, 0x8000, 0xffff)
    return (q[0] + i[0] + strings[0] + q[1] + i[1] + q[2] + q[3] + strings[1]
            + bytes([enum]) + quad + b''.join(q[4:9]) + bytes([appearance]) + bytes(range(11, 20))
            + strings[2] + bytes([flag, 0xfe]) + struct.pack('<H', appearance_count)
            + b''.join(q[9:]) + bytes([flag, optional]))


class ExtensionBoundary(Exception):
    pass


def verify(context, root):
    functions = {name: int(at, 16) for name, at in context['functions'].items()}
    input_ = context['native_input']
    if input_['source_sha256'] != context['source_sha256']:
        raise ValueError('CharacterRecord input source differs')
    inputs = {name: int(at, 16) for name, at in input_['functions'].items()}
    roots = set(functions.values()) | set(inputs.values())
    exports = dict(input_['exports'], **context['exports'])
    leaves = {int(at, 16): spec['bytes'] for at, spec in input_['leaves'].items()}
    leaves.update({int(at, 16): code for at, code in context['leaves'].items()})
    h = load('update-native-harness').make_harness(context, exports, roots, leaves=leaves, root=root)
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    calls = {name: {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
                   for r in bindings.rows(native, h.image, at) if r['call']} for name, at in functions.items()}
    if calls != context['call_sites']:
        raise ValueError('CharacterRecord call sites differ')

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def data(at, size):
        off = h.image.offset(at - h.image.pe.base)
        return h.raw[off:off + size]

    for block in context['blocks']:
        payload = bytes.fromhex(block['bytes'])
        require(data(int(block['address'], 16), len(payload)) == payload
                and hashlib.sha256(payload).hexdigest() == block['sha256'], 'CharacterRecord table differs')
    b = {name: int(at, 16) for name, at in context['bindings'].items()}
    for table, reader in ((b['record_table'], functions['reader']), (b['time_table'], functions['time_reader']),
                          (b['quad_table'], functions['u16_quad_reader']), (b['appearance_table'], functions['appearance_reader']),
                          (b['optional_table'], functions['optional_reader'])):
        require(struct.unpack('<Q', data(table + 0x20, 8))[0] == reader, 'CharacterRecord reader table link differs')
    # Pin input table and the entire declared numeric/string callee inventory too.
    actual_input = {hex(r['address']): {'target': hex(r['direct_target']) if r['direct_target'] is not None else r['operands']}
                    for at in inputs.values() for r in bindings.rows(native, h.image, at) if r['call']}
    require(actual_input == input_['call_sites'], 'CharacterRecord input callees differ')
    require(data(int(input_['table'], 16), len(bytes.fromhex(input_['table_bytes']))) == bytes.fromhex(input_['table_bytes']),
            'CharacterRecord input table differs')
    packet, archive, buffer = [h.scratch + n for n in (0x1000, 0x2000, 0x5000)]
    uc, x = h.uc, h.x
    state, operations = {}, []
    load('login-result-string-fixtures').install(load, h, input_, state, packet, STRINGS)

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def put(at, fmt, *values):
        uc.mem_write(at, struct.pack('<' + fmt, *values))

    def position():
        at = int.from_bytes(uc.mem_read(archive + 0x30, 8), 'little') - buffer
        require(0 <= at <= len(state['body']), 'CharacterRecord input cursor outside buffer')
        return at

    def fixture(machine, name):
        if name == 'appearance_clear':
            require(reg('RDX') == 0, 'CharacterRecord initial appearance storage not empty')
        elif name == 'appearance_resize':
            require(reg('RDX') == packet + 0xe0, 'CharacterRecord appearance vector receiver differs')
            if reg('R8') & 0xffff:
                raise ExtensionBoundary('appearance_items_not_ported')
        elif name == 'appearance_allocate':
            raise ValueError('Unexpected allocation for empty appearance fixture')
        elif name == 'optional_storage':
            raise ExtensionBoundary('optional_items_not_ported')
        else:
            raise ValueError('Unsupported CharacterRecord fixture')
        h.finish()
    protected = roots | set(leaves)
    for name, at in context['fixtures'].items():
        require(int(at, 16) not in protected, 'CharacterRecord fixture overlaps native code')
        h.add_fixture(int(at, 16), lambda machine, name=name: fixture(machine, name))
    import unicorn
    primitives = {inputs[name]: name for name in ('u16', 'u32', 'u64', 'bool', 'raw')}
    def entered(machine, at, size, unused):
        if at in primitives:
            require(reg('RCX') == archive, 'CharacterRecord primitive receiver differs')
            operations.append(dict(kind=primitives[at], consumed=position()))
            if len(operations) - 1 == state['fail_at']:
                h.finish(0)
    uc.hook_add(unicorn.UC_HOOK_CODE, entered)
    sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
    from vampir_core.character_list import decode_character_list

    def values():
        result = dict(strings=[], u32=[], u16=[], u64=[], enum60=0, appearance=[], appearance_flags=[], flag108=False)
        for off in STRINGS:
            ptr, size, cap = struct.unpack('<QII', bytes(uc.mem_read(packet + off, 16)))
            require(0 <= size == cap <= 2048, 'CharacterRecord string descriptor differs')
            result['strings'].append(bytes(uc.mem_read(ptr, size * 2))[:-2].decode('utf-16le') if size else '')
        for key, offsets, width in (('u32', (0x10, 0x30), 4), ('u16', (0x70, 0x72, 0x74, 0x76), 2), ('u64', U64, 8)):
            result[key] = [int.from_bytes(uc.mem_read(packet + off, width), 'little') for off in offsets]
        result['enum60'] = int.from_bytes(uc.mem_read(packet + 0x60, 1), 'little')
        result['appearance'] = list(uc.mem_read(packet + 0xb8, 10))
        result['appearance_flags'] = list(uc.mem_read(packet + 0xd8, 2))
        result['flag108'] = bool(uc.mem_read(packet + 0x108, 1)[0])
        return result

    def run(body, poison=0x55, fail_at=None, allow_extra=False):
        state.clear(); state.update(body=body, heap=h.scratch + 0x10000, allocations={}, fail_at=fail_at)
        operations.clear(); uc.mem_write(h.scratch + 0x30000, bytes(0x8000))
        uc.mem_write(packet - 16, b'\xa5' * 16 + bytes([poison]) * 0x170 + b'\xa6' * 16)
        require(h.call(functions['constructor'], packet) == packet, 'CharacterRecord constructor return differs')
        before = bytes(uc.mem_read(packet, 0x170))
        uc.mem_write(archive - 16, b'\xa7' * 16 + bytes([poison]) * 0x40 + b'\xa8' * 16)
        uc.mem_write(buffer - 16, b'\xa9' * 16 + body + b'\xaa' * 16)
        uc.reg_write(x.UC_X86_REG_RDX, buffer); uc.reg_write(x.UC_X86_REG_R8, len(body)); uc.reg_write(x.UC_X86_REG_R9, 1)
        put(h.scratch + 0x38028, 'Q', 0); h.call(inputs['constructor'], archive)
        input_before = bytes(uc.mem_read(archive - 16, 0x60))
        abi = {name: 0x1234567800000000 + i for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
        for name, value in abi.items():
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
        uc.reg_write(x.UC_X86_REG_RDX, archive)
        try:
            returned = h.call(functions['reader'], packet, budget=1000000) & 255
        except ExtensionBoundary as error:
            return dict(accepted=False, boundary=str(error), consumed=position())
        require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.scratch + 0x38008,
                'CharacterRecord ABI differs')
        after = bytes(uc.mem_read(packet, 0x170))
        fields = [(off, 8) for off in U64] + [(off, 16) for off in STRINGS]
        fields += [(0x10, 4), (0x30, 4), (0x60, 1), (0x70, 8), (0xb8, 10), (0xd8, 2), (0xe0, 16), (0x108, 1), (0x118, 1)]
        mutable = {i for off, size in fields for i in range(off, off + size)}
        require(all(a == z for i, (a, z) in enumerate(zip(before, after)) if i not in mutable)
                and bytes(uc.mem_read(packet - 16, 16)) == b'\xa5' * 16
                and bytes(uc.mem_read(packet + 0x170, 16)) == b'\xa6' * 16, 'CharacterRecord guards/padding changed')
        input_after = bytes(uc.mem_read(archive - 16, 0x60))
        mutable_input = set(range(0x20, 0x24)) | set(range(0x40, 0x48))
        require(all(a == z for i, (a, z) in enumerate(zip(input_before, input_after)) if i not in mutable_input)
                and bytes(uc.mem_read(buffer - 16, len(body) + 32)) == b'\xa9' * 16 + body + b'\xaa' * 16,
                'CharacterRecord input buffer/guards differ')
        for ptr, size in state['allocations'].items():
            require(bytes(uc.mem_read(ptr - 16, 16)) == b'\xa5' * 16 and bytes(uc.mem_read(ptr + size, 16)) == b'\xa6' * 16,
                    'CharacterRecord string allocation guard changed')
        projected = None
        if returned:
            wire = body[:position()] if allow_extra else body
            whole = struct.pack('<IIH', 0, 0, 1) + wire + bytes(28)
            decoded = decode_character_list(whole, max_payload_size=4096, max_characters=1, max_extension_items=0).records[0]
            projected = values()
            expected = {key: list(getattr(decoded, key)) if isinstance(getattr(decoded, key), tuple) else getattr(decoded, key)
                        for key in projected}
            require(projected == expected and not decoded.appearance_items and decoded.optional_items is None,
                    'CharacterRecord runtime projection differs')
        return dict(accepted=bool(returned), consumed=position(), operations=operations.copy(), values=projected)

    cases = []
    for text in ('', 'Carnage', 'Тест日本😀', 'X' * 17):
        for enum in (0, 6, 7, 255):
            for appearance, flag in ((0, 0), (1, 2), (2, 1), (255, 255)):
                for poison in (0x55, 0xaa):
                    body = body_for(text, enum, appearance, flag, 0xfedcba9876543210)
                    result = run(body, poison); require(result['accepted'] and result['consumed'] == len(body), 'CharacterRecord full body rejected')
                    cases.append(result)
    body = body_for('Тест日本😀', 255, 255, 255, 0xffffffffffffffff)
    baseline = run(body)
    truncated = [run(body[:size]) for size in range(len(body))]
    failures = [run(body, fail_at=i) for i in range(len(baseline['operations']))]
    require(all(not row['accepted'] for row in truncated + failures), 'CharacterRecord incomplete input accepted')
    require(all(len(row['operations']) == i + 1 for i, row in enumerate(failures)), 'CharacterRecord continued after read failure')
    boundaries = [run(body_for(appearance_count=1)), run(body_for(optional=1))]
    require({row.get('boundary') for row in boundaries} == {'appearance_items_not_ported', 'optional_items_not_ported'},
            'CharacterRecord extension boundary differs')
    extra = run(body + b'extra', allow_extra=True)
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases, truncated=truncated,
                failures=failures, boundaries=boundaries, extra=extra, evidence=h.evidence, network_used=False, profile_activated=False,
                limits=['Native whole record, time/u16/appearance/optional readers, input buffer/scalars/raw/FString/std-string/UTF8 execute.',
                        'Storage/allocation/free and empty appearance resize are bounded fixtures; actual allocator lifetime is not proved.',
                        'Nonempty appearance and present optional data stop at explicit boundaries; full nested containers are not ported.',
                        'No whole-list integration, result handler, network, character creation or profile promotion.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    result = verify(json.loads(args.context.read_text('utf-8')), args.root)
    result.update(context_sha256=hashlib.sha256(args.context.read_bytes()).hexdigest(), tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    path = load('research-workflow').snapshot(args.root, 'native-character-record-checks', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']), truncated=len(result['truncated']), failures=len(result['failures']))))
