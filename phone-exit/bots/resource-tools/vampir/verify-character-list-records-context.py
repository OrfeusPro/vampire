"""Current whole list/records/collections on one native memory with bounded storage."""
import argparse
from dataclasses import asdict
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


def verify(context, root):
    functions = {name: int(at, 16) for name, at in context['functions'].items()}
    h = load('update-native-harness').make_harness(context, context['exports'], set(functions.values()),
        leaves={int(at, 16): code for at, code in context['leaves'].items()}, root=root)
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    calls = {name: {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
                   for r in bindings.rows(native, h.image, at) if r['call']} for name, at in functions.items()}
    if calls != context['call_sites']:
        raise ValueError('Whole character list call sites differ')

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def data(at, size):
        off = h.image.offset(at - h.image.pe.base)
        return h.raw[off:off + size]

    uc, x = h.uc, h.x
    for block in context['blocks']:
        at, payload = int(block['address'], 16), bytes.fromhex(block['bytes'])
        require(data(at, len(payload)) == payload and hashlib.sha256(payload).hexdigest() == block['sha256'], 'Whole list source block differs')
        for page in range(at & ~4095, (at + len(payload) + 4095) & ~4095, 4096):
            if not any(lo <= page <= hi for lo, hi, _ in uc.mem_regions()):
                uc.mem_map(page, 4096); uc.mem_write(page, data(page, 4096))
    b = {name: int(at, 16) for name, at in context['bindings'].items()}
    require(struct.unpack('<Q', data(b['packet_table'] + 0x20, 8))[0] == functions['list_reader']
            and struct.unpack('<Q', data(b['packet_table'] + 0x28, 8))[0] == b['id_getter']
            and h.call(b['id_getter']) == 102, 'Whole list packet/ID link differs')
    packet, archive, buffer = [h.scratch + n for n in (0x1000, 0x2000, 0x5000)]
    state, operations = dict(packet=packet), []

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def put(at, fmt, *values):
        uc.mem_write(at, struct.pack('<' + fmt, *values))

    def number(at, width):
        return int.from_bytes(uc.mem_read(at, width), 'little')

    def allocate(size):
        require(0 < size <= 4096 and state['heap'] + size + 64 < h.scratch + 0x30000, 'Whole list allocation budget')
        pointer = state['heap'] + 16; state['heap'] += (size + 63) & ~15
        uc.mem_write(pointer - 16, b'\xa5' * 16 + b'\x5a' * size + b'\xa6' * 16)
        state['allocations'][pointer] = size
        return pointer

    record = load('verify-character-record-context')
    load('login-result-string-fixtures').install(load, h, context['string_storage'], state,
                                               lambda: state['record'], record.STRINGS)
    load('character-list-storage-fixtures').install(h, context, state, allocate)

    def position():
        value = number(archive + 0x30, 8) - buffer
        require(0 <= value <= len(state['body']), 'Whole list cursor outside input')
        return value

    import unicorn
    primitives = {functions['input_' + name]: name for name in ('u16', 'u32', 'u64', 'bool', 'raw')}
    def entered(machine, at, size, unused):
        if at == functions['constructor']:
            state['record'] = reg('RCX'); state['generation'] += 1
            require(h.scratch + 0x30000 <= state['record'] <= h.scratch + 0x38000 - 0x170, 'Whole list record constructor owner differs')
        elif at in primitives:
            require(reg('RCX') == archive, 'Whole list primitive receiver differs')
            operations.append(dict(kind=primitives[at], consumed=position()))
            if len(operations) - 1 == state['fail_at']:
                h.finish(0)
    uc.hook_add(unicorn.UC_HOOK_CODE, entered)
    sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
    from vampir_core.character_list import decode_character_list

    def capture(at):
        result = dict(strings=[], u32=[], u16=[], u64=[], enum60=0, appearance=[], appearance_flags=[],
                      appearance_items=[], optional_items=None, flag108=False)
        require(number(at, 8) == b['record_table'], 'Whole list copied record table differs')
        for off in record.STRINGS:
            pointer, count, cap = struct.unpack('<QII', bytes(uc.mem_read(at + off, 16)))
            require(0 <= count == cap <= 2048 and (not count or pointer in state['allocations']), 'Whole list string descriptor/ownership differs')
            result['strings'].append(bytes(uc.mem_read(pointer, count * 2))[:-2].decode('utf-16le') if count else '')
        for key, offsets, width in (('u32', (0x10, 0x30), 4), ('u16', (0x70, 0x72, 0x74, 0x76), 2), ('u64', record.U64, 8)):
            result[key] = [number(at + off, width) for off in offsets]
        result['enum60'] = number(at + 0x60, 1)
        result['appearance'] = list(uc.mem_read(at + 0xb8, 10)); result['appearance_flags'] = list(uc.mem_read(at + 0xd8, 2))
        pointer, count, cap = struct.unpack('<QII', bytes(uc.mem_read(at + 0xe0, 16)))
        require(0 <= count <= cap <= 8 and (not count or pointer in state['allocations']), 'Whole list appearance descriptor differs')
        result['appearance_items'] = [[number(pointer + i * 16 + off, width) for off, width in ((8, 4), (12, 1), (14, 2))] for i in range(count)]
        result['flag108'] = bool(number(at + 0x108, 1))
        if number(at + 0x118, 1):
            pointer, count = struct.unpack('<QI', bytes(uc.mem_read(at + 0x120, 12)))
            require(count <= 8 and pointer in state['allocations'], 'Whole list optional descriptor differs')
            result['optional_items'] = sorted([[number(pointer + i * 0x38 + off, width) for off, width in
                                               ((0, 1), (0x10, 1), (0x14, 4), (0x18, 4), (0x1c, 4), (0x28, 8))] for i in range(count)])
        return result

    def run(body, fail_at=None, allow_extra=False, poison=0x55):
        require(type(body) is bytes and len(body) <= 4096, 'Whole list input budget')
        state.clear(); state.update(packet=packet, body=body, heap=h.scratch + 0x10000, allocations={}, fail_at=fail_at,
                                    record=0, generation=0, map_storage={}, copies=[], insertions=[], rehashes=[], list_storage=(0, 0))
        operations.clear(); uc.mem_write(h.scratch + 0x30000, bytes(0x8000))
        uc.mem_write(packet - 16, b'\xa7' * 16 + bytes([poison]) * 0x48 + b'\xa8' * 16)
        require(h.call(b['packet_constructor'], packet) == packet, 'Whole list constructor return differs')
        before_packet = bytes(uc.mem_read(packet, 0x48))
        uc.mem_write(archive - 16, b'\xa9' * 16 + bytes(0x40) + b'\xaa' * 16)
        uc.mem_write(buffer - 16, b'\xab' * 16 + body + b'\xac' * 16)
        uc.reg_write(x.UC_X86_REG_RDX, buffer); uc.reg_write(x.UC_X86_REG_R8, len(body)); uc.reg_write(x.UC_X86_REG_R9, 1)
        put(h.scratch + 0x38028, 'Q', 0); h.call(functions['input_constructor'], archive)
        before_input = bytes(uc.mem_read(archive - 16, 0x60))
        abi = {name: 0x1234567800000000 + i for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
        for name, value in abi.items():
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
        uc.reg_write(x.UC_X86_REG_RDX, archive)
        try:
            returned = h.call(functions['list_reader'], packet, budget=1000000) & 255
        except unicorn.UcError as error:
            raise ValueError('Whole list memory fault at ' + hex(reg('RIP'))) from error
        require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.scratch + 0x38008, 'Whole list ABI differs')
        after_packet = bytes(uc.mem_read(packet, 0x48)); mutable_packet = set(range(0x10, 0x48)) - set(range(0x34, 0x38))
        require(all(a == z for i, (a, z) in enumerate(zip(before_packet, after_packet)) if i not in mutable_packet)
                and bytes(uc.mem_read(packet - 16, 16)) == b'\xa7' * 16
                and bytes(uc.mem_read(packet + 0x48, 16)) == b'\xa8' * 16, 'Whole list packet guards/padding changed')
        after_input = bytes(uc.mem_read(archive - 16, 0x60)); mutable_input = set(range(0x20, 0x24)) | set(range(0x40, 0x48))
        require(all(a == z for i, (a, z) in enumerate(zip(before_input, after_input)) if i not in mutable_input)
                and bytes(uc.mem_read(buffer - 16, len(body) + 32)) == b'\xab' * 16 + body + b'\xac' * 16, 'Whole list input guards changed')
        for pointer, size in state['allocations'].items():
            require(bytes(uc.mem_read(pointer - 16, 16)) == b'\xa5' * 16
                    and bytes(uc.mem_read(pointer + size, 16)) == b'\xa6' * 16, 'Whole list allocation guards changed')
        count = number(packet + 0x20, 4); projected = None
        if returned:
            wire = body[:position()] if allow_extra else body
            decoded = decode_character_list(wire, max_payload_size=4096, max_characters=4, max_extension_items=128)
            require(count == len(decoded.records) == len(state['copies']) == state['generation'], 'Whole list count/copy lifecycle differs')
            pointer = number(packet + 0x18, 8)
            require(not count or pointer in state['allocations'], 'Whole list output array ownership differs')
            projected = [capture(pointer + i * 0x170) for i in range(count)]
            expected = json.loads(json.dumps([asdict(item) for item in decoded.records], ensure_ascii=False))
            require(projected == expected, 'Whole list runtime projection/record aliasing differs')
            require((number(packet + 0x10, 4), number(packet + 0x14, 4)) == (decoded.result_code, decoded.raw14)
                    and tuple(number(packet + off, width) for off, width in ((0x28, 8), (0x30, 4), (0x38, 8), (0x40, 8))) == decoded.tail,
                    'Whole list header/tail differs')
        return dict(accepted=bool(returned), consumed=position(), count=count, records=projected, operations=operations.copy(),
                    copies=state['copies'].copy(), insertions=state['insertions'].copy(), rehashes=state['rehashes'].copy())

    def make_body(count, style=0, code=0):
        records = []
        for index in range(count):
            base = record.body_for(('Тест日本😀' if style & 1 else 'Carnage') + str(index),
                                   enum=(index + style) * 40, appearance=255, flag=2, seed=index * 1000000000000 + style)
            items = [(index * 100 + j, 255 - j, 0x8000 + j) for j in range((index + style) % 4)]
            appearance = struct.pack('<H', len(items)) + b''.join(struct.pack('<IBH', *item) for item in items)
            entries = [(j * 16 + 1, 255 - j, index + j, 0xffffffff - j, style + j, index * 10000 + j) for j in range((index + style) % 6)]
            if entries:
                entries.append((1, 0, index + 90, 80, 70, 60 + index))
            optional = b'\0' if (index + style) % 3 == 0 else b'\xff' + struct.pack('<H', len(entries)) + b''.join(struct.pack('<BBIIIQ', *item) for item in entries)
            records.append(base[:-28] + appearance + base[-26:-1] + optional)
        return struct.pack('<IIH', code, 0x80000000 + style, count) + b''.join(records) + struct.pack('<QIQQ', 0xffffffffffffffff, 0x80000000, 123, 456)

    cases = [run(make_body(count, style, code), poison=poison) for count in (0, 1, 2, 4)
             for style in (0, 1, 2, 3) for code, poison in ((0, 0x55), (58, 0xaa))]
    require(all(case['accepted'] for case in cases), 'Whole list complete body rejected')
    body = make_body(1, 2); baseline = run(body)
    truncated = [run(body[:size]) for size in range(len(body))]
    failures = [run(body, fail_at=i) for i in range(len(baseline['operations']))]
    require(all(not case['accepted'] for case in truncated + failures), 'Whole list incomplete input accepted')
    require(all(len(case['operations']) == i + 1 for i, case in enumerate(failures)), 'Whole list continued after failed input')
    many = make_body(4, 3)
    multi_truncated = [run(many[:size]) for size in sorted({10, 11, len(many) // 2, len(many) - 28, len(many) - 1})]
    require(all(not case['accepted'] for case in multi_truncated), 'Whole list partial multi-record result accepted')
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases,
                truncated=truncated, failures=failures, multi_truncated=multi_truncated, extra=run(body + b'extra', allow_extra=True),
                evidence=h.evidence, network_used=False, profile_activated=False,
                limits=['Whole current list/record/nested readers and native input/string/vector/map-insert functions execute in one Unicorn memory.',
                        'Storage, allocator/free, reset/rehash/bit capacity, unseen-key predicate, shallow record copy and cleanup remain fixtures.',
                        'Distinct records use distinct retained storage generations; no native allocator/copy lifetime or repeated decode into old objects is proved.',
                        'No result handler/dispatcher, network/auth, character creation, runtime profile or baseline promotion.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    result = verify(json.loads(args.context.read_text('utf-8')), args.root)
    result.update(context_sha256=hashlib.sha256(args.context.read_bytes()).hexdigest(), tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    path = load('research-workflow').snapshot(args.root, 'native-character-list-records-checks', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']), truncated=len(result['truncated']), failures=len(result['failures']))))
