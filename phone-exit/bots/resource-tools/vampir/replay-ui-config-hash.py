"""Native counted UTF16 key hash; independent bitwise reference, no service fixtures."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('hash_unique', HERE / 'replay-ui-config-uniqueness.py')
uniqueness = importlib.util.module_from_spec(spec); spec.loader.exec_module(uniqueness)
native, getter, unicorn, x = uniqueness.native, uniqueness.getter, uniqueness.unicorn, uniqueness.x
HASH = 0x141425d60
TABLE = 0x14b0c2b10


def table_word(byte):
    value = byte << 24
    for _ in range(8):
        value = ((value << 1) ^ (0x04c11db7 if value & 0x80000000 else 0)) & 0xffffffff
    return value


def table_bytes(image):
    offset = image.offset(TABLE - image.pe.base)
    data = image.data[offset:offset + 1024]
    if data != struct.pack('<256I', *(table_word(a) for a in range(256))):
        raise ValueError('Изменилась file-backed таблица hash')
    return data


def reference(data, count):
    if count <= 0: return 0
    if len(data) < count * 2: raise ValueError('Недостаточно UTF16 units для oracle')
    result = 0
    for (unit,) in struct.iter_unpack('<H', data[:count * 2]):
        if 97 <= unit <= 122: unit -= 32
        for byte in (unit & 255, unit >> 8):
            # Compute a polynomial remainder per byte; do not read the native lookup table.
            result = (result >> 8) ^ table_word((result ^ byte) & 255)
    return result


def run(request):
    if request['source_sha256'] != getter.SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Другой источник / вопрос')
    if hex(HASH) not in {f['address'] for f in request['functions']}: raise ValueError('Нет явного hash root')
    if native.capstone.__version__ != '5.0.6' or unicorn.__version__ != '2.1.4':
        raise ValueError('Изменились закреплённые инструменты')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA: raise ValueError('Изменился EXE')
    image = native.Image(raw); row = image.containing(HASH)
    if row is None or image.pe.base + image.roots[row][0] != HASH: raise ValueError('Изменился unwind root')
    fragments = native.decode_ranges(image, {image.roots[row]})
    table = table_bytes(image)
    ranges = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']) for f in fragments]
    extra_leaves = {uniqueness.COMPARE: uniqueness.COMPARE_HEX}
    for address, encoded in extra_leaves.items():
        data = bytes.fromhex(encoded); offset = image.offset(address - image.pe.base)
        if image.containing(address) is not None or raw[offset:offset + len(data)] != data:
            raise ValueError('Изменился ранее проверенный compare leaf')
        if raw[offset + len(data):offset + len(data) + 4] != b'\xcc' * 4: raise ValueError('Изменился compare padding')
        ranges.append((address, address + len(data)))
    offset = image.offset(uniqueness.ASCII_TABLE - image.pe.base)
    if raw[offset:offset + 128] != bytes(a + 32 if 65 <= a <= 90 else a for a in range(128)):
        raise ValueError('Изменилась ранее проверенная compare table')
    pages = {p for a, b in ranges for p in range(a & ~4095, (b + 4095) & ~4095, 4096)}
    pages.update(a & ~4095 for a in (TABLE, uniqueness.ASCII_TABLE))
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page, 4096); offset = image.offset(page - image.pe.base)
        uc.mem_write(page, raw[offset:offset + 4096])
    base = 0x20000000; uc.mem_map(base, 0x20000)
    text, other, stack, stop = [base + a for a in (0x1000, 0x3000, 0x10008, 0x1f000)]
    def hook(machine, address, size, unused):
        if not any(a <= address and address + size <= b for a, b in ranges):
            raise ValueError('Исполнение вне native hash / compare: ' + hex(address))
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    def execute(entry, rcx, rdx):
        uc.mem_write(stack - 0x400, b'\x91' * 0x800); uc.mem_write(stack, struct.pack('<Q', stop))
        saved = 0x123456789abcdef0
        for reg, value in ((x.UC_X86_REG_RCX, rcx), (x.UC_X86_REG_RDX, rdx),
                          (x.UC_X86_REG_RBX, saved), (x.UC_X86_REG_RSP, stack)):
            uc.reg_write(reg, value)
        uc.emu_start(entry, stop, count=16384)
        if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RSP) != stack + 8 or uc.reg_read(x.UC_X86_REG_RBX) != saved:
            raise ValueError('Нет полного native возврата / сохранности RBX')
        return uc.reg_read(x.UC_X86_REG_RAX) & 0xffffffff
    values = ('', 'ContentSubName', 'contentsubname', 'CONTENTSUBNAME', 'A', 'a', 'Z', 'z',
              '@', '[', '`', '{', 'Тест', 'тест', 'A😀', 'a😀', 'A\0X', 'a\0Y', 'A/B', 'Long' * 20)
    payloads = [v.encode('utf-16le') for v in values] + [b'\x00\xd8', b'\x00\xdc']
    cases = []
    for payload_index, data in enumerate(payloads):
        for count in range(len(data) // 2 + 1):
            for alignment in (0, 1, 2):
                pointer = text + alignment
                before = b'\x7a' * 8 + data + b'\x7b' * 8; uc.mem_write(pointer - 8, before)
                result = execute(HASH, count, pointer)
                if result != reference(data, count) or bytes(uc.mem_read(pointer - 8, len(before))) != before:
                    raise ValueError('Native hash / source guards расходятся с bitwise oracle')
                cases.append(dict(payload=payload_index, utf16_hex=data.hex(), units=count, alignment=alignment, result=result))
    for count in (-0x80000000, -1, 0):
        for pointer in (0, text):
            if execute(HASH, count & 0xffffffff, pointer) != 0: raise ValueError('Nonpositive count не вернул zero')
            cases.append(dict(nonpositive_count=count, pointer=hex(pointer), result=0))
    pairs = [('ContentSubName', 'contentsubname', True), ('A', 'a', True), ('Тест', 'Тест', True),
             ('Тест', 'тест', False), ('A😀', 'a😀', True), ('A😀', 'A😁', False),
             ('', '', True), ('A\0X', 'a\0Y', True)]
    consistency = []
    for left, right, equal in pairs:
        a, b = left.encode('utf-16le'), right.encode('utf-16le')
        uc.mem_write(text, a + b'\0\0'); uc.mem_write(other, b + b'\0\0')
        compared = execute(uniqueness.COMPARE, text, other) == 0
        left_hash, right_hash = execute(HASH, len(a) // 2, text), execute(HASH, len(b) // 2, other)
        embedded = '\0' in left or '\0' in right
        if compared != equal or (equal and not embedded and left_hash != right_hash):
            raise ValueError('Нарушена согласованность native compare / hash для выбранных ключей')
        if embedded and left_hash == right_hash: raise ValueError('Не выявлено ожидаемое различие counted hash после NUL')
        consistency.append(dict(left=left, right=right, compared_equal=compared,
            left_hash=left_hash, right_hash=right_hash, embedded_nul_synthetic=embedded))
    if bytes(uc.mem_read(TABLE, 1024)) != table: raise ValueError('Изменена native hash table')
    return dict(source_sha256=getter.SHA, fragments=fragments, table_sha256=getter.sha(table),
        cases=cases, consistency=consistency,
        limits=['Native counted hash and previously proved compare leaf execute without service fixtures.',
            'Bitwise reference uses polynomial04c11db7, initial zero, explicit UTF16 unit count; not a zlib CRC claim.',
            'Only ASCII lowercase is uppercased; no general Unicode normalization or key-validity proof.',
            'Embedded NUL / isolated surrogate / odd alignment are synthetic boundary inputs, not supported setting contracts.',
            'No active config, allocator, later dispatch or Brush proof.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = run(json.loads(args.request.read_text('utf-8')))
    result['replay_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(cases=len(result['cases']), consistency=len(result['consistency']))))
