"""Native key lookup/comparison/replacement; only temporary free and memmove are fixtures."""
import argparse
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('unique_payload', HERE / 'replay-ui-config-payload.py')
payload = importlib.util.module_from_spec(spec); spec.loader.exec_module(payload)
native, getter, unicorn, x = payload.native, payload.getter, payload.unicorn, payload.x
ROOTS = (0x1445d8430, 0x1445c29f0, 0x141421b80)
COMPARE = 0x14145f1e0
COMPARE_HEX = '4c8bd14c8d1d165259074c2bd24c8bc2430fb70402450fb7084d8d4002413bc1750585c075eac38bd0410bd1f7c280ffffff750f430fb61419420fb604182bc274cec3412bc1c3'
ASCII_TABLE = 0x1489f4400
MOVE, FREE = 0x1487f5abf, 0x141483080


def run(request, compare_request):
    for r in (request, compare_request):
        if r['source_sha256'] != getter.SHA or r['question'] != 'ui-nktileview-property-schema':
            raise ValueError('Другой источник / вопрос')
    if not {hex(a) for a in ROOTS} <= {f['address'] for f in request['functions']}:
        raise ValueError('Нет явных roots')
    if hex(COMPARE) not in {f['address'] for f in compare_request['functions']}:
        raise ValueError('Нет явного compare leaf')
    if native.capstone.__version__ != '5.0.6' or unicorn.__version__ != '2.1.4':
        raise ValueError('Изменились закреплённые инструменты')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA: raise ValueError('Изменился EXE')
    image = native.Image(raw); selected = set()
    for a in ROOTS:
        row = image.containing(a)
        if row is None or image.pe.base + image.roots[row][0] != a: raise ValueError('Изменился unwind root')
        selected.add(image.roots[row])
    fragments = native.decode_ranges(image, selected)
    ranges = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']) for f in fragments]
    leaves = dict(payload.LEAVES); leaves[COMPARE] = COMPARE_HEX
    for address, encoded in leaves.items():
        data = bytes.fromhex(encoded); offset = image.offset(address - image.pe.base)
        if image.containing(address) is not None or raw[offset:offset + len(data)] != data:
            raise ValueError('Изменились exact leaf bytes / unwind')
        if raw[offset + len(data):offset + len(data) + 4] != b'\xcc' * 4: raise ValueError('Изменился leaf padding')
        ranges.append((address, address + len(data)))
    offset = image.offset(ASCII_TABLE - image.pe.base); ascii_table = raw[offset:offset + 128]
    if ascii_table != bytes(a + 32 if 65 <= a <= 90 else a for a in range(128)):
        raise ValueError('Изменилась ASCII folding table')
    offset = image.offset(payload.TABLE - image.pe.base)
    if struct.unpack_from('<4Q', raw, offset) != (0x141421b50, 0x14140e2f0, 0x141421b70, 0x141421b80):
        raise ValueError('Изменилась таблица capture cleanup')
    pages = {p for a, b in ranges for p in range(a & ~4095, (b + 4095) & ~4095, 4096)}
    pages.update(a & ~4095 for a in (ASCII_TABLE, payload.TABLE, MOVE, FREE))
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page, 4096); offset = image.offset(page - image.pe.base)
        uc.mem_write(page, raw[offset:offset + 4096])
    base = 0x20000000; uc.mem_map(base, 0x20000)
    container, entries, old_text, new_text, index_ptr, flag_ptr, heap1, heap2, bits, bucket, stack, stop = [
        base + a for a in (0x1000, 0x2000, 0x4000, 0x4400, 0x5000, 0x5100, 0x5200, 0x5300, 0x5400, 0x5500, 0x10008, 0x1f000)]
    state = {}
    def qword(at): return int.from_bytes(uc.mem_read(at, 8), 'little')
    def integer(at): return int.from_bytes(uc.mem_read(at, 4), 'little', signed=True)
    def hook(machine, address, size, unused):
        if address in (MOVE, FREE):
            rcx, rdx, r8 = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
            if address == MOVE:
                if (rcx, rdx, r8) != (entries, entries + 0xb0, 0xa0): raise ValueError('Неверный replacement memmove')
                uc.mem_write(rcx, bytes(uc.mem_read(rdx, r8))); state['moves'] += 1
            else:
                if rcx != old_text or not state['old_has_data']: raise ValueError('Неверный old key free')
                state['frees'] += 1
            sp = uc.reg_read(x.UC_X86_REG_RSP)
            uc.reg_write(x.UC_X86_REG_RAX, rcx); uc.reg_write(x.UC_X86_REG_RIP, qword(sp))
            uc.reg_write(x.UC_X86_REG_RSP, sp + 8); return
        if not any(a <= address and address + size <= b for a, b in ranges):
            raise ValueError('Исполнение вне uniqueness / lookup / compare / cleanup: ' + hex(address))
        if address == COMPARE: state['compares'] += 1
        if address == 0x1445c29f0: state['lookups'] += 1
        if address == 0x141421b80: state['cleanups'] += 1
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    def execute(entry, rcx, rdx, r8, r9, fifth=0):
        state.update(moves=0, frees=0, compares=0, lookups=0, cleanups=0)
        uc.mem_write(stack - 0x400, b'\x91' * 0x800); uc.mem_write(stack, struct.pack('<Q', stop))
        uc.mem_write(stack + 0x28, struct.pack('<Q', fifth))
        for reg, value in ((x.UC_X86_REG_RCX, rcx), (x.UC_X86_REG_RDX, rdx),
                          (x.UC_X86_REG_R8, r8), (x.UC_X86_REG_R9, r9), (x.UC_X86_REG_RSP, stack)):
            uc.reg_write(reg, value)
        uc.emu_start(entry, stop, count=4096)
        if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RSP) != stack + 8:
            raise ValueError('Нет полного native возврата')
        return uc.reg_read(x.UC_X86_REG_RAX) & 0xffffffff
    def string_fields(data, at):
        if data is None: return struct.pack('<Qii', 0, 0, 0)
        encoded = data.encode('utf-16le') + b'\0\0'; uc.mem_write(at, encoded)
        return struct.pack('<Qii', at, len(encoded) // 2, len(encoded) // 2)
    pairs = [('ContentSubName', 'ContentSubName', True), ('ContentSubName', 'contentsubname', True),
        ('AB', 'AC', False), ('ABC', 'AB', False), ('Тест', 'Тест', True), ('Тест', 'тест', False),
        ('A😀', 'a😀', True), ('A😀', 'A😁', False), ('A\0X', 'a\0Y', True),
        (None, None, True), (None, '', True), ('', None, True), ('', '', True),
        (None, 'A', False), ('A', None, False), ('A', 'B', False)]
    cases = []
    for pair_index, (old_value, new_value, match) in enumerate(pairs):
        for active1, active2, external, existing_free, out_flag in itertools.product((False, True), repeat=5):
            old = bytearray(b'\x61' * 0xb0); new = bytearray(b'\x72' * 0xb0)
            old[:16] = string_fields(old_value, old_text); new[:16] = string_fields(new_value, new_text)
            for offset, active, heap, capture in ((0x20, active1, heap1, 0x11111111), (0x60, active2, heap2, 0x22222222)):
                struct.pack_into('<Q', old, offset, 0x1445c78d0 if active else 0)
                struct.pack_into('<Q', old, offset + 0x10, heap if external else 0)
                struct.pack_into('<QQ', old, offset + 0x20, payload.TABLE, capture)
                uc.mem_write(heap, struct.pack('<QQ', payload.TABLE, capture))
                struct.pack_into('<Q', new, offset, 0x1445c7970)
                struct.pack_into('<Q', new, offset + 0x10, 0)
                struct.pack_into('<QQ', new, offset + 0x20, payload.TABLE, capture + 0x10000000)
            struct.pack_into('<ii', old, 0xa0, -1, 0); struct.pack_into('<ii', new, 0xa0, -1, 0)
            free_entry = bytearray(b'\x83' * 0xb0); struct.pack_into('<ii', free_entry, 0, -1, -1)
            before_entries = bytes(old + new + free_entry)
            uc.mem_write(entries - 8, b'\xa5' * 8 + before_entries + b'\xa5' * 8)
            model = bytearray(0x60)
            struct.pack_into('<Qii', model, 0, entries, 3 if existing_free else 2, 4)
            struct.pack_into('<I', model, 0x10, 0x55555555 if external else 3)
            struct.pack_into('<Q', model, 0x20, bits if external else 0)
            struct.pack_into('<ii', model, 0x30, 2 if existing_free else -1, int(existing_free))
            struct.pack_into('<i', model, 0x38, 0x77777777 if external else 0)
            struct.pack_into('<Q', model, 0x40, bucket if external else 0); struct.pack_into('<i', model, 0x48, 1)
            uc.mem_write(container, bytes(model)); uc.mem_write(bits, struct.pack('<I', 3)); uc.mem_write(bucket, bytes(4))
            uc.mem_write(index_ptr, struct.pack('<i', 1)); uc.mem_write(flag_ptr, b'\xa5')
            state['old_has_data'] = old_value is not None
            result = execute(ROOTS[0], container, 0x1234, entries + 0xb0, index_ptr, flag_ptr if out_flag else 0)
            if result != int(match) or integer(index_ptr) != (0 if match else 1): raise ValueError('Неверный replacement результат / index')
            if bytes(uc.mem_read(flag_ptr, 1)) != (bytes([int(match)]) if out_flag else b'\xa5'):
                raise ValueError('Неверный optional out bool')
            expected_entries = bytearray(before_entries); expected_model = bytearray(model)
            if match:
                expected_entries[:0xa0] = new[:0xa0]
                struct.pack_into('<ii', expected_entries, 0xb0, -1, 2 if existing_free else -1)
                if existing_free: struct.pack_into('<i', expected_entries, 0x160, 1)
                struct.pack_into('<ii', expected_model, 0x30, 1, int(existing_free) + 1)
                if not external: struct.pack_into('<I', expected_model, 0x10, 1)
            if bytes(uc.mem_read(entries - 8, len(before_entries) + 16)) != b'\xa5' * 8 + bytes(expected_entries) + b'\xa5' * 8:
                raise ValueError('Неверный payload / hash links / free-list / guard')
            if bytes(uc.mem_read(container, 0x60)) != bytes(expected_model): raise ValueError('Неверные поля контейнера')
            if integer(bits) != (1 if match and external else 3) or integer(bucket) != 0:
                raise ValueError('Неверный external bitmap / bucket')
            expected_counts = (int(match), int(match and old_value is not None), int(match) * (int(active1) + int(active2)))
            if (state['moves'], state['frees'], state['cleanups']) != expected_counts or state['lookups'] != 1:
                raise ValueError('Неверные ownership calls / lookup')
            old_count, new_count = struct.unpack_from('<i', old, 8)[0], struct.unpack_from('<i', new, 8)[0]
            if state['compares'] != int(old_count == new_count and old_count > 1):
                raise ValueError('Неверный length / empty gate перед native compare')
            cases.append(dict(pair=pair_index, old=old_value, new=new_value, expected_match=match,
                active=[active1, active2], external=external, existing_free=existing_free, optional_out=out_flag,
                compares=state['compares'], moves=state['moves'], old_key_frees=state['frees'], cleanups=state['cleanups']))
    lookup_cases = []
    for external, query in itertools.product((False, True), ('abc', 'ghi', 'XYZ')):
        expected, compares = {'abc': (0, 3), 'ghi': (2, 1), 'XYZ': (-1, 3)}[query]
        model = bytearray(0x60); struct.pack_into('<Qii', model, 0, entries, 3, 4)
        struct.pack_into('<i', model, 0x38, 2); struct.pack_into('<Q', model, 0x40, bucket if external else 0)
        struct.pack_into('<i', model, 0x48, 1); uc.mem_write(container, bytes(model)); uc.mem_write(bucket, struct.pack('<i', 2))
        for index, value in enumerate(('ABC', 'DEF', 'GHI')):
            node = bytearray(0xb0); node[:16] = string_fields(value, old_text + index * 0x100)
            struct.pack_into('<i', node, 0xa0, index - 1); uc.mem_write(entries + index * 0xb0, bytes(node))
        uc.mem_write(index_ptr, string_fields(query, new_text)); before = bytes(uc.mem_read(entries, 0x210))
        result = execute(0x1445c29f0, container, 0x1234, index_ptr, 0)
        if result != (expected & 0xffffffff) or state['compares'] != compares or bytes(uc.mem_read(entries, 0x210)) != before:
            raise ValueError('Неверный native collision lookup')
        lookup_cases.append(dict(external=external, query=query, result=expected, compares=compares))
    for allocated in (0, 3):
        uc.mem_write(container, bytes(0x60)); uc.mem_write(container + 8, struct.pack('<i', allocated))
        uc.mem_write(container + 0x34, struct.pack('<i', allocated))
        if execute(0x1445c29f0, container, 0, 0, 0) != 0xffffffff or state['compares']:
            raise ValueError('Empty lookup не обходит null query')
        lookup_cases.append(dict(empty_allocated_slots=allocated, result=-1))
    fast_cases = []
    for optional in (False, True):
        uc.mem_write(container, bytes(0x60)); uc.mem_write(container + 8, struct.pack('<i', 1))
        uc.mem_write(index_ptr, struct.pack('<i', 0)); uc.mem_write(flag_ptr, b'\xa5')
        if execute(ROOTS[0], container, 0, 0, index_ptr, flag_ptr if optional else 0) != 0:
            raise ValueError('Single-active fast exit не вернул false')
        if any(state[k] for k in ('lookups', 'compares', 'moves', 'frees', 'cleanups')) or integer(index_ptr) != 0:
            raise ValueError('Fast exit изменил index / вызвал lookup')
        if bytes(uc.mem_read(flag_ptr, 1)) != (b'\0' if optional else b'\xa5'): raise ValueError('Неверный fast out bool')
        fast_cases.append(dict(optional_out=optional, result=False))
    return dict(source_sha256=getter.SHA, fragments=fragments, compare_leaf_sha256=getter.sha(bytes.fromhex(COMPARE_HEX)),
        ascii_table_sha256=getter.sha(ascii_table), cases=cases, lookup_cases=lookup_cases, fast_cases=fast_cases,
        limits=['Native uniqueness, lookup, ASCII-table UTF16 compare and capture cleanup execute completely.',
            'Only old key free and replacement memmove0xa0 are fixtures; memory is not actually released.',
            'Explicit same-bucket synthetic inputs; real hash algorithm / growth / higher-level reader replacement not covered.',
            'Embedded NUL is an adversarial synthetic payload, not a supported real setting key contract.',
            'No later callable dispatch, config precedence, active resource or Brush binding proof.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True); parser.add_argument('--compare-request', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = run(json.loads(args.request.read_text('utf-8')), json.loads(args.compare_request.read_text('utf-8')))
    result['replay_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps({k: len(result[k]) for k in ('cases', 'lookup_cases', 'fast_cases')}))
