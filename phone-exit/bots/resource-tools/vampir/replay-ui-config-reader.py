"""Whole native reader/insertion/capture-copy/cleanup on one memory, explicit service fixtures."""
import argparse
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('reader_payload', HERE / 'replay-ui-config-payload.py')
payload = importlib.util.module_from_spec(spec); spec.loader.exec_module(payload)
native, getter, unicorn, x = payload.native, payload.getter, payload.unicorn, payload.x
ROOTS = (0x1445c2c30, 0x1445c1f50, 0x1445c4f60, 0x141421b80)
CONTAINER = 0x14b186130
FIXTURES = {0x14142a250: 'assign_string', 0x141426b30: 'construct_key',
    0x141429680: 'append_bit', 0x141425d60: 'hash_key', 0x1445d8430: 'uniqueness_false',
    0x141483080: 'free_temp', 0x1487e8ce0: 'check_cookie'}


def run(request):
    if request['source_sha256'] != getter.SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Другой источник / вопрос')
    if not {hex(a) for a in ROOTS} <= {f['address'] for f in request['functions']}:
        raise ValueError('Не все явные roots входят в задание')
    if native.capstone.__version__ != '5.0.6' or unicorn.__version__ != '2.1.4':
        raise ValueError('Изменились закреплённые инструменты')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA: raise ValueError('Изменился EXE')
    image = native.Image(raw); selected = set()
    for address in ROOTS:
        row = image.containing(address)
        if row is None or image.pe.base + image.roots[row][0] != address:
            raise ValueError('Изменился unwind root')
        selected.add(image.roots[row])
    fragments = native.decode_ranges(image, selected)
    ranges = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']) for f in fragments]
    # Reuse the exact already-reviewed copy / capture-address / cleanup leaves, not guessed unwind ranges.
    for address, expected_hex in payload.LEAVES.items():
        offset = image.offset(address - image.pe.base); data = bytes.fromhex(expected_hex)
        if image.containing(address) is not None or raw[offset:offset + len(data)] != data:
            raise ValueError('Изменились leaf boundaries / bytes')
        if raw[offset + len(data):offset + len(data) + 4] != b'\xcc' * 4:
            raise ValueError('Изменилась INT3 граница leaf')
        ranges.append((address, address + len(data)))
    offset = image.offset(payload.TABLE - image.pe.base)
    table = raw[offset:offset + 32]
    if struct.unpack('<4Q', table) != (0x141421b50, 0x14140e2f0, 0x141421b70, 0x141421b80):
        raise ValueError('Изменилась таблица capture operations')
    pages = {p for a, b in ranges for p in range(a & ~4095, (b + 4095) & ~4095, 4096)}
    pages.update(a & ~4095 for f in fragments for r in f['instructions'] for a in r['rip_references'])
    pages.update(a & ~4095 for a in FIXTURES)
    pages.add(payload.TABLE & ~4095)
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page, 4096)
        try: offset = image.offset(page - image.pe.base)
        except ValueError: continue  # explicit BSS fixture globals initialized below
        uc.mem_write(page, raw[offset:offset + 4096])
    base = 0x20000000; uc.mem_map(base, 0x30000)
    config, vtable, lookup, entries, stack, stop = [base + a for a in
        (0x1000, 0x2000, 0x3000, 0x4000, 0x20008, 0x2f000)]
    uc.mem_write(config, struct.pack('<Q', vtable)); uc.mem_write(vtable + 0x58, struct.pack('<Q', lookup))
    cookie = 0x123456789abcdef0
    uc.mem_write(0x14b271780, struct.pack('<Q', cookie))
    uc.mem_write(0x14b564638, struct.pack('<Q', config)); uc.mem_write(0x14b564640, struct.pack('<i', 1))
    state = {}
    def qword(at): return int.from_bytes(uc.mem_read(at, 8), 'little')
    def integer(at): return int.from_bytes(uc.mem_read(at, 4), 'little', signed=True)
    def ret(result=0):
        sp = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX, result); uc.reg_write(x.UC_X86_REG_RIP, qword(sp))
        uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
    def hook(machine, address, size, unused):
        if address not in FIXTURES and address != lookup:
            if not any(a <= address and address + size <= b for a, b in ranges):
                raise ValueError('Исполнение вне выбранной полной цепочки: ' + hex(address))
            if address == 0x141421b50: state['native_copies'] += 1
            if address == 0x141421b80: state['native_cleanups'] += 1
            if address == 0x1445c1f50:
                state['moved_key_object'] = qword(uc.reg_read(x.UC_X86_REG_R8))
            return
        rcx, rdx, r8, r9 = [uc.reg_read(r) for r in
            (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        name = 'lookup' if address == lookup else FIXTURES[address]
        state['calls'].append(name)
        if name == 'lookup':
            if (rcx, rdx, r8, qword(uc.reg_read(x.UC_X86_REG_RSP) + 0x28)) != (config, state['section'], state['key'], 0x14b2e5678):
                raise ValueError('Неверный lookup ABI')
            if bytes(uc.mem_read(r9, 16)) != bytes(16): raise ValueError('Не обнулён временный FString')
            if state['found'] and not state['zero_length']:
                data = state['value'].encode('utf-16le') + b'\0\0'
                uc.mem_write(state['temp'], data)
                uc.mem_write(r9, struct.pack('<Qii', state['temp'], len(data) // 2, len(data) // 2))
            ret(int(state['found']))
        elif name == 'assign_string':
            expected_pointer = 0 if state['zero_length'] else state['temp']
            if (rcx, rdx, r8) != (state['dest'], expected_pointer, len(state['value'].encode('utf-16le')) // 2):
                raise ValueError('Неверное присваивание lookup результата')
            data = bytes(uc.mem_read(rdx, r8 * 2)) + b'\0\0' if r8 else b''
            if data: uc.mem_write(state['dest_data'], data)
            uc.mem_write(rcx, struct.pack('<Qii', state['dest_data'] if data else 0, len(data) // 2, len(data) // 2))
            ret(rcx)
        elif name == 'construct_key':
            if rdx != state['key']: raise ValueError('Конструируется другой key')
            uc.mem_write(state['key_data'], state['key_bytes'])
            uc.mem_write(rcx, struct.pack('<Qii', state['key_data'], len(state['key_bytes']) // 2, len(state['key_bytes']) // 2))
            ret(rcx)
        elif name == 'append_bit':
            if (rcx, rdx, integer(CONTAINER + 0x28)) != (CONTAINER + 0x10, 0, state['index']):
                raise ValueError('Неверное добавление occupancy bit')
            uc.mem_write(CONTAINER + 0x28, struct.pack('<i', state['index'] + 1))
            ret(state['index'])
        elif name == 'hash_key':
            if (rcx, rdx) != (len(state['key_bytes']) // 2 - 1, state['key_data']):
                raise ValueError('Неверные аргументы key hash')
            ret(state['hash'])
        elif name == 'uniqueness_false':
            if (rcx, rdx, r8, integer(r9), qword(uc.reg_read(x.UC_X86_REG_RSP) + 0x28)) != (
                    CONTAINER, state['hash'], entries + state['index'] * 0xb0, state['index'], 0):
                raise ValueError('Неверные аргументы uniqueness helper')
            ret(0)  # exact new-entry scenario; duplicate / replacement path deliberately excluded
        elif name == 'free_temp':
            if rcx != state['temp'] or not state['found'] or state['zero_length']:
                raise ValueError('Освобождается key / capture / неподтверждённый temporary')
            ret()
        else:
            if rcx != cookie: raise ValueError('Неверный stack cookie после полного reader')
            ret()
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    results = []
    groups = [(('RED', False), ('Other', False), ('', False)),
              (('', False), ('Тест', False), ('A😀', False)),
              (('', True), ('A/B', False), ('Long' * 20, False))]
    keys = ('ContentSubName', 'Demo.UI.Scale', 'Демо.Поле')
    for found_mask, group, ignored_rcx in itertools.product(range(8), range(len(groups)), (0, base + 0x900)):
        uc.mem_write(CONTAINER, bytes(0x60)); uc.mem_write(CONTAINER, struct.pack('<Qii', entries, 0, 4))
        uc.mem_write(CONTAINER + 0x28, struct.pack('<iiii', 0, 128, -1, 0))
        uc.mem_write(CONTAINER + 0x38, struct.pack('<i', -1)); uc.mem_write(CONTAINER + 0x48, struct.pack('<i', 1))
        uc.mem_write(entries - 8, b'\xa5' * (0xb0 * 4 + 16))
        sequence = []; retained = []
        for index, (value, zero_length) in enumerate(groups[group]):
            slot = base + 0x8000 + index * 0x1000
            dest, dest_data, temp, key, section, key_data = [slot + a for a in (0, 0x100, 0x300, 0x500, 0x600, 0x700)]
            key_bytes = (keys[index] + '\0').encode('utf-16le')
            state.clear(); state.update(index=index, value=value, zero_length=zero_length,
                found=bool(found_mask & (1 << index)), dest=dest, dest_data=dest_data, temp=temp,
                key=key, key_data=key_data, section=section, key_bytes=key_bytes,
                hash=0x12345000 + index * 0x23, calls=[], native_copies=0, native_cleanups=0)
            uc.mem_write(dest - 8, b'\x5a' * 32); uc.mem_write(key, key_bytes)
            uc.mem_write(section, (('NnCoreSetting' if index == 0 else 'DemoSection') + '\0').encode('utf-16le'))
            uc.mem_write(stack - 0x1000, b'\x91' * 0x1100); uc.mem_write(stack, struct.pack('<Q', stop))
            for reg, val in ((x.UC_X86_REG_RCX, ignored_rcx), (x.UC_X86_REG_RDX, dest),
                             (x.UC_X86_REG_R8, section), (x.UC_X86_REG_R9, key), (x.UC_X86_REG_RSP, stack)):
                uc.reg_write(reg, val)
            uc.emu_start(ROOTS[0], stop, count=2048)
            if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RSP) != stack + 8:
                raise ValueError('Нет полного native возврата reader')
            calls = ['lookup'] + (['assign_string'] if state['found'] else [])
            calls += ['construct_key', 'append_bit', 'hash_key', 'uniqueness_false']
            calls += ['free_temp'] if state['found'] and not zero_length else []
            calls += ['check_cookie']
            if state['calls'] != calls or (state['native_copies'], state['native_cleanups']) != (2, 2):
                raise ValueError('Неверные calls / native copy / cleanup')
            if (integer(CONTAINER + 8), integer(CONTAINER + 0x28), integer(CONTAINER + 0x10), integer(CONTAINER + 0x38)) != (
                    index + 1, index + 1, (1 << (index + 1)) - 1, index):
                raise ValueError('Неверные container count / bitmap / bucket')
            node = entries + index * 0xb0
            expected_fields = {0: key_data, 0x10: dest, 0x20: 0x1445c78d0, 0x30: 0,
                0x40: payload.TABLE, 0x48: dest, 0x60: 0x1445c7970, 0x70: 0, 0x80: payload.TABLE, 0x88: dest}
            if any(qword(node + at) != expected for at, expected in expected_fields.items()):
                raise ValueError('Неверные сохранённые key / callable captures')
            if (integer(node + 8), integer(node + 12), integer(node + 0xa0), integer(node + 0xa4)) != (
                    len(key_bytes) // 2, len(key_bytes) // 2, index - 1, 0):
                raise ValueError('Неверные key length / native collision chain')
            if bytes(uc.mem_read(dest - 8, 8)) != b'\x5a' * 8 or bytes(uc.mem_read(dest + 16, 8)) != b'\x5a' * 8:
                raise ValueError('Повреждена граница destination')
            expected_dest = b'\x5a' * 16
            if state['found']:
                length = len(value.encode('utf-16le')) // 2
                expected_dest = struct.pack('<Qii', dest_data if length else 0, length + 1 if length else 0, length + 1 if length else 0)
            if bytes(uc.mem_read(dest, 16)) != expected_dest: raise ValueError('Destination изменён после fixture присваивания')
            if bytes(uc.mem_read(state['moved_key_object'], 16)) != bytes(16):
                raise ValueError('Source key FString не очищен native переносом')
            retained.append((node, dict(expected_fields), key_bytes, dest, expected_dest, value))
            for old_node, old_fields, old_key, old_dest, old_dest_bytes, old_value in retained:
                if any(qword(old_node + at) != expected for at, expected in old_fields.items()):
                    raise ValueError('Позднее чтение изменило сохранённый capture / key')
                if bytes(uc.mem_read(old_fields[0], len(old_key))) != old_key or bytes(uc.mem_read(old_dest, 16)) != old_dest_bytes:
                    raise ValueError('Позднее чтение повредило key bytes / destination')
                if old_dest_bytes != b'\x5a' * 16 and old_value:
                    expected_data = old_value.encode('utf-16le') + b'\0\0'
                    if bytes(uc.mem_read(qword(old_dest), len(expected_data))) != expected_data:
                        raise ValueError('Повреждён результат string assignment fixture')
            sequence.append(dict(index=index, found_fixture=state['found'], value_fixture=value,
                zero_length_fixture=zero_length, calls=calls, native_capture_copies=2, native_cleanups=2,
                saved_capture=hex(dest), complete_reader_return=True, moved_key_source_cleared=True,
                previous_bindings_preserved=index))
        if bytes(uc.mem_read(entries - 8, 8)) != b'\xa5' * 8 or bytes(uc.mem_read(entries + 3 * 0xb0, 0xb0 + 8)) != b'\xa5' * (0xb0 + 8):
            raise ValueError('Запись за три native элемента')
        chain = []; current = integer(CONTAINER + 0x38)
        while current != -1:
            if current not in range(3) or current in chain: raise ValueError('Повреждён native bucket chain / цикл')
            chain.append(current); current = integer(entries + current * 0xb0 + 0xa0)
        if chain != [2, 1, 0]: raise ValueError('Потерян элемент native bucket chain')
        results.append(dict(found_mask=found_mask, group=group, ignored_rcx=hex(ignored_rcx), sequence=sequence,
            retained_bindings=3, native_bucket_chain=chain))
    return dict(source_sha256=getter.SHA, fragments=fragments, cases=results,
        fixtures=list(FIXTURES.values()) + ['lookup'],
        limits=['Native reader, insertion, paired capture copy and inline cleanup execute together completely.',
            'Global config object is present; preallocated container holds exactly three new entries without growth or reuse.',
            'Lookup, FString construction/assignment, bit append, key hash, uniqueness, temporary free and cookie service are fixtures.',
            'Uniqueness always returns false; duplicate / replacement / errors / rehash / allocation growth not covered.',
            'No later callable dispatch, precedence, live settings, successful resource loading or Brush binding proof.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = run(json.loads(args.request.read_text('utf-8')))
    result['replay_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(sequences=len(result['cases']), reader_calls=sum(len(c['sequence']) for c in result['cases']))))
