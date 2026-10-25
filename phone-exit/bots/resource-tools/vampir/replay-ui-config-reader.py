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
spec = importlib.util.spec_from_file_location('reader_uniqueness', HERE / 'replay-ui-config-uniqueness.py')
uniqueness = importlib.util.module_from_spec(spec); spec.loader.exec_module(uniqueness)
spec = importlib.util.spec_from_file_location('reader_hash', HERE / 'replay-ui-config-hash.py')
key_hash = importlib.util.module_from_spec(spec); spec.loader.exec_module(key_hash)
native, getter, unicorn, x = payload.native, payload.getter, payload.unicorn, payload.x
ROOTS = (0x1445c2c30, 0x1445c1f50, 0x1445c4f60, 0x141421b80)
REPLACEMENT_ROOTS = ROOTS + (0x1445d8430, 0x1445c29f0)
HASH_ROOTS = REPLACEMENT_ROOTS + (key_hash.HASH,)
DISPATCH_ROOTS = HASH_ROOTS + (0x1445cbd00, 0x1445d6ec0, 0x1445c78d0, 0x1445c67a0, 0x1414277b0)
CONTAINER = 0x14b186130
FIXTURES = {0x14142a250: 'assign_string', 0x141426b30: 'construct_key',
    0x141429680: 'append_bit', 0x141425d60: 'hash_key', 0x1445d8430: 'uniqueness_false',
    0x141483080: 'free_temp', 0x1487e8ce0: 'check_cookie'}


def run(request, native_replacement=False, native_hash=False, dispatch=False):
    if request['source_sha256'] != getter.SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Другой источник / вопрос')
    if native_hash and not native_replacement: raise ValueError('Native hash требует native replacement режима')
    if dispatch and not native_hash: raise ValueError('Dispatch требует native hash / replacement')
    roots = DISPATCH_ROOTS if dispatch else HASH_ROOTS if native_hash else REPLACEMENT_ROOTS if native_replacement else ROOTS
    fixtures = dict(FIXTURES)
    if native_replacement:
        del fixtures[0x1445d8430]
        fixtures[uniqueness.MOVE] = 'replace_payload'
        fixtures[0x141483080] = 'free_string'
    if native_hash: del fixtures[key_hash.HASH]
    if dispatch:
        fixtures.update({0x141436ed0: 'allocate_read', 0x1487f5ab9: 'copy_string', 0x141438050: 'resize_value'})
    if not {hex(a) for a in roots} <= {f['address'] for f in request['functions']}:
        raise ValueError('Не все явные roots входят в задание')
    if native.capstone.__version__ != '5.0.6' or unicorn.__version__ != '2.1.4':
        raise ValueError('Изменились закреплённые инструменты')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA: raise ValueError('Изменился EXE')
    image = native.Image(raw); selected = set()
    for address in roots:
        row = image.containing(address)
        if row is None or image.pe.base + image.roots[row][0] != address:
            raise ValueError('Изменился unwind root')
        selected.add(image.roots[row])
    fragments = native.decode_ranges(image, selected)
    if native_hash: key_hash.table_bytes(image)
    ranges = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']) for f in fragments]
    # Reuse the exact already-reviewed copy / capture-address / cleanup leaves, not guessed unwind ranges.
    leaves = dict(payload.LEAVES)
    if native_replacement: leaves[uniqueness.COMPARE] = uniqueness.COMPARE_HEX
    if dispatch: leaves[0x1445c7970] = '488b12488b09e935fee5fc'
    for address, expected_hex in leaves.items():
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
    pages.update(a & ~4095 for a in fixtures)
    pages.add(payload.TABLE & ~4095)
    if native_replacement:
        offset = image.offset(uniqueness.ASCII_TABLE - image.pe.base)
        if raw[offset:offset + 128] != bytes(a + 32 if 65 <= a <= 90 else a for a in range(128)):
            raise ValueError('Изменилась ASCII folding table')
        pages.add(uniqueness.ASCII_TABLE & ~4095)
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
        if address not in fixtures and address != lookup:
            if not any(a <= address and address + size <= b for a, b in ranges):
                raise ValueError('Исполнение вне выбранной полной цепочки: ' + hex(address))
            if address == 0x141421b50: state['native_copies'] += 1
            if address == 0x141421b80: state['native_cleanups'] += 1
            if dispatch and address == 0x1445c78d0: state['read_invokes'] += 1
            if dispatch and address == 0x1445c7970: state['write_invokes'] += 1
            if dispatch and address == 0x1414277b0: state['native_assignments'] += 1
            if address == 0x1445c1f50:
                state['moved_key_object'] = qword(uc.reg_read(x.UC_X86_REG_R8))
                state['returned_index_object'] = uc.reg_read(x.UC_X86_REG_RDX)
            if native_replacement and address == uniqueness.COMPARE: state['native_compares'] += 1
            if native_replacement and address == 0x1445c29f0: state['native_key_lookups'] += 1
            if native_hash and address == key_hash.HASH:
                if (uc.reg_read(x.UC_X86_REG_RCX), uc.reg_read(x.UC_X86_REG_RDX)) != (len(state['key_bytes']) // 2 - 1, state['key_data']):
                    raise ValueError('Неверные native hash аргументы')
                state['native_hash_calls'] += 1
            if native_hash and address == 0x141425dc9:
                actual = uc.reg_read(x.UC_X86_REG_RAX) & 0xffffffff
                if actual != key_hash.reference(state['key_bytes'][:-2], len(state['key_bytes']) // 2 - 1):
                    raise ValueError('Native hash расходится с bitwise reference')
                state['native_hash_result'] = actual
            return
        rcx, rdx, r8, r9 = [uc.reg_read(r) for r in
            (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        name = 'lookup' if address == lookup else fixtures[address]
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
            new_slot = state.get('new_slot', state['index'])
            if (rcx, rdx, integer(CONTAINER + 0x28)) != (CONTAINER + 0x10, 0, new_slot):
                raise ValueError('Неверное добавление occupancy bit')
            uc.mem_write(CONTAINER + 0x28, struct.pack('<i', new_slot + 1))
            ret(new_slot)
        elif name == 'hash_key':
            if (rcx, rdx) != (len(state['key_bytes']) // 2 - 1, state['key_data']):
                raise ValueError('Неверные аргументы key hash')
            ret(state['hash'])
        elif name == 'uniqueness_false':
            if (rcx, rdx, r8, integer(r9), qword(uc.reg_read(x.UC_X86_REG_RSP) + 0x28)) != (
                    CONTAINER, state['hash'], entries + state['index'] * 0xb0, state['index'], 0):
                raise ValueError('Неверные аргументы uniqueness helper')
            ret(0)  # exact new-entry scenario; duplicate / replacement path deliberately excluded
        elif name in ('free_temp', 'free_string'):
            if state.get('dispatch_phase') and rcx == state['key_data']:
                state['calls'][-1] = 'free_query'; uc.mem_write(rcx, b'\xdd' * len(state['key_bytes']))
            elif native_replacement and rcx == state['old_key_pointer']:
                state['calls'][-1] = 'free_old_key'
                uc.mem_write(rcx, b'\xdd' * state['old_key_size'])
            elif rcx == state['temp'] and state['found'] and not state['zero_length']:
                state['calls'][-1] = 'free_temp'
            else:
                raise ValueError('Освобождается key / capture / неподтверждённый temporary')
            ret()
        elif name == 'replace_payload':
            expected = (entries + state['result_slot'] * 0xb0, entries + state['new_slot'] * 0xb0, 0xa0)
            if (rcx, rdx, r8) != expected: raise ValueError('Неверный replacement memmove')
            uc.mem_write(rcx, bytes(uc.mem_read(rdx, r8))); ret(rcx)
        elif name == 'allocate_read':
            if (rdx, r8) != (state['expected_read_units'], 0) or bytes(uc.mem_read(rcx, 12)) != struct.pack('<Qi', 0, rdx):
                raise ValueError('Неверный read clone allocation / count reset')
            uc.mem_write(rcx, struct.pack('<Q', state['read_data']))
            uc.mem_write(rcx + 12, struct.pack('<i', rdx + 3)); ret(0)
        elif name == 'resize_value':
            if (rcx, rdx) != (state['dest'], state['new_units']) or bytes(uc.mem_read(rcx + 8, 4)) != bytes(4):
                raise ValueError('Неверный native assignment resize / count reset')
            uc.mem_write(rcx, struct.pack('<Q', state['dest_data']))
            uc.mem_write(rcx + 12, struct.pack('<i', rdx + 5)); ret(0)
        elif name == 'copy_string':
            expected = (state['read_data'], state['expected_read_pointer'], state['expected_read_units'] * 2) if state['dispatch_phase'] == 'read' else (
                state['dest_data'], state['new_data'], state['new_units'] * 2)
            if (rcx, rdx, r8) != expected: raise ValueError('Неверные read/write byte-copy аргументы')
            uc.mem_write(rcx, bytes(uc.mem_read(rdx, r8))); ret(rcx)
        else:
            if rcx != cookie: raise ValueError('Неверный stack cookie после полного reader')
            ret()
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    if native_replacement:
        results = replacement_sequences(uc, base, entries, stack, stop, state, native_hash, dispatch)
        return dict(source_sha256=getter.SHA, fragments=fragments, cases=results,
            fixtures=list(fixtures.values()) + ['lookup'], native_replacement=True, native_hash=native_hash, dispatch=dispatch,
            limits=['Whole native reader/insertion/lookup/compare/replacement/capture-copy/cleanup on one memory.',
                '384 six-call sequences; preallocated four slots, three live keys; no allocation growth or rehash.',
                ('Registration lookup/initial FString assignment/key construction/bit append/free/memmove/cookie and consumer allocation/copy/resize are fixtures; consumer assignment/hash are native.' if dispatch else
                 'Lookup, FString construction/assignment, bit append, string free, memmove and cookie are fixtures; hash is native.' if native_hash else
                 'Lookup, FString construction/assignment, bit append, hash, string free, memmove and cookie are fixtures.'),
                'Old key free poisons its synthetic storage; actual allocator and general ownership not executed.',
                ('Registered callable read/write executes natively; caller/event, persistence, config precedence and Brush unknown.' if dispatch else
                 'Later callable invocation, config precedence, active settings and Brush binding unknown.')])
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


def replacement_sequences(uc, base, entries, stack, stop, state, native_hash=False, dispatch=False):
    def integer(at): return int.from_bytes(uc.mem_read(at, 4), 'little', signed=True)
    def qword(at): return int.from_bytes(uc.mem_read(at, 8), 'little')
    keys = ('ContentSubName', 'contentsubname', 'Demo.Second', 'Demo.Second', 'Demo.Third', 'CONTENTSUBNAME')
    logical_keys = (0, 0, 1, 1, 2, 0)
    new_slots, result_slots = (0, 1, 1, 2, 2, 3), (0, 0, 1, 1, 2, 0)
    allocated_counts, live_masks = (1, 2, 2, 3, 3, 4), (1, 1, 3, 3, 7, 7)
    free_heads = (-1, 1, -1, 2, -1, 3)
    groups = [(('RED', False), ('Other', False), ('', False), ('Again', False), ('Тест', False), ('A/B', False)),
              (('', False), ('Тест', False), ('A😀', False), ('', True), ('Alt', False), ('X😀', False)),
              (('', True), ('A/B', False), ('Long' * 20, False), ('Last', False), ('', False), ('END', False))]
    results = []; bucket_count = 8 if native_hash else 1; bucket_storage = base + 0x6000
    for found_mask, group, shared_destination in itertools.product(range(64), range(3), (False, True)):
        uc.mem_write(CONTAINER, bytes(0x60)); uc.mem_write(CONTAINER, struct.pack('<Qii', entries, 0, 4))
        uc.mem_write(CONTAINER + 0x28, struct.pack('<iiii', 0, 128, -1, 0))
        uc.mem_write(CONTAINER + 0x38, struct.pack('<i', -1)); uc.mem_write(CONTAINER + 0x48, struct.pack('<i', bucket_count))
        if native_hash: uc.mem_write(CONTAINER + 0x40, struct.pack('<Q', bucket_storage))
        uc.mem_write(bucket_storage, b'\xff' * (bucket_count * 4))
        uc.mem_write(entries - 8, b'\xa5' * (0xb0 * 4 + 16))
        live = {}; destinations = {}; sequence = []; bucket_heads = [-1] * bucket_count; node_links = {}
        for index, (value, zero_length) in enumerate(groups[group]):
            slot = base + 0x8000 + index * 0x1000
            target = base + 0x8000 + (logical_keys[index] if shared_destination else index) * 0x1000
            dest, dest_data = target, target + 0x100
            temp, key, section, key_data = [slot + at for at in (0x300, 0x500, 0x600, 0x700)]
            new_slot, result_slot = new_slots[index], result_slots[index]
            replacement = new_slot != result_slot
            old_key_pointer = live[result_slot][0][0] if replacement else None
            old_key_size = len(live[result_slot][1]) if replacement else 0
            key_bytes = (keys[index] + '\0').encode('utf-16le')
            state.clear(); state.update(index=index, new_slot=new_slot, result_slot=result_slot,
                value=value, zero_length=zero_length, found=bool(found_mask & (1 << index)),
                dest=dest, dest_data=dest_data, temp=temp, key=key, key_data=key_data,
                section=section, key_bytes=key_bytes, hash=0x12345000 + index * 0x23,
                old_key_pointer=old_key_pointer, old_key_size=old_key_size,
                calls=[], native_copies=0, native_cleanups=0, native_compares=0, native_key_lookups=0,
                native_hash_calls=0, native_hash_result=None)
            if dispatch: state.update(read_invokes=0, write_invokes=0, native_assignments=0)
            if dest not in destinations:
                uc.mem_write(dest - 8, b'\x5a' * 8 + bytes(16) + b'\x5a' * 8)
                destinations[dest] = (bytes(16), None)
            uc.mem_write(key, key_bytes)
            uc.mem_write(section, (('NnCoreSetting' if index == 0 else 'DemoSection') + '\0').encode('utf-16le'))
            uc.mem_write(stack - 0x1000, b'\x91' * 0x1100); uc.mem_write(stack, struct.pack('<Q', stop))
            for reg, val in ((x.UC_X86_REG_RCX, 0), (x.UC_X86_REG_RDX, dest),
                             (x.UC_X86_REG_R8, section), (x.UC_X86_REG_R9, key), (x.UC_X86_REG_RSP, stack)):
                uc.reg_write(reg, val)
            uc.emu_start(ROOTS[0], stop, count=4096)
            if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RSP) != stack + 8:
                raise ValueError('Нет полного native reader возврата с replacement')
            calls = ['lookup'] + (['assign_string'] if state['found'] else []) + ['construct_key']
            if index in (0, 1, 3, 5): calls.append('append_bit')
            if not native_hash: calls.append('hash_key')
            if replacement: calls += ['free_old_key', 'replace_payload']
            if state['found'] and not zero_length: calls.append('free_temp')
            calls.append('check_cookie')
            if state['calls'] != calls or (state['native_copies'], state['native_cleanups']) != (2, 4 if replacement else 2):
                raise ValueError('Неверный общий service / native copy / cleanup path')
            if (state['native_key_lookups'], state['native_compares']) != (int(index != 0), int(replacement)):
                raise ValueError('Не исполнен ожидаемый native lookup / compare')
            if state['native_hash_calls'] != int(native_hash): raise ValueError('Не исполнен native hash')
            bucket = (key_hash.reference(key_bytes[:-2], len(key_bytes) // 2 - 1) if native_hash else 0) & (bucket_count - 1)
            if replacement:
                if node_links[result_slot][1] != bucket: raise ValueError('Equal ключи попали в разные buckets')
            else:
                node_links[result_slot] = (bucket_heads[bucket], bucket); bucket_heads[bucket] = result_slot
            if integer(state['returned_index_object']) != result_slot:
                raise ValueError('Insertion не вернул индекс сохранённой привязки')
            if bytes(uc.mem_read(state['moved_key_object'], 16)) != bytes(16):
                raise ValueError('Source key не очищен после native переноса')
            expected_container = (allocated_counts[index], allocated_counts[index], live_masks[index],
                free_heads[index], int(replacement), bucket_heads[0] if bucket_count == 1 else -1)
            if tuple(integer(CONTAINER + at) for at in (8, 0x28, 0x10, 0x30, 0x34, 0x38)) != expected_container:
                raise ValueError('Неверные counts / occupancy / free-list / bucket после reuse')
            if (qword(CONTAINER), integer(CONTAINER + 12), qword(CONTAINER + 0x20),
                    qword(CONTAINER + 0x40), integer(CONTAINER + 0x48)) != (entries, 4, 0, bucket_storage if native_hash else 0, bucket_count):
                raise ValueError('Изменились preallocated storage / capacity / inline bucket')
            if native_hash and [integer(bucket_storage + b * 4) for b in range(bucket_count)] != bucket_heads:
                raise ValueError('Native hash bucket headers расходятся с oracle')
            if replacement:
                if (integer(entries + new_slot * 0xb0), integer(entries + new_slot * 0xb0 + 4)) != (-1, -1):
                    raise ValueError('Неверные поля освобождённого временного слота')
                if bytes(uc.mem_read(old_key_pointer, old_key_size)) != b'\xdd' * old_key_size:
                    raise ValueError('Old key free fixture не пометил storage')
            fields = {0: key_data, 0x10: dest, 0x20: 0x1445c78d0, 0x30: 0,
                0x40: payload.TABLE, 0x48: dest, 0x60: 0x1445c7970, 0x70: 0,
                0x80: payload.TABLE, 0x88: dest}
            live[result_slot] = (fields, key_bytes)
            if state['found']:
                length = len(value.encode('utf-16le')) // 2
                destinations[dest] = (struct.pack('<Qii', dest_data if length else 0,
                    length + 1 if length else 0, length + 1 if length else 0), value)
            for live_slot, (expected_fields, expected_key) in live.items():
                node = entries + live_slot * 0xb0
                if any(qword(node + at) != expected for at, expected in expected_fields.items()):
                    raise ValueError('Повреждены retained native captures / key')
                if (integer(node + 8), integer(node + 12), integer(node + 0xa0), integer(node + 0xa4)) != (
                        len(expected_key) // 2, len(expected_key) // 2, *node_links[live_slot]):
                    raise ValueError('Повреждены key count / capacity / hash links')
                if bytes(uc.mem_read(expected_fields[0], len(expected_key))) != expected_key:
                    raise ValueError('Live key ссылается на освобождённый storage')
            for old_dest, (expected_bytes, expected_value) in destinations.items():
                if bytes(uc.mem_read(old_dest - 8, 32)) != b'\x5a' * 8 + expected_bytes + b'\x5a' * 8:
                    raise ValueError('Повреждён destination / guard при регистрации другого ключа')
                if expected_value:
                    encoded = expected_value.encode('utf-16le') + b'\0\0'
                    if bytes(uc.mem_read(qword(old_dest), len(encoded))) != encoded:
                        raise ValueError('Повреждены bytes assignment fixture')
            sequence.append(dict(index=index, key_fixture=keys[index], found_fixture=state['found'],
                new_slot=new_slot, retained_slot=result_slot, replacement=replacement,
                reused_slot=index in (2, 4), calls=calls, native_capture_copies=state['native_copies'],
                native_cleanups=state['native_cleanups'], native_key_lookups=state['native_key_lookups'],
                native_compares=state['native_compares'], native_hash_calls=state['native_hash_calls'],
                native_hash_result=state['native_hash_result'], complete_reader_return=True))
        if bytes(uc.mem_read(entries - 8, 8)) != b'\xa5' * 8 or bytes(uc.mem_read(entries + 4 * 0xb0, 8)) != b'\xa5' * 8:
            raise ValueError('Запись за preallocated storage')
        chains = []; seen = []
        for b in range(bucket_count):
            chain = []; current = integer(bucket_storage + b * 4) if native_hash else integer(CONTAINER + 0x38)
            while current != -1:
                if current not in live or current in seen or node_links[current][1] != b:
                    raise ValueError('Повреждён native bucket chain / цикл')
                chain.append(current); seen.append(current); current = integer(entries + current * 0xb0 + 0xa0)
            chains.append(chain)
        if set(seen) != set(live): raise ValueError('Потеряна сохранённая привязка')
        dispatch_results = dispatch_registered(uc, base, entries, stack, stop, state, live, destinations) if dispatch else []
        results.append(dict(found_mask=found_mask, group=group, shared_destination=shared_destination,
            sequence=sequence, live_bindings=3, free_slot=3, bucket_count=bucket_count,
            native_bucket_chain=chains[0], native_bucket_chains=chains, dispatch_calls=dispatch_results))
    return results


def dispatch_registered(uc, base, entries, stack, stop, state, live, destinations):
    def qword(at): return int.from_bytes(uc.mem_read(at, 8), 'little')
    snapshot = bytes(uc.mem_read(CONTAINER, 0x60)), bytes(uc.mem_read(entries - 8, 0xb0 * 4 + 16)), bytes(uc.mem_read(base + 0x6000, 32))
    query, query_data, output, read_data, new_data = [base + a for a in (0x17000, 0x18000, 0x19000, 0x1a000, 0x1b000)]
    results = []
    for key, slot in (('contentsubname', 0), ('Demo.Second', 1), ('Demo.Third', 2), ('Missing', None)):
        fields = live[slot][0] if slot is not None else None
        dest = fields[0x10] if fields else 0
        new_value = 'Saved😀' + str(slot); encoded_new = (new_value + '\0').encode('utf-16le')
        uc.mem_write(new_data, encoded_new)
        key_bytes = (key + '\0').encode('utf-16le'); uc.mem_write(query, key_bytes)
        for phase in ('read_before', 'write', 'read_after'):
            expected_dest = destinations[dest][0] if fields else bytes(16)
            read_pointer, read_units, old_capacity = struct.unpack('<Qii', expected_dest)
            state.clear(); state.update(index=0, key=query, key_data=query_data, key_bytes=key_bytes,
                dest=dest, dest_data=dest + 0x100 if fields else 0, dispatch_phase='write' if phase == 'write' else 'read',
                calls=[], native_copies=0, native_cleanups=0, native_compares=0, native_key_lookups=0,
                native_hash_calls=0, native_hash_result=None, read_invokes=0, write_invokes=0, native_assignments=0,
                read_data=read_data, expected_read_pointer=read_pointer, expected_read_units=read_units,
                new_data=new_data, new_units=len(encoded_new) // 2)
            before_data = bytes(uc.mem_read(read_pointer, read_units * 2)) if read_pointer else b''
            uc.mem_write(output - 8, b'\xa5' * 32); uc.mem_write(read_data, b'\x6a' * 512)
            uc.mem_write(stack - 0x1000, b'\x91' * 0x1100); uc.mem_write(stack, struct.pack('<Q', stop))
            for reg, value in ((x.UC_X86_REG_RCX, query if phase == 'write' else output),
                              (x.UC_X86_REG_RDX, new_data if phase == 'write' else query), (x.UC_X86_REG_RSP, stack)):
                uc.reg_write(reg, value)
            uc.emu_start(0x1445d6ec0 if phase == 'write' else 0x1445cbd00, stop, count=8192)
            if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RSP) != stack + 8:
                raise ValueError('Нет полного registration → consumer возврата')
            calls = ['construct_key', 'free_query']
            if phase == 'write':
                if fields:
                    if old_capacity != state['new_units']: calls.append('resize_value')
                    calls.append('copy_string')
                    capacity = state['new_units'] + 5 if old_capacity != state['new_units'] else old_capacity
                    destinations[dest] = (struct.pack('<Qii', dest + 0x100, state['new_units'], capacity), new_value)
                if (state['write_invokes'], state['native_assignments'], state['read_invokes']) != (int(fields is not None), int(fields is not None), 0):
                    raise ValueError('Не вызвана зарегистрированная native write привязка')
            else:
                if fields and read_units: calls += ['allocate_read', 'copy_string']
                expected_output = struct.pack('<Qii', read_data, read_units, read_units + 3) if fields and read_units else bytes(16)
                if uc.reg_read(x.UC_X86_REG_RAX) != output or bytes(uc.mem_read(output - 8, 32)) != b'\xa5' * 8 + expected_output + b'\xa5' * 8:
                    raise ValueError('Неверный read из реально зарегистрированной привязки')
                if fields and read_units and bytes(uc.mem_read(read_data, len(before_data) + 8)) != before_data + b'\x6a' * 8:
                    raise ValueError('Clone не скопировал текущий destination / guard')
                if (state['read_invokes'], state['write_invokes'], state['native_assignments']) != (int(fields is not None), 0, 0):
                    raise ValueError('Не вызвана зарегистрированная native read привязка')
            if state['calls'] != calls or (state['native_hash_calls'], state['native_key_lookups'], state['native_compares']) != (1, 1, int(fields is not None)):
                raise ValueError('Неверные calls / lookup при интеграции registration → dispatch')
            actual_snapshot = bytes(uc.mem_read(CONTAINER, 0x60)), bytes(uc.mem_read(entries - 8, 0xb0 * 4 + 16)), bytes(uc.mem_read(base + 0x6000, 32))
            if actual_snapshot != snapshot: raise ValueError('Consumer изменил зарегистрированный контейнер / free slot')
            for old_dest, (expected, value) in destinations.items():
                if bytes(uc.mem_read(old_dest - 8, 32)) != b'\x5a' * 8 + expected + b'\x5a' * 8:
                    raise ValueError('Write изменил прежний или посторонний destination')
                if value:
                    data = (value + '\0').encode('utf-16le')
                    if bytes(uc.mem_read(qword(old_dest), len(data))) != data: raise ValueError('Повреждены destination bytes')
            for fields_live, key_live in live.values():
                if bytes(uc.mem_read(fields_live[0], len(key_live))) != key_live:
                    raise ValueError('Consumer повредил зарегистрированный key')
            results.append(dict(key=key, slot=slot, phase=phase, complete_return=True,
                native_read_invokes=state['read_invokes'], native_write_invokes=state['write_invokes'],
                native_assignments=state['native_assignments'], calls=calls))
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-replacement', action='store_true')
    parser.add_argument('--native-hash', action='store_true')
    parser.add_argument('--dispatch', action='store_true')
    args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = run(json.loads(args.request.read_text('utf-8')), args.native_replacement, args.native_hash, args.dispatch)
    result['replay_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(sequences=len(result['cases']), reader_calls=sum(len(c['sequence']) for c in result['cases']),
        consumer_calls=sum(len(c.get('dispatch_calls', [])) for c in result['cases']))))
