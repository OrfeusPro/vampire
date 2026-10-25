"""Native binding consumers: lookup, captured read clone and write forwarding on synthetic storage."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('consumer_hash', HERE / 'replay-ui-config-hash.py')
key_hash = importlib.util.module_from_spec(spec); spec.loader.exec_module(key_hash)
native, getter, unicorn, x = key_hash.native, key_hash.getter, key_hash.unicorn, key_hash.x
ROOTS = (0x1445cbd00, 0x1445d6ec0, 0x1445c78d0, 0x1445c67a0, 0x141425d60, 0x1445c29f0)
CONTAINER = 0x14b186130
FIXTURES = {0x141426b30: 'query_string', 0x141483080: 'free_query',
            0x141436ed0: 'allocate_clone', 0x1487f5ab9: 'copy_clone', 0x1414277b0: 'assign_value'}


def run(request, native_assignment=False):
    if request['source_sha256'] != getter.SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Другой источник / вопрос')
    roots = ROOTS + (0x1414277b0,) if native_assignment else ROOTS
    fixtures = dict(FIXTURES)
    if native_assignment:
        del fixtures[0x1414277b0]
        fixtures[0x141438050] = 'resize_value'
    if not {hex(a) for a in roots} <= {f['address'] for f in request['functions']}:
        raise ValueError('Нет явных consumer roots')
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
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    for at, pair in {0x1445cbda0: ('call', 'qword ptr [rax + 8]'),
                     0x1445cbda9: ('call', 'rbx'), 0x1445d6f68: ('call', 'qword ptr [rax + 8]'),
                     0x1445d6f73: ('call', 'rbx')}.items():
        if (rows[at]['mnemonic'], rows[at]['operands']) != pair:
            raise ValueError('Изменилась native invoke цепочка')
    key_hash.table_bytes(image)
    ranges = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']) for f in fragments]
    leaves = {0x14140e2f0: '488d4108c3', key_hash.uniqueness.COMPARE: key_hash.uniqueness.COMPARE_HEX,
              0x1445c7970: '488b12488b09e935fee5fc'}
    for address, encoded in leaves.items():
        data = bytes.fromhex(encoded); offset = image.offset(address - image.pe.base)
        if image.containing(address) is not None or raw[offset:offset + len(data)] != data:
            raise ValueError('Изменился ранее проверенный leaf')
        if raw[offset + len(data):offset + len(data) + 4] != b'\xcc' * 4:
            raise ValueError('Изменился leaf padding')
        ranges.append((address, address + len(data)))
    table = key_hash.uniqueness.payload.TABLE
    offset = image.offset(table - image.pe.base)
    if struct.unpack_from('<4Q', raw, offset) != (0x141421b50, 0x14140e2f0, 0x141421b70, 0x141421b80):
        raise ValueError('Изменилась capture table')
    offset = image.offset(key_hash.uniqueness.ASCII_TABLE - image.pe.base)
    if raw[offset:offset + 128] != bytes(a + 32 if 65 <= a <= 90 else a for a in range(128)):
        raise ValueError('Изменилась compare table')
    pages = {p for a, b in ranges for p in range(a & ~4095, (b + 4095) & ~4095, 4096)}
    pages.update(a & ~4095 for f in fragments for r in f['instructions'] for a in r['rip_references'])
    pages.update(a & ~4095 for a in (*fixtures, table, key_hash.TABLE, key_hash.uniqueness.ASCII_TABLE))
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page, 4096)
        try: offset = image.offset(page - image.pe.base)
        except ValueError: continue
        uc.mem_write(page, raw[offset:offset + 4096])
    base = 0x20000000; uc.mem_map(base, 0x30000)
    entries, buckets, query, query_data, output, output_data, new_data, stack, stop = [base + a for a in
        (0x1000, 0x2000, 0x3000, 0x3100, 0x4000, 0x5000, 0x6000, 0x20008, 0x2f000)]
    state = {}
    def qword(at): return int.from_bytes(uc.mem_read(at, 8), 'little')
    def ret(result):
        sp = uc.reg_read(x.UC_X86_REG_RSP); uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, qword(sp)); uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
    def hook(machine, address, size, unused):
        if address not in fixtures:
            if not any(a <= address and address + size <= b for a, b in ranges):
                raise ValueError('Исполнение вне consumer chain: ' + hex(address))
            if address == 0x1445c78d0: state['read_invokes'] += 1
            if address == 0x1445c7970: state['write_invokes'] += 1
            if address == 0x14140e2f0: state['capture_getters'] += 1
            if address == 0x1414277b0: state['native_assignments'] += 1
            return
        rcx, rdx, r8 = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        name = fixtures[address]; state['calls'].append(name)
        if name == 'query_string':
            if rdx != query: raise ValueError('Другой query pointer')
            data = state['query'].encode('utf-16le') + b'\0\0'
            uc.mem_write(query_data, data); uc.mem_write(rcx, struct.pack('<Qii', query_data, len(data) // 2, len(data) // 2))
            ret(rcx)
        elif name == 'free_query':
            if rcx != query_data: raise ValueError('Освобождается не query')
            uc.mem_write(rcx, b'\xdd' * (len(state['query'].encode('utf-16le')) + 2)); ret(0)
        elif name == 'allocate_clone':
            if rdx != state['expected_count'] or r8 != 0: raise ValueError('Неверный clone allocation count')
            if bytes(uc.mem_read(rcx, 12)) != struct.pack('<Qi', 0, rdx): raise ValueError('Clone временная строка не обнулена')
            uc.mem_write(rcx, struct.pack('<Q', output_data)); uc.mem_write(rcx + 12, struct.pack('<i', rdx + 3)); ret(0)
        elif name == 'copy_clone':
            expected = (state['destination_data'], new_data, len((state['new_value'] + '\0').encode('utf-16le'))) if state['phase'] == 1 else (
                output_data, state['expected_data'], state['expected_count'] * 2)
            if (rcx, rdx, r8) != expected:
                raise ValueError('Неверные clone copy arguments')
            uc.mem_write(rcx, bytes(uc.mem_read(rdx, r8))); ret(rcx)
        elif name == 'resize_value':
            count = len((state['new_value'] + '\0').encode('utf-16le')) // 2
            if (rcx, rdx) != (state['destination'], count) or bytes(uc.mem_read(rcx + 8, 4)) != bytes(4):
                raise ValueError('Неверные native assignment resize аргументы / count reset')
            state['assigned_capacity'] = count + 7
            uc.mem_write(rcx, struct.pack('<Q', state['destination_data']))
            uc.mem_write(rcx + 12, struct.pack('<i', state['assigned_capacity'])); ret(0)
        else:
            if (rcx, rdx) != (state['destination'], new_data): raise ValueError('Write invoke выбрал другой destination / value')
            encoded = state['new_value'].encode('utf-16le') + b'\0\0'
            target = state['destination_data']; uc.mem_write(target, encoded)
            uc.mem_write(rcx, struct.pack('<Qii', target, len(encoded) // 2, len(encoded) // 2)); ret(rcx)
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    def execute(entry, rcx, rdx):
        state.update(calls=[], read_invokes=0, write_invokes=0, capture_getters=0, native_assignments=0)
        uc.mem_write(stack - 0x1000, b'\x91' * 0x1100); uc.mem_write(stack, struct.pack('<Q', stop))
        for reg, value in ((x.UC_X86_REG_RCX, rcx), (x.UC_X86_REG_RDX, rdx), (x.UC_X86_REG_RSP, stack)):
            uc.reg_write(reg, value)
        uc.emu_start(entry, stop, count=8192)
        if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RSP) != stack + 8:
            raise ValueError('Нет полного consumer возврата')
    keys = ('ContentSubName', 'Demo.Second', 'Тест')
    queries = [('ContentSubName', 0), ('contentsubname', 0), ('Demo.Second', 1), ('Тест', 2), ('тест', None), ('Missing', None)]
    cases = []
    for original in (None, '', 'RED', 'Тест', 'A😀', 'A/B', 'Long' * 20, 'A\0B'):
        for external in (False, True):
            for query_value, target_index in queries:
                model = bytearray(0x60); struct.pack_into('<Qii', model, 0, entries, 3, 4)
                struct.pack_into('<Q', model, 0x40, buckets); struct.pack_into('<i', model, 0x48, 8)
                uc.mem_write(CONTAINER, bytes(model)); heads = [-1] * 8
                for index, key in enumerate(keys):
                    slot = base + 0x8000 + index * 0x2000
                    key_pointer, dest, dest_data, capture1, capture2 = [slot + a for a in (0, 0x400, 0x500, 0xc00, 0xd00)]
                    data = (key + '\0').encode('utf-16le'); uc.mem_write(key_pointer, data)
                    value = original if index == target_index else 'Other' + str(index)
                    encoded = value.encode('utf-16le') + b'\0\0' if value is not None else b''
                    uc.mem_write(dest_data, encoded + b'\x7a' * 8)
                    uc.mem_write(dest - 8, b'\xa5' * 8 + struct.pack('<Qii', dest_data if encoded else 0, len(encoded) // 2, len(encoded) // 2) + b'\xa5' * 8)
                    node = bytearray(0xb0); node[:16] = struct.pack('<Qii', key_pointer, len(data) // 2, len(data) // 2)
                    struct.pack_into('<Q', node, 0x10, dest)
                    for at, invoke, storage in ((0x20, 0x1445c78d0, capture1), (0x60, 0x1445c7970, capture2)):
                        struct.pack_into('<Q', node, at, invoke); struct.pack_into('<Q', node, at + 0x10, storage if external else 0)
                        struct.pack_into('<QQ', node, at + 0x20, table, dest); uc.mem_write(storage, struct.pack('<QQ', table, dest))
                    bucket = key_hash.reference(data[:-2], len(data) // 2 - 1) & 7
                    struct.pack_into('<ii', node, 0xa0, heads[bucket], bucket); heads[bucket] = index
                    uc.mem_write(entries + index * 0xb0, bytes(node))
                uc.mem_write(buckets, struct.pack('<8i', *heads)); uc.mem_write(query, (query_value + '\0').encode('utf-16le'))
                state.clear(); state.update(query=query_value, new_value='Updated😀', destination=base + 0x8400 + (target_index or 0) * 0x2000,
                    destination_data=base + 0x8500 + (target_index or 0) * 0x2000)
                before_container = bytes(uc.mem_read(CONTAINER, 0x60)); before_entries = bytes(uc.mem_read(entries, 0x210))
                before_values = [bytes(uc.mem_read(base + 0x8400 + i * 0x2000 - 8, 32)) for i in range(3)]
                before_data = [bytes(uc.mem_read(base + 0x8500 + i * 0x2000, 256)) for i in range(3)]
                reads = []
                for phase in range(3):
                    state['phase'] = phase
                    if phase == 1:
                        state['assigned_capacity'] = int.from_bytes(uc.mem_read(state['destination'] + 12, 4), 'little')
                        uc.mem_write(new_data, (state['new_value'] + '\0').encode('utf-16le'))
                        execute(0x1445d6ec0, query, new_data)
                        if (state['write_invokes'], state['read_invokes'], state['capture_getters']) != (int(target_index is not None), 0, int(target_index is not None)):
                            raise ValueError('Неверный write invoke / capture getter')
                        expected_calls = ['query_string', 'free_query']
                        if target_index is not None:
                            if native_assignment:
                                new_count = len((state['new_value'] + '\0').encode('utf-16le')) // 2
                                if state['assigned_capacity'] != new_count: expected_calls.append('resize_value')
                                expected_calls.append('copy_clone')
                            else: expected_calls.append('assign_value')
                        if state['native_assignments'] != int(native_assignment and target_index is not None):
                            raise ValueError('Assignment body не исполнен native')
                    else:
                        encoded = (original.encode('utf-16le') + b'\0\0') if phase == 0 and original is not None else b''
                        if phase == 2: encoded = (state['new_value'] + '\0').encode('utf-16le')
                        state['expected_count'] = len(encoded) // 2
                        state['expected_data'] = state['destination_data']
                        uc.mem_write(output - 8, b'\xa5' * 32); uc.mem_write(output_data, b'\x5a' * 512)
                        execute(0x1445cbd00, output, query)
                        if uc.reg_read(x.UC_X86_REG_RAX) != output: raise ValueError('Read consumer не вернул output')
                        expected = bytes(16)
                        if target_index is not None and encoded:
                            expected = struct.pack('<Qii', output_data, len(encoded) // 2, len(encoded) // 2 + 3)
                            if bytes(uc.mem_read(output_data, len(encoded) + 8)) != encoded + b'\x5a' * 8:
                                raise ValueError('Неверный independent clone / copy guard')
                        if bytes(uc.mem_read(output - 8, 32)) != b'\xa5' * 8 + expected + b'\xa5' * 8:
                            raise ValueError('Неверные read fields / miss / guards')
                        if (state['read_invokes'], state['write_invokes'], state['capture_getters']) != (int(target_index is not None), 0, int(target_index is not None)):
                            raise ValueError('Неверный read invoke / capture getter')
                        expected_calls = ['query_string', 'free_query'] + (['allocate_clone', 'copy_clone'] if target_index is not None and encoded else [])
                        reads.append(dict(after_write=phase == 2, clone_units=len(encoded) // 2 if target_index is not None else 0,
                            missing_zeroed=target_index is None))
                    if state['calls'] != expected_calls: raise ValueError('Неверный порядок consumer services')
                    if bytes(uc.mem_read(CONTAINER, 0x60)) != before_container or bytes(uc.mem_read(entries, 0x210)) != before_entries:
                        raise ValueError('Consumer изменил binding container')
                    for index in range(3):
                        at = base + 0x8400 + index * 0x2000
                        if phase == 0 or index != target_index:
                            if bytes(uc.mem_read(at - 8, 32)) != before_values[index] or bytes(uc.mem_read(at + 0x100, 256)) != before_data[index]:
                                raise ValueError('Изменён посторонний destination / source clone')
                        else:
                            encoded = (state['new_value'] + '\0').encode('utf-16le')
                            expected = struct.pack('<Qii', at + 0x100, len(encoded) // 2,
                                state['assigned_capacity'] if native_assignment else len(encoded) // 2)
                            if bytes(uc.mem_read(at - 8, 32)) != b'\xa5' * 8 + expected + b'\xa5' * 8:
                                raise ValueError('Write fixture не сохранил value / guards')
                cases.append(dict(original_fixture=original, external_capture=external, query=query_value,
                    target_index=target_index, reads=reads, native_read_invokes=2 * int(target_index is not None),
                    native_write_invokes=int(target_index is not None), complete_consumer_calls=3,
                    native_assignment_calls=int(native_assignment and target_index is not None)))
    return dict(source_sha256=getter.SHA, fragments=fragments, cases=cases, native_assignment=native_assignment,
        limits=['Native consumers/hash/lookup/compare/capture-address/read-clone and setter leaf execute together.',
            ('Query string, query free, clone allocation/byte copy and value resize are fixtures; target assignment body is native.' if native_assignment else
             'Query string, query free, clone allocation/byte copy and target string assignment are fixtures.'),
            'Bindings are synthetic initialized records matching previously proved layout, not registration-to-dispatch integration.',
            'Read consumer requires valid active callable for a found binding; invalid/inactive state not modeled.',
            'No caller/event source, config precedence, active settings, actual allocator or Brush binding proof.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-assignment', action='store_true')
    args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = run(json.loads(args.request.read_text('utf-8')), args.native_assignment)
    result['replay_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(cases=len(result['cases']), consumer_calls=sum(c['complete_consumer_calls'] for c in result['cases']))))
