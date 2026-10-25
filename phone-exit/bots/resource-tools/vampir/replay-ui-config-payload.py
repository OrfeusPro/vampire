"""Native paired callable copy and capture cleanup; no config dispatch or live process access."""
import argparse
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('payload_refresh', HERE / 'replay-nktileview-refresh.py')
refresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(refresh)
native, getter, unicorn, x = refresh.native, refresh.getter, refresh.unicorn, refresh.x
ROOTS = (0x1445c4f60, 0x141421b80)
TABLE = 0x1489e4448
LEAVES = {0x141421b50: '488d05f1285c0748894210488d4218488b4908488908c3',
          0x14140e2f0: '488d4108c3', 0x141421b70: '488b0133d248ff6018'}
FREE = 0x141431f80


def run(request, leaf_request):
    for r in (request, leaf_request):
        if r['source_sha256'] != getter.SHA or r['question'] != 'ui-nktileview-property-schema':
            raise ValueError('Другой источник / вопрос')
    if not {hex(a) for a in ROOTS} <= {f['address'] for f in request['functions']}:
        raise ValueError('Нет явных roots')
    if not {hex(a) for a in LEAVES} <= {f['address'] for f in leaf_request['functions']}:
        raise ValueError('Нет явных leaf targets')
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
    table_offset = image.offset(TABLE - image.pe.base)
    table_bytes = raw[table_offset:table_offset + 32]
    if struct.unpack('<4Q', table_bytes) != (0x141421b50, 0x14140e2f0, 0x141421b70, 0x141421b80):
        raise ValueError('Изменились slots общей таблицы')
    leaves = []
    for address, expected_hex in LEAVES.items():
        if image.containing(address) is not None: raise ValueError('У leaf появилась unwind запись')
        offset = image.offset(address - image.pe.base); expected = bytes.fromhex(expected_hex)
        data = raw[offset:offset + len(expected)]
        if data != expected or raw[offset + len(expected):offset + len(expected) + 4] != b'\xcc' * 4:
            raise ValueError('Изменились точные leaf bytes / INT3 граница')
        leaves.append(dict(address=hex(address), bytes=data.hex(), sha256=getter.sha(data), boundary='exact leaf then INT3; no unwind'))
    ranges = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']) for f in fragments]
    ranges += [(a, a + len(bytes.fromhex(b))) for a, b in LEAVES.items()]
    pages = {p for a, b in ranges for p in range(a & ~4095, (b + 4095) & ~4095, 4096)}
    pages.update((TABLE & ~4095, FREE & ~4095))
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page, 4096); offset = image.offset(page - image.pe.base)
        uc.mem_write(page, raw[offset:offset + 4096])
    base = 0x20000000; uc.mem_map(base, 0x20000)
    source, output, heap1, heap2, stack, stop = [base + p for p in (0x1000, 0x3000, 0x5000, 0x5100, 0x10008, 0x1f000)]
    state = {}
    def hook(machine, address, size, unused):
        if address == FREE:
            rcx, rdx = machine.reg_read(x.UC_X86_REG_RCX), machine.reg_read(x.UC_X86_REG_RDX)
            if rcx != source or rdx != 16: raise ValueError('Неверные deallocation аргументы')
            state['free_calls'] += 1
            sp = machine.reg_read(x.UC_X86_REG_RSP)
            machine.reg_write(x.UC_X86_REG_RAX, 0xdeadbeef)
            machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
            machine.reg_write(x.UC_X86_REG_RSP, sp + 8)
            return
        if not any(a <= address and address + size <= b for a, b in ranges):
            raise ValueError('Исполнение вне native payload / leaf: ' + hex(address))
        if address == 0x141421b50: state['capture_copies'] += 1
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    def execute(entry, rcx, rdx):
        state.clear(); state.update(free_calls=0, capture_copies=0)
        uc.mem_write(stack - 0x400, b'\x91' * 0x800); uc.mem_write(stack, struct.pack('<Q', stop))
        for reg, value in ((x.UC_X86_REG_RCX, rcx), (x.UC_X86_REG_RDX, rdx), (x.UC_X86_REG_RSP, stack)):
            uc.reg_write(reg, value)
        uc.emu_start(entry, stop, count=256)
        if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RSP) != stack + 8:
            raise ValueError('Native не завершил полный возврат')
    copy_cases = []
    for active1, active2, external1, external2 in itertools.product((False, True), repeat=4):
        for capture1, capture2 in ((0, 0), (0x12345678, 0x87654321), (0x123456789abcdef0, 0xfedcba9876543210)):
            src = bytearray(b'\x73' * 0x90); expected = bytearray(b'\xa5' * 0x90)
            struct.pack_into('<Q', src, 0, 0x1122334455667788)
            expected[:8] = src[:8]
            for index, active, external, capture, heap, invoke in (
                (0, active1, external1, capture1, heap1, 0x1445c78d0),
                (1, active2, external2, capture2, heap2, 0x1445c7970)):
                at = 0x10 + index * 0x40
                struct.pack_into('<QQ', src, at, invoke if active else 0, 0x1111222233334444)
                struct.pack_into('<Q', src, at + 0x10, heap if external else 0)
                struct.pack_into('<QQ', src, at + 0x20, TABLE, capture)
                uc.mem_write(heap, struct.pack('<QQ', TABLE, capture) + b'\x64' * 16)
                struct.pack_into('<Q', expected, at, invoke if active else 0)
                struct.pack_into('<Q', expected, at + 0x10, 0)
                if active: struct.pack_into('<QQ', expected, at + 0x20, TABLE, capture)
            uc.mem_write(source, bytes(src)); uc.mem_write(output - 8, b'\xa5' * 0xa0)
            execute(ROOTS[0], output, source)
            if uc.reg_read(x.UC_X86_REG_RAX) != output or state['free_calls'] or state['capture_copies'] != int(active1) + int(active2):
                raise ValueError('Неверный native copy path')
            if bytes(uc.mem_read(output - 8, 0xa0)) != b'\xa5' * 8 + bytes(expected) + b'\xa5' * 8:
                raise ValueError('Повреждены поля / границы destination')
            if bytes(uc.mem_read(source, 0x90)) != bytes(src): raise ValueError('Изменён source payload')
            for heap, capture in ((heap1, capture1), (heap2, capture2)):
                if bytes(uc.mem_read(heap, 32)) != struct.pack('<QQ', TABLE, capture) + b'\x64' * 16:
                    raise ValueError('Изменён external capture')
            copy_cases.append(dict(active=[active1, active2], external_source=[external1, external2],
                captures=[hex(capture1), hex(capture2)], native_capture_copies=state['capture_copies'], complete_return=True))
    cleanup_cases = []
    for entry in (0x141421b70, 0x141421b80):
        for flags in (0, 1, 2, 3, 0xfe, 0xff, 0x100, 0x101):
            before = struct.pack('<QQ', TABLE if entry == 0x141421b70 else 0x12345678, 0x123456789abcdef0)
            uc.mem_write(source - 8, b'\xa5' * 8 + before + b'\xa5' * 8)
            execute(entry, source, flags)
            expected_calls = int(entry == 0x141421b80 and bool(flags & 1))
            if state['free_calls'] != expected_calls or uc.reg_read(x.UC_X86_REG_RAX) != source:
                raise ValueError('Неверная cleanup / deallocation ветвь')
            after = struct.pack('<QQ', TABLE, 0x123456789abcdef0)
            if bytes(uc.mem_read(source - 8, 32)) != b'\xa5' * 8 + after + b'\xa5' * 8:
                raise ValueError('Неожиданное изменение capture при cleanup')
            cleanup_cases.append(dict(entry=hex(entry), flags=flags, deallocation_fixture_calls=expected_calls, complete_return=True))
    address_cases = []
    for capture in (0, 0x12345678, 0x123456789abcdef0):
        before = struct.pack('<QQ', TABLE, capture); uc.mem_write(source, before)
        execute(0x14140e2f0, source, 0xdeadbeef)
        if uc.reg_read(x.UC_X86_REG_RAX) != source + 8 or bytes(uc.mem_read(source, 16)) != before:
            raise ValueError('Leaf не вернул адрес захваченного указателя')
        address_cases.append(dict(capture=hex(capture), returns_capture_address=True))
    return dict(source_sha256=getter.SHA, fragments=fragments, leaves=leaves,
        table=dict(address=hex(TABLE), bytes=table_bytes.hex(), sha256=getter.sha(table_bytes)),
        copy_cases=copy_cases, cleanup_cases=cleanup_cases, address_cases=address_cases,
        limits=['Copy helper and virtual capture-copy leaf execute natively; no fixture in those paths.',
            'External storage is synthetic mapped wrappers; captured pointer is opaque; allocation origin / ownership not proved.',
            'Deallocation is a fixture; destructor resets vtable, tail cleanup forces nondeleting path.',
            'No callable invocation, config event dispatch, full reader / insertion or active settings proof.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--leaf-request', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = run(json.loads(args.request.read_text('utf-8')), json.loads(args.leaf_request.read_text('utf-8')))
    result['replay_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps({key: len(result[key]) for key in ('copy_cases', 'cleanup_cases', 'address_cases')}))
