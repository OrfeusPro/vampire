"""Bounded native Refresh wrapper + 24-byte setter; shared refresh routine is a fixture."""
import argparse
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('tile_getter', HERE / 'inspect-nktileview-registration.py')
getter = importlib.util.module_from_spec(spec); spec.loader.exec_module(getter)
native = getter.native
import unicorn
from unicorn import x86_const as x


def run(request):
    if request['source_sha256'] != getter.SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Не тот источник / вопрос')
    if not {'0x144a8f220', '0x144626640'} <= {f['address'] for f in request['functions']}:
        raise ValueError('Нужны явные wrapper и tail target в задании')
    if native.capstone.__version__ != '5.0.6' or unicorn.__version__ != '2.1.4':
        raise ValueError('Нужны закреплённые Capstone / Unicorn')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA:
        raise ValueError('Изменился EXE')
    image = native.Image(raw); root = image.containing(0x144a8f220)
    if root is None or image.pe.base + image.roots[root][0] != 0x144a8f220:
        raise ValueError('Изменился root Refresh')
    fragments = native.decode_ranges(image, {image.roots[root]})
    if len(fragments) != 1 or fragments[0]['end_rva'] + image.pe.base != 0x144a8f26f:
        raise ValueError('Изменились границы wrapper')
    leaf = bytes.fromhex('0f100233d2c681f9140000010f1181b8140000e9f8d7ffff')
    leaf_offset = image.offset(0x144628e30 - image.pe.base)
    if raw[leaf_offset:leaf_offset + len(leaf)] != leaf or raw[leaf_offset + len(leaf):leaf_offset + len(leaf) + 8] != b'\xcc' * 8:
        raise ValueError('Изменился leaf setter или padding после tail JMP')
    ranges = [(0x144a8f220, 0x144a8f26f), (0x144628e30, 0x144628e48)]
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    pages = {a & ~4095 for a in (0x144a8f220, 0x144628e30, 0x144626640)}
    for page in pages:
        uc.mem_map(page, 4096)
        offset = image.offset(page - image.pe.base); uc.mem_write(page, raw[offset:offset + 4096])
    scratch = 0x20000000; uc.mem_map(scratch, 0x20000)
    owner, receiver, frame, stack, stop = [scratch + p for p in (0x1000, 0x3000, 0x6000, 0x10000, 0x1f000)]
    calls = []
    def hook(machine, address, size, unused):
        if address == 0x144626640:
            calls.append(dict(receiver=machine.reg_read(x.UC_X86_REG_RCX), flag=machine.reg_read(x.UC_X86_REG_RDX) & 255))
            sp = machine.reg_read(x.UC_X86_REG_RSP)
            machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
            machine.reg_write(x.UC_X86_REG_RSP, sp + 8)
        elif not any(a <= address and address + size <= b for a, b in ranges):
            raise ValueError('Исполнение вне проверенных диапазонов: ' + hex(address))
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    cases = []
    for present, cursor, payload in itertools.product((False, True), (0, 1, 0x1000, 0xffffffffffffffff),
                                                     (bytes(16), bytes(range(16)), b'\xff' * 16)):
        calls.clear()
        owner_before = bytearray(b'\xa5' * 0x500)
        owner_before[0x408:0x410] = struct.pack('<Q', receiver if present else 0)
        owner_before[0x430:0x440] = payload
        uc.mem_write(owner, bytes(owner_before)); uc.mem_write(receiver, b'\x5a' * 0x1600)
        frame_before = bytearray(b'\xc3' * 0x60); frame_before[0x20:0x28] = struct.pack('<Q', cursor)
        uc.mem_write(frame, bytes(frame_before)); uc.mem_write(stack, struct.pack('<Q', stop))
        for reg, value in ((x.UC_X86_REG_RCX, owner), (x.UC_X86_REG_RDX, frame), (x.UC_X86_REG_RSP, stack)):
            uc.reg_write(reg, value)
        uc.emu_start(0x144a8f220, stop, count=512)
        if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RSP) != stack + 8:
            raise ValueError('Wrapper не завершился штатным возвратом')
        frame_before[0x20:0x28] = struct.pack('<Q', (cursor + int(cursor != 0)) & 0xffffffffffffffff)
        target = bytearray(b'\x5a' * 0x1600)
        if present:
            target[0x14b8:0x14c8] = payload; target[0x14f9] = 1
        if bytes(uc.mem_read(owner, 0x500)) != owner_before or bytes(uc.mem_read(frame, 0x60)) != frame_before:
            raise ValueError('Изменился источник или постороннее поле frame')
        if bytes(uc.mem_read(receiver, 0x1600)) != target:
            raise ValueError('Копирование / флаг / границы receiver отличаются')
        expected = [dict(receiver=receiver, flag=0), dict(receiver=receiver, flag=1)] if present else []
        if calls != expected:
            raise ValueError('Порядок вызовов refresh routine отличается')
        cases.append(dict(receiver_present=present, frame_cursor=cursor, payload_hex=payload.hex(), flags=[c['flag'] for c in calls]))
    return dict(source_sha256=getter.SHA, fragments=fragments, leaf=dict(address='0x144628e30', bytes=leaf.hex(),
        file_offset=leaf_offset, boundary='fixed_straight_line_tail_JMP_then_INT3_not_unwind'), cases=cases,
        limits=['Native wrapper and exact setter only; 144626640 is a no-op return fixture.',
            'The 16-byte block has no proved type, unit, property names or list-element semantics.',
            'Two routine invocations with flags 0 then 1 do not prove scheduling / coalescing or rendering.',
            'No live widget, engine state, server data, profile or game commands.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Прежний отчёт не перезаписывается')
    result = run(json.loads(args.request.read_text('utf-8')))
    result['replay_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(source_sha256=getter.SHA, cases=len(result['cases'])), ensure_ascii=False))
