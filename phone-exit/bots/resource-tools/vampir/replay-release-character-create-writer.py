"""Whole current ID 103 writer, native UTF8/scalars, bounded raw output fixture."""
import importlib.util
import itertools
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
from vampir_core.character_create import CharacterCreatePayload, encode_character_create


def run(*, producer=False):
    spec = importlib.util.spec_from_file_location('create_writer_strings', HERE / 'replay-release-fstring-input.py')
    strings = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(strings)
    h = strings.make_harness(extra_addresses=(0x1456d8120, 0x1456bb7d0, 0x14578e120,
        0x14578ddd0, 0x14578c800, 0x144aae660, 0x14144c630, 0x1414466d0, 0x144aada00,
        0x144aadc10, 0x144aadc90, 0x144aadcc0, 0x144aadc60, 0x144aade10, 0x144aade40,
        *((0x146449dc0,) if producer else ())),
        extra_leaves=(0x145784790, 0x145783f30, 0x144aae500, 0x144aae8c0, 0x144aadae0, 0x1432ad880,
                      0x141c57110, 0x141e4aef0, 0x144aadaf0, 0x1436af790))
    uc, x = h.uc, h.x
    # Reviewed UTF16 -> UTF8 leaf has internal branches and a single final RET.
    address, length = 0x14143f400, 0x13d
    offset = h.image.offset(address - h.image.pe.base)
    content = h.raw[offset:offset + length]
    rows = list(h.env.capstone.Cs(h.env.capstone.CS_ARCH_X86, h.env.capstone.CS_MODE_64).disasm(content, address))
    if sum(row.size for row in rows) != length or rows[-1].mnemonic != 'ret':
        raise ValueError('UTF8 encoder leaf boundary changed')
    h.ranges.append((address, address + length))
    hooks = (0x144aadd50, 0x14690a090, 0x141436da0, 0x141483160, 0x1487eac40, h.copy)
    if producer:
        hooks += (0x14644a0c0, 0x14641af30, 0x146447e50, 0x144aaf870,
                  0x144aafc50, 0x1456d9440, 0x141436fb0)
    pages = {p for a, b in h.ranges for p in range(a & ~4095, (b + 4095) & ~4095, 4096)}
    pages.update(a & ~4095 for a in hooks)
    pages.update(a & ~4095 for a in (0x14992a3a8, 0x149921fb0, 0x149921f68))
    for page in sorted(pages):
        if not any(lo <= page <= hi for lo, hi, _ in uc.mem_regions()):
            uc.mem_map(page, 4096)
            off = h.image.offset(page - h.image.pe.base)
            uc.mem_write(page, h.raw[off:off + 4096])
    packet, output = h.scratch + 0x10000, h.scratch + 0x11000
    data, appearance = packet + 0x10, packet + 0x30
    chunks, widths = [], []
    fail_at = None
    bindings = {0x28: 0x144aadc10, 0xc8: 0x144aadae0, 0xd0: 0x1432ad880,
        0xe0: 0x141c57110, 0xe8: 0x141e4aef0, 0xf0: 0x144aadaf0}
    for slot, target in bindings.items():
        if int.from_bytes(uc.mem_read(0x149672748 + slot, 8), 'little') != target:
            raise ValueError('Create output archive slot changed')
    for table, writer in ((0x14992a3a8, 0x1456bb7d0), (0x14992a360, 0x14578e120),
                          (0x149921fb0, 0x14578ddd0), (0x149921f68, 0x14578c800)):
        if int.from_bytes(uc.mem_read(table + 0x10, 8), 'little') != writer:
            raise ValueError('Create object writer slot changed')
    def fixture(machine):
        current = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c, d = [machine.reg_read(reg) for reg in
            (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        result = None
        if current == 0x144aadd50:
            if a != output or not 0 <= c <= 512 or not h.scratch <= b <= h.scratch + 0x40000 - c:
                raise ValueError('Create raw output fixture bound')
            result = int(len(widths) != fail_at)
            widths.append(c)
            if result: chunks.append(bytes(machine.mem_read(b, c)))
        elif current == 0x14690a090:
            result = h.allocate(a)
        elif current == 0x141436da0:
            if b or d != 1: raise ValueError('Create UTF8 scratch allocation contract')
            machine.mem_write(a, struct.pack('<Q', h.allocate(c)))
        elif current == h.copy:
            if c > 512 or not all(h.scratch <= p <= h.scratch + 0x40000 - c for p in (a, b)):
                raise ValueError('Create writer memcpy bound')
            if c: machine.mem_write(a, bytes(machine.mem_read(b, c)))
            result = a
        h.finish(result)  # Explicit free / cookie fixtures preserve RAX.
    for a in hooks: h.fixtures[a] = fixture
    def text(address, value):
        encoded = value.encode('utf-16le') + b'\0\0'
        pointer = h.allocate(len(encoded))
        uc.mem_write(pointer, encoded)
        uc.mem_write(address, struct.pack('<QII', pointer, len(encoded) // 2, len(encoded) // 2))
    def write(raw_class, name, appearance_text, values, flag, byte, items):
        h.string_heap[0] = h.scratch + 0x20000
        chunks.clear(); widths.clear()
        uc.mem_write(packet - 16, b'\xa5' * 0xa0)
        h.call(0x1456d8120, packet)
        uc.mem_write(data + 8, struct.pack('<I', raw_class))
        text(data + 0x10, name); text(appearance + 0x18, appearance_text)
        uc.mem_write(appearance + 8, bytes(values))
        uc.mem_write(appearance + 0x28, bytes((flag, byte)))
        pointer = h.allocate(len(items) * 16) if items else 0
        for index, (a, b, c) in enumerate(items):
            h.call(0x145783f30, pointer + index * 16)
            uc.mem_write(pointer + index * 16 + 8, struct.pack('<IBxH', a, b, c))
        uc.mem_write(appearance + 0x30, struct.pack('<QII', pointer, len(items), len(items)))
        h.call(0x144aada00, output)
        before = bytes(uc.mem_read(packet, 0x70))
        try:
            accepted = h.call(0x1456bb7d0, packet, output, budget=200000) & 255
        except h.env.unicorn.UcError as error:
            raise ValueError('Create writer memory fault at ' + hex(uc.reg_read(x.UC_X86_REG_RIP))) from error
        if bytes(uc.mem_read(packet, 0x70)) != before:
            raise ValueError('Create writer changed input object')
        return accepted, b''.join(chunks)
    def wire_text(value):
        encoded = value.encode('utf-8')
        return struct.pack('<H', len(encoded)) + encoded
    if producer:
        spec = importlib.util.spec_from_file_location('create_producer_entry', HERE / 'replay-release-character-create-producer.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module.run_with_writer(h, packet, output, chunks, widths)
    cases = []
    inputs = [(1, value, value, 0) for value in ('a' * 15, 'a' * 16, 'a' * 127, 'a' * 128, 'a' * 129, '界' * 80)]
    inputs.extend(itertools.product((0, 0x12345678, 0xffffffff), ('', 'NightRaven', 'Ж界🙂'), ('', '{"x":1}'), (0, 1)))
    for raw_class, name, appearance_text, variant in inputs:
        values = [0] * 10 if not variant else [255, 1, 2, 3, 4, 5, 6, 7, 8, 255]
        items = [] if not variant else [(0x12345678, 255, 0xffff), (0, 0, 1)]
        flag, byte = (0, 0) if not variant else (255, 255)
        accepted, body = write(raw_class, name, appearance_text, values, flag, byte, items)
        expected = (struct.pack('<I', raw_class) + wire_text(name) + bytes(values) + wire_text(appearance_text)
            + bytes((flag, byte)) + struct.pack('<H', len(items))
            + b''.join(struct.pack('<IBH', *item) for item in items))
        if accepted != 1 or body != expected:
            raise ValueError('Create writer differs: ' + repr((accepted, body.hex(), expected.hex())))
        payload = CharacterCreatePayload(raw_class, name, tuple(values), appearance_text, (flag, byte), tuple(items))
        if encode_character_create(payload, source_sha256=h.sha) != body:
            raise ValueError('Portable create encoder differs from whole native writer')
        cases.append(dict(raw_class=raw_class, name=name, appearance_text=appearance_text,
            variant=variant, body_hex=body.hex(), widths=widths.copy()))
    failures = []
    success_widths, success_chunks = widths.copy(), chunks.copy()
    for fail_at in range(len(success_widths)):
        accepted, body = write(raw_class, name, appearance_text, values, flag, byte, items)
        if (widths != success_widths[:len(widths)] or len(widths) <= fail_at or
                body != b''.join(chunk for index, chunk in enumerate(success_chunks[:len(widths)]) if index != fail_at)):
            raise ValueError('Create writer failure trace differs from native field sequence')
        failures.append(dict(fail_at=fail_at, accepted=accepted, stopped=len(widths) == fail_at + 1,
            widths=widths.copy(), output_bytes=len(body)))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        native_execution=True, network_used=False, cases=cases, failures=failures,
        encoder_leaf=dict(address=hex(address), bytes=content.hex()),
        limits=['Whole ID 103 / CreateData / appearance writers and native UTF16/UTF8 conversion execute.',
            'Raw output append, storage allocation/free/copy/cookie are bounded fixtures.',
            'Synthetic class, appearance and terminated strings do not prove valid game settings.',
            'No producer, JSON generation, server result, network or actual character creation.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-character-create-writer', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']), failures=len(report['failures']))))
