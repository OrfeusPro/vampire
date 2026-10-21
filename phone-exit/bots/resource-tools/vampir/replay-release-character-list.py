"""New EXE whole-list reader, actual nested readers, empty extension containers."""
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
from vampir_core.character_list import decode_character_list


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    strings = load('list_release_strings', HERE / 'replay-release-fstring-input.py')
    native = load('list_release_native', HERE / 'build-native-entry-code.py')
    audit = load('list_release_audit', HERE / 'audit-client-release.py')
    comparison = native.ROOT / 'ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c'
    evidence = comparison / 'details/run-2cc64357ed05/details.json'
    evidence_sha = 'facdd4d4f5073c63f95ac13f79e5b55dbf0039cf5278658ab377d820e4e57279'
    if audit.sha256(evidence) != evidence_sha:
        raise ValueError('Reviewed whole-list Ghidra evidence changed')
    h = strings.make_harness(extra_addresses=(0x1456dcf00, 0x145784b10, 0x1457897d0,
        0x1456e7cf0, 0x1456de090, 0x144aad880, 0x1457a47d0, 0x1457fefb0,
        0x145795e90, 0x145788d00, 0x1456c42d0, 0x144aad7c0, 0x1456bb730),
        extra_leaves=(0x144aae4e0, 0x1457917a0, 0x1457fedc0))
    uc, x = h.uc, h.x
    nested_bindings = {0x1499212d8: 0x1457fefb0, 0x149922470: 0x145795e90,
                       0x149921fb0: 0x145788d00, 0x149923ba0: 0x1456c42d0}
    for table, reader in nested_bindings.items():
        offset = h.image.offset(table - h.image.pe.base)
        if struct.unpack_from('<Q', h.raw, offset + 0x20)[0] != reader:
            raise ValueError('Nested reader binding changed')
        page = table & ~4095
        if not any(lo <= page <= hi for lo, hi, permissions in uc.mem_regions()):
            uc.mem_map(page, 4096)
            off = h.image.offset(page - h.image.pe.base)
            uc.mem_write(page, h.raw[off:off + 4096])
    # Only bounded storage/copy/cleanup are fixtures; no wire parsing in hooks.
    fixture_addresses = (0x1456d6f70, 0x1420e88c0, 0x1456d85c0, 0x145786670,
                         0x1456b6c90, 0x14141cdd0)
    for a in fixture_addresses:
        for page in (a & ~4095, (a & ~4095) + 4096):
            if any(lo <= page <= hi for lo, hi, permissions in uc.mem_regions()):
                continue
            uc.mem_map(page, 4096)
            off = h.image.offset(page - h.image.pe.base)
            uc.mem_write(page, h.raw[off:off + 4096])
    def fixture(machine):
        address = machine.reg_read(x.UC_X86_REG_RIP)
        a, b = machine.reg_read(x.UC_X86_REG_RCX), machine.reg_read(x.UC_X86_REG_RDX)
        if address == 0x1420e88c0:
            if b > 4:
                raise ValueError('List allocation fixture count bound')
            pointer = h.allocate(b * 0x170) if b else 0
            machine.mem_write(a, struct.pack('<Q', pointer))
            machine.mem_write(a + 12, struct.pack('<I', b))
        elif address == 0x1456d85c0:
            if not all(h.scratch <= p <= h.scratch + 0x40000 - 0x170 for p in (a, b)):
                raise ValueError('List copy fixture scratch bound')
            machine.mem_write(a, bytes(machine.mem_read(b, 0x170)))
            h.finish(a)
            return
        elif address == 0x14141cdd0:
            if b != 0:
                raise ValueError('Nonempty appearance extensions outside scenario')
            machine.mem_write(a, bytes(16))
        elif address == 0x1456b6c90 and b != 0:
            raise ValueError('Nonempty appearance cleanup outside scenario')
        h.finish()  # Explicit cleanup fixture preserves RAX.
    for address in fixture_addresses:
        h.fixtures[address] = fixture
    packet = h.scratch + 0x6000
    def read(body):
        if len(body) > 4096:
            raise ValueError('List input byte bound')
        h.string_heap[0] = h.scratch + 0x20000
        uc.mem_write(packet, bytes(0x100))  # Packet storage fixture, not packet-ID/constructor proof.
        uc.mem_write(h.buffer, bytes(4096))
        uc.mem_write(h.buffer, body)
        h.call(h.ctor, h.obj)
        uc.mem_write(h.obj + 0x20, struct.pack('<QI', h.buffer, len(body)))
        uc.mem_write(h.obj + 0x30, struct.pack('<Q', h.buffer))
        try:
            accepted = h.call(0x1456dcf00, packet, h.obj, budget=2000000) & 255
        except h.env.unicorn.UcError as error:
            raise ValueError('List memory fault at ' + hex(uc.reg_read(x.UC_X86_REG_RIP))) from error
        consumed = int.from_bytes(uc.mem_read(h.obj + 0x30, 8), 'little') - h.buffer
        pointer, count, capacity = struct.unpack('<QII', bytes(uc.mem_read(packet + 0x18, 16)))
        if not 0 <= count <= capacity <= 4:
            raise ValueError('Native list output count bound')
        def number(address, size):
            return int.from_bytes(uc.mem_read(address, size), 'little')
        def text(address):
            p, units, cap = struct.unpack('<QII', bytes(uc.mem_read(address, 16)))
            if not 0 <= units <= cap <= 2048:
                raise ValueError('List FString bound')
            return bytes(uc.mem_read(p, (units - 1) * 2)).decode('utf-16le') if units else ''
        records = []
        for index in range(count):
            record = pointer + index * 0x170
            if number(record + 0xe8, 4) != 0 or number(record + 0x118, 1) != 0:
                raise ValueError('Nonempty native extensions outside verified profile')
            records.append(dict(strings=tuple(text(record + n) for n in (0x18, 0x50, 0xc8)),
                u32=tuple(number(record + n, 4) for n in (0x10, 0x30)),
                u16=tuple(number(record + n, 2) for n in (0x70, 0x72, 0x74, 0x76)),
                u64=tuple(number(record + n, 8) for n in (8, 0x28, 0x40, 0x48, 0x80, 0x88, 0x98, 0xa0, 0xa8, 0xf0, 0xf8, 0x100)),
                enum60=number(record + 0x60, 1), appearance=tuple(uc.mem_read(record + 0xb8, 10)),
                appearance_flags=tuple(uc.mem_read(record + 0xd8, 2)), flag108=bool(number(record + 0x108, 1)),
                appearance_items=(), optional_items=None))
        return dict(accepted=accepted, consumed=consumed, count=count, records=records,
                    result_code=number(packet + 0x10, 4), raw14=number(packet + 0x14, 4),
                    tail=tuple(number(packet + off, size) for off, size in ((0x28, 8), (0x30, 4), (0x38, 8), (0x40, 8))))
    old = load('old_list_wire_fixtures', HERE / 'replay-character-list-reader.py')
    bodies = [struct.pack('<IIHQIQQ', code, 207, 0, 1, 2, 3, 4) for code in (0, 1, 0xffffffff)]
    for text_value, value, enum, appearance, flag in (('', 0, 0, 0, 0), ('Ж界🙂', 0x12345678, 255, 255, 255), ('a' * 128, 2**64 - 1, 5, 1, 1)):
        for count in (1, 2, 4):
            bodies.append(struct.pack('<IIH', 0, 207, count) + old.record_bytes(text_value, value, enum, appearance, flag) * count + struct.pack('<QIQQ', 1, 2, 3, 4))
    cases = []
    for body in bodies:
        actual = read(body)
        expected = decode_character_list(body, max_payload_size=4096, max_characters=4, max_extension_items=0)
        if actual['accepted'] != 1 or actual['consumed'] != len(body):
            raise ValueError('Whole-list native acceptance differs')
        if (actual['result_code'], actual['raw14'], actual['tail'], actual['count']) != (expected.result_code, expected.raw14, expected.tail, len(expected.records)):
            raise ValueError('Whole-list header differs from portable decoder')
        for result, record in zip(actual['records'], expected.records):
            if any(result[key] != getattr(record, key) for key in result):
                raise ValueError('Record fields differ from portable decoder')
        cases.append(dict(body_bytes=len(body), characters=actual['count'], portable_fields_match=True))
    short = []
    for body in (bodies[0], bodies[6]):
        for size in range(len(body)):
            actual = read(body[:size])
            if actual['accepted'] != 0 or actual['consumed'] > size:
                raise ValueError('Short list accepted or read beyond input')
            short.append(dict(body_bytes=len(body), available=size, consumed=actual['consumed'], accepted=0))
    trailing = read(bodies[6] + b'extra')
    if trailing['accepted'] != 1 or trailing['consumed'] != len(bodies[6]):
        raise ValueError('Native trailing-byte behavior changed')
    report = dict(schema=1, source=str(h.source), source_sha256=h.sha, tool_sha256=audit.sha256(Path(__file__)),
        ghidra_evidence_sha256=evidence_sha, dependencies={p: audit.sha256(HERE / p) for p in
        ('replay-release-archive-input.py', 'replay-release-fstring-input.py', 'replay-character-list-reader.py')},
        portable_decoder_sha256=audit.sha256(HERE.parents[1] / 'vampir-shared/vampir_core/character_list.py'),
        nested_reader_bindings={hex(k): hex(v) for k, v in nested_bindings.items()},
        fragments=h.fragments, leaves=h.leaves, cases=cases, truncated=short,
        trailing_native_consumed=trailing['consumed'], native_execution=True, compatibility='not_established',
        limits=['Actual whole packet body reader, record constructors/readers, archive/UTF8 and array callbacks execute.',
                'Packet storage, array allocation, shallow copy, cleanup and string storage are explicit fixtures.',
                'Appearance extensions empty and optional map absent; no packet ID/handler/live session proof.'])
    target = audit.save_snapshot(comparison / 'character-list-replay', report)
    print(json.dumps(dict(report=str(target), sha256=audit.sha256(target), cases=len(cases), truncated=len(short)), indent=2))


if __name__ == '__main__':
    main()
