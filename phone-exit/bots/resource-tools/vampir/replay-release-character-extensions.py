"""Whole new-release list with nonempty appearance arrays and optional maps."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_harness(extra_addresses=(), extra_leaves=()):
    lists = load('extension_release_lists', HERE / 'replay-release-character-list.py')
    native = load('extension_release_native', HERE / 'build-native-entry-code.py')
    audit = load('extension_release_audit', HERE / 'audit-client-release.py')
    comparison = native.ROOT / 'ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c'
    evidence = comparison / 'details/run-c835a4433cde/details.json'
    evidence_sha = 'f80a7771f06e6b888c00df5b093de6521ffa2fe96bd0bfba3867fbf36e5ae34b'
    if audit.sha256(evidence) != evidence_sha:
        raise ValueError('Reviewed extension Ghidra evidence changed')
    h = lists.make_harness(extra_addresses=(0x14573cc90, 0x145787660, 0x1456c8140,
        0x1456bea70, 0x1456bcea0, 0x145785490, 0x14578a680, *extra_addresses),
        extra_leaves=(0x145783f30, *extra_leaves), max_appearance=8)
    uc, x = h.uc, h.x
    fixture_addresses = (0x1456b7990, 0x14168aa80, 0x1456c8550, 0x1456d3530,
                         0x1456d5df0, 0x141429760, 0x1456d2c90, 0x145786e60)
    for a in fixture_addresses:
        for page in (a & ~4095, (a & ~4095) + 4096):
            if any(lo <= page <= hi for lo, hi, permissions in uc.mem_regions()):
                continue
            uc.mem_map(page, 4096)
            offset = h.image.offset(page - h.image.pe.base)
            uc.mem_write(page, h.raw[offset:offset + 4096])
    map_storage, insertions = {}, []
    def reset():
        map_storage.clear()
        insertions.clear()
    h.list_before_read = reset
    def init_map(address):
        pointer = map_storage.get(address)
        if pointer is None:
            pointer = h.allocate(8 * 0x38)
            map_storage[address] = pointer
        uc.mem_write(address, bytes(0x50))
        uc.mem_write(pointer, bytes(8 * 0x38))
        uc.mem_write(address, struct.pack('<QII', pointer, 0, 8))
        uc.mem_write(address + 0x2c, struct.pack('<I', 128))
        uc.mem_write(address + 0x30, struct.pack('<i', -1))
        uc.mem_write(address + 0x38, struct.pack('<i', -1))
        uc.mem_write(address + 0x48, struct.pack('<I', 1))
    def fixture(machine):
        address = machine.reg_read(x.UC_X86_REG_RIP)
        a, b = machine.reg_read(x.UC_X86_REG_RCX), machine.reg_read(x.UC_X86_REG_RDX)
        result = None
        if address in (0x14168aa80, 0x1456c8550):
            init_map(a)
        elif address == 0x1456d3530:
            init_map(b)
        elif address == 0x1456d5df0:
            pointer, count = struct.unpack('<QI', bytes(uc.mem_read(a, 12)))
            if not 1 <= count <= 8 or any(uc.mem_read(pointer + i * 0x38, 1)[0] == b for i in range(count - 1)):
                raise ValueError('Native insert predicate received duplicate or excessive key')
            result = 0
            insertions.append(b)
        elif address == 0x1456d2c90:
            pointer, count = struct.unpack('<QI', bytes(uc.mem_read(a, 12)))
            buckets = int.from_bytes(uc.mem_read(a + 0x48, 4), 'little')
            if not 0 <= count <= 8 or not 1 <= buckets <= 16 or buckets & (buckets - 1):
                raise ValueError('Map rehash fixture bound')
            heads = [-1] * buckets
            for index in range(count):
                node = pointer + index * 0x38
                bucket = uc.mem_read(node, 1)[0] & (buckets - 1)
                uc.mem_write(node + 0x30, struct.pack('<iI', heads[bucket], bucket))
                heads[bucket] = index
            p = h.allocate(4 * buckets) if buckets > 1 else a + 0x38
            uc.mem_write(p, struct.pack('<' + 'i' * buckets, *heads))
            uc.mem_write(a + 0x40, struct.pack('<Q', p if buckets > 1 else 0))
        h.finish(result)
    for address in fixture_addresses:
        h.fixtures[address] = fixture
    original_cleanup = h.fixtures[0x145786670]
    def cleanup_record(machine):
        # Keep copied record storage alive; a later temporary record gets fresh map nodes.
        original_cleanup(machine)
        map_storage.clear()
    h.fixtures[0x145786670] = cleanup_record
    def map_snapshot(address):
        pointer, count = struct.unpack('<QI', bytes(uc.mem_read(address, 12)))
        if not 0 <= count <= 8:
            raise ValueError('Optional output count bound')
        return tuple(sorted(tuple(int.from_bytes(uc.mem_read(pointer + i * 0x38 + off, width), 'little')
            for off, width in ((0, 1), (0x10, 1), (0x14, 4), (0x18, 4), (0x1c, 4), (0x28, 8))) for i in range(count)))
    h.optional_snapshot = map_snapshot
    h.map_insertions = insertions
    h.extension_ghidra_sha = evidence_sha
    h.decode_character_list = lists.decode_character_list
    return h


def main():
    h = make_harness()
    audit, comparison, insertions = h.audit, h.comparison, h.map_insertions
    wire = load('extension_old_wire', HERE / 'replay-character-list-extensions.py')
    cases, bodies = [], []
    for items in ((), ((0, 0, 0),), ((0xffffffff, 255, 65535), (0x12345678, 128, 0x8001)), ((1, 2, 3),) * 8):
        for count in (1, 2, 4):
            bodies.append(wire.list_bytes(items, count=count))
    entry_cases = ((), ((0, 0, 0, 0, 0, 0),), ((255, 9, 0xffffffff, 0, 1, 0x8000000000000000),),
        ((1, 255, 0xffffffff, 0x80000000, 1, 2**64 - 1), (9, 8, 1, 2, 3, 4), (1, 2, 3, 4, 5, 6)),
        tuple((i * 8 + 1, 255 - i, i, 0xffffffff - i, 0x80000000 + i, 2**64 - 1 - i) for i in range(8)),
        tuple((i * 8 + 1, 255 - i, i, 0xffffffff - i, 0x80000000 + i, 2**64 - 1 - i) for i in range(8)) + ((1, 0, 9, 8, 7, 6),))
    for entries in entry_cases:
        for count in (1, 2, 4):
            bodies.append(wire.list_bytes(((0xffffffff, 255, 65535),), wire.optional_bytes(entries, 255), count))
    # Distinct neighboring records catch accidentally shared fixture map storage.
    bodies.append(struct.pack('<IIH', 0, 207, 2) + wire.record_bytes(((1, 2, 3),), wire.optional_bytes(((1, 2, 3, 4, 5, 6),)))
        + wire.record_bytes(((7, 8, 9),), wire.optional_bytes(((9, 8, 7, 6, 5, 4),))) + struct.pack('<QIQQ', 1, 2, 3, 4))
    for body in bodies:
        actual = h.read_list(body)
        expected = h.decode_character_list(body, max_payload_size=4096, max_characters=4, max_extension_items=128)
        if actual['accepted'] != 1 or actual['consumed'] != len(body) or actual['count'] != len(expected.records):
            raise ValueError('Whole-list extension acceptance differs')
        for result, record in zip(actual['records'], expected.records):
            if any(result[key] != getattr(record, key) for key in result):
                raise ValueError('Native extension fields differ from portable decoder')
        unique_keys = [entry[0] for record in expected.records if record.optional_items is not None for entry in record.optional_items]
        if sorted(insertions) != sorted(unique_keys):
            raise ValueError('Duplicate callback inserted another map entry')
        cases.append(dict(body_bytes=len(body), characters=actual['count'], portable_fields_match=True,
                          unique_map_insertions=len(insertions)))
    truncated = []
    for body in (wire.list_bytes(((0xffffffff, 255, 65535), (0, 0, 0))),
                 wire.list_bytes(((1, 2, 3),), wire.optional_bytes(((1, 255, 2, 3, 4, 5), (9, 2, 3, 4, 5, 6), (1, 1, 7, 8, 9, 10)), 255))):
        for size in range(len(body)):
            actual = h.read_list(body[:size])
            if actual['accepted'] != 0 or actual['consumed'] > size:
                raise ValueError('Short extension body accepted or overread')
            truncated.append(dict(available=size, consumed=actual['consumed'], accepted=0))
    report = dict(schema=1, source=str(h.source), source_sha256=h.sha, tool_sha256=audit.sha256(Path(__file__)),
        ghidra_evidence_sha256=h.extension_ghidra_sha, dependencies={p: audit.sha256(HERE / p) for p in
        ('replay-release-character-list.py', 'replay-release-fstring-input.py', 'replay-release-archive-input.py', 'replay-character-list-extensions.py')},
        fragments=h.fragments, leaves=h.leaves, cases=cases, truncated=truncated, native_execution=True,
        compatibility='not_established', limits=['Whole list/record/appearance/map callbacks and native insert/pair/value readers execute.',
        'Preallocated storage, resets, bitvector capacity, unseen-key insert predicate, rehash, copy and cleanup are fixtures.',
        'Duplicate search/overwrite use actual callback code; allocator/lifetime, packet IDs, handler and live session unproven.'])
    target = audit.save_snapshot(comparison / 'character-extension-replay', report)
    print(json.dumps(dict(report=str(target), sha256=audit.sha256(target), cases=len(cases), truncated=len(truncated)), indent=2))


if __name__ == '__main__':
    main()
