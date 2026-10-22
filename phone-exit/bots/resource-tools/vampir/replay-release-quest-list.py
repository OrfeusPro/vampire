"""Whole ID 1802 with native nested readers and bounded fresh storage fixtures."""
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
from vampir_core.quest_list import decode_quest_list_result


def run():
    spec = importlib.util.spec_from_file_location('quest_list_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    fixtures = {}
    addresses = (0x14582cac0, 0x1457a7980, 0x1457a7a80, 0x1457a9dd0,
        0x1457aad70, 0x1457aad30, 0x1456bb6b0, 0x1457a9cc0, 0x1456b8e10,
        0x1457a77c0, 0x1457a7a20, 0x145787dd0, 0x144aad880)
    h = archive.make_harness(extra_addresses=addresses,
        extra_leaves=(0x144aae4e0, 0x1457840d0), fixtures=fixtures)
    evidence = {
        'details/run-df3c5d97b2b8/details.json': '658e92284a85cbcd397427d8008910a209b148eb6c03151b6da3aa973b053f9b',
        'details/run-f47f7eb31681/details.json': '8f4a6d97417cb1c50a5e857cc6a3c75a1179fadf114ef64e9e5942b05e847bba',
        'details/run-6c286a6860d8/details.json': 'a9698c44e788c5e38cb3d31b0a7d02604ffd197c5f0959e91c30d552f5a7d622',
        'details/run-b25ee312ccc9/details.json': 'b79eaf9158bd493eb3878b730468b108e59c4baf8fa5c6e0db1b2716fd24a063'}
    for name, digest in evidence.items():
        if h.audit.sha256(h.comparison / name) != digest:
            raise ValueError('Quest list export evidence changed')
    uc, x = h.uc, h.x
    heap = [h.scratch + 0x20000]
    allocations = {}

    def finish(value=None):
        if value is not None: uc.reg_write(x.UC_X86_REG_RAX, value)
        sp = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(sp, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, sp + 8)

    def allocate(size):
        if not 0 < size <= 8 * 72 or heap[0] + size > h.scratch + 0x3f000:
            raise ValueError('Quest fresh storage bound')
        ptr = heap[0]
        heap[0] += (size + 15) & ~15
        allocations[ptr] = size
        uc.mem_write(ptr, bytes(size))
        return ptr

    def cleanup(machine):
        ptr = machine.reg_read(x.UC_X86_REG_RCX)
        count = machine.reg_read(x.UC_X86_REG_RDX) & 0xffffffff
        if count and (count > 8 or allocations.get(ptr, 0) < count * 72):
            raise ValueError('Quest cleanup fixture bound')
        finish()

    def resize(machine):
        entry = machine.reg_read(x.UC_X86_REG_RIP)
        container = machine.reg_read(x.UC_X86_REG_RCX)
        n = machine.reg_read(x.UC_X86_REG_RDX) & 0xffffffff
        ptr, count, capacity = struct.unpack('<QII', machine.mem_read(container, 16))
        if n > 8 or ptr or capacity or count not in (0, n):
            raise ValueError('Fresh quest allocation required')
        stride = 32 if entry == 0x141438040 else 72
        ptr = allocate(n * stride) if n else 0
        machine.mem_write(container, struct.pack('<QII', ptr, count, n))
        finish()

    def copy_records(machine):
        dst, src, n = [machine.reg_read(r) for r in
            (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        if n > 8 or allocations.get(dst, 0) < n * 72 or allocations.get(src, 0) < n * 72:
            raise ValueError('Quest group copy fixture bound')
        machine.mem_write(dst, bytes(machine.mem_read(src, n * 72)))
        finish()

    def free(machine):
        if machine.reg_read(x.UC_X86_REG_RCX) not in allocations:
            raise ValueError('Unknown quest temporary free')
        finish()

    bindings = ((0x14994bc30, 8, 0x1457aad30), (0x14994bc30, 16, 0x1457a9cc0),
        (0x149922240, 8, 0x1456bb6b0), (0x149922240, 16, 0x1456b8e10),
        (0x14994bc18, 8, 0x1457aad70), (0x14994bc18, 16, 0x1457a9dd0),
        (0x14994aaa8, 32, 0x1457a77c0), (0x14994aa60, 32, 0x1457a7a20),
        (0x14994aae8, 32, 0x1457a7a80), (0x14994ab30, 32, 0x1457a7980),
        (0x149921178, 32, 0x145787dd0))
    for table, slot, target in bindings:
        if struct.unpack_from('<Q', h.raw, h.image.offset(table - h.image.pe.base) + slot)[0] != target:
            raise ValueError('Quest array binding changed')
    hooks = {0x145783520: cleanup, 0x145783550: cleanup, 0x1456b6cc0: cleanup,
        0x141438040: resize, 0x141865400: resize, 0x141865110: resize,
        0x145783160: copy_records, 0x141483160: free,
        0x1456b7990: lambda machine: finish()}
    for page in {a & ~4095 for a in (*hooks, *[t for t, s, a in bindings])}:
        if not any(lo <= page <= hi for lo, hi, _ in uc.mem_regions()):
            uc.mem_map(page, 4096)
            offset = h.image.offset(page - h.image.pe.base)
            uc.mem_write(page, h.raw[offset:offset + 4096])
    fixtures.update(hooks)
    packet = h.scratch + 0x10000

    def read(body):
        heap[0] = h.scratch + 0x20000
        allocations.clear()
        uc.mem_write(packet, bytes(128))
        uc.mem_write(packet + 0x40, struct.pack('<Q', 0x14994ab30))
        uc.mem_write(h.buffer, bytes(8192))
        if body: uc.mem_write(h.buffer, body)
        h.call(h.ctor, h.obj)
        uc.mem_write(h.obj + 0x20, struct.pack('<QI', h.buffer, len(body)))
        uc.mem_write(h.obj + 0x30, struct.pack('<Q', h.buffer))
        ok = h.call(0x14582cac0, packet, h.obj, budget=300000) & 255
        return ok, int.from_bytes(uc.mem_read(h.obj + 0x30, 8), 'little') - h.buffer

    def compare_quests(container, expected):
        ptr, count, capacity = struct.unpack('<QII', uc.mem_read(container, 16))
        if count != len(expected) or capacity != count:
            raise ValueError('Quest array count differs')
        for i, record in enumerate(expected):
            at = ptr + i * 72
            actual = (int.from_bytes(uc.mem_read(at + 8, 8), 'little'), uc.mem_read(at + 16, 1)[0],
                uc.mem_read(at + 32, 1)[0], *struct.unpack('<QQ', uc.mem_read(at + 40, 16)),
                uc.mem_read(at + 56, 1)[0], *struct.unpack('<III', uc.mem_read(at + 60, 12)))
            if actual != (record.raw08, record.raw10, record.progress.raw08,
                    record.progress.raw10, record.progress.raw18, int(record.raw38),
                    record.raw3c, record.raw40, record.raw44):
                raise ValueError('Quest array record differs')

    def body_for(q, a, g, nested, raw):
        def quest(i):
            return struct.pack('<QBBQQBIII', 0x8000000000000000 + i, raw, raw,
                0xffffffffffffffff - i, i + 7, raw, i, 0xffffffff - i, i + 11)
        return (struct.pack('<IBH', 0xffffffff if raw == 255 else 0, raw, q)
            + b''.join(quest(i) for i in range(q)) + struct.pack('<H', a)
            + b''.join(struct.pack('<BQQ', raw, i + 5, 0xffffffffffffffff - i) for i in range(a))
            + bytes([raw, raw]) + struct.pack('<H', g)
            + b''.join(struct.pack('<BH', raw, nested)
                + b''.join(quest(100 + i * 8 + j) for j in range(nested)) for i in range(g))
            + struct.pack('<Q', 0xfedcba9876543210))

    cases = []
    for q in (0, 1, 2):
        for a in (0, 1, 2):
            for g in (0, 1, 2):
                for nested in (0, 1, 2):
                    for raw in (0, 1, 255):
                        body = body_for(q, a, g, nested, raw)
                        expected = decode_quest_list_result(body, source_sha256=h.sha,
                            max_collection_items=8, max_total_items=64, max_payload_size=8192)
                        if read(body) != (1, len(body)):
                            raise ValueError('Whole quest list reader rejected full body')
                        if (struct.unpack('<I', uc.mem_read(packet + 16, 4))[0], uc.mem_read(packet + 20, 1)[0],
                            *bytes(uc.mem_read(packet + 56, 2))) != (expected.code, expected.raw14,
                                int(expected.raw38), int(expected.raw39)):
                            raise ValueError('Quest list scalar fields differ')
                        compare_quests(packet + 24, expected.quests)
                        ptr, n, capacity = struct.unpack('<QII', uc.mem_read(packet + 40, 16))
                        if n != len(expected.assets) or capacity != n:
                            raise ValueError('Asset array count differs')
                        for i, asset in enumerate(expected.assets):
                            at = ptr + i * 32
                            if (uc.mem_read(at + 8, 1)[0], *struct.unpack('<QQ', uc.mem_read(at + 16, 16))) != (
                                    asset.raw08, asset.raw10, asset.raw18):
                                raise ValueError('Asset array fields differ')
                        ptr, n, capacity = struct.unpack('<QII', uc.mem_read(packet + 72, 16))
                        if n != len(expected.data.groups) or capacity != n:
                            raise ValueError('Quest group count differs')
                        for i, group in enumerate(expected.data.groups):
                            at = ptr + i * 32
                            if uc.mem_read(at + 8, 1)[0] != group.raw08:
                                raise ValueError('Quest group enum differs')
                            compare_quests(at + 16, group.quests)
                        if int.from_bytes(uc.mem_read(packet + 88, 8), 'little') != expected.data.raw18:
                            raise ValueError('Quest data suffix differs')
                        cases.append(dict(q=q, a=a, g=g, nested=nested, raw=raw, size=len(body)))
    short = []
    body = body_for(2, 2, 2, 2, 255)
    for size in range(len(body)):
        ok, consumed = read(body[:size])
        if ok or not 0 <= consumed <= size:
            raise ValueError('Short quest list accepted or overread')
        short.append(dict(size=size, consumed=consumed))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        native_execution=True, network_used=False, cases=cases, short=short,
        fragments=h.fragments, leaves=h.leaves, evidence=evidence,
        limits=['Whole ID 1802, nested readers, callbacks, array loop and resize wrappers execute.',
            'Fresh zeroed initial object; allocation, pointer-free record copy, cleanup and free are bounded fixtures.',
            'No constructor, nonempty reused arrays, growth, handler, field meaning or live request proof.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-quest-list-replay', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']), short=len(report['short']))))
