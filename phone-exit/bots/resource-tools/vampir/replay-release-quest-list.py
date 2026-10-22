"""Actual ID1802 constructor / reader, bounded fresh arrays and empty item changes."""
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
from vampir_core.quest_list import decode_quest_list_result


def run():
    spec = importlib.util.spec_from_file_location('actual_quest_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec);spec.loader.exec_module(archive)
    fixtures = {}
    addresses = (0x145829ac0, 0x14582cac0, 0x14579e360, 0x1457a9cc0,
        0x1457aad30, 0x1456bb6b0, 0x1456b8e10, 0x1457a77c0, 0x1457a7a20,
        0x145787dd0, 0x144aad880)
    h = archive.make_harness(extra_addresses=addresses,
        extra_leaves=(0x14579b070, 0x145835650, 0x1457840d0, 0x144aae4e0), fixtures=fixtures)
    evidence = {'details/run-387f0cc495c4/details.json':
        '1a292ffca303ecf85f86a2a97423188bca387fe6b2c89f2ff3f9f76c06629e43',
        'details/run-df3c5d97b2b8/details.json':
        '658e92284a85cbcd397427d8008910a209b148eb6c03151b6da3aa973b053f9b'}
    for name, digest in evidence.items():
        if h.audit.sha256(h.comparison / name) != digest: raise ValueError('Actual quest evidence changed')
    uc, x = h.uc, h.x
    heap = [h.scratch + 0x20000]
    def finish():
        sp = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(sp, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
    def cleanup(machine):
        if machine.reg_read(x.UC_X86_REG_RDX) & 0xffffffff: raise ValueError('Fresh cleanup only')
        finish()
    def allocate(machine):
        container = machine.reg_read(x.UC_X86_REG_RCX)
        n = machine.reg_read(x.UC_X86_REG_RDX) & 0xffffffff
        if n > 8 or bytes(machine.mem_read(container, 16)) != bytes(16): raise ValueError('Fresh bounded allocation only')
        stride = 72 if machine.reg_read(x.UC_X86_REG_RIP) == 0x141865400 else 32
        ptr = heap[0] if n else 0;heap[0] += (n * stride + 15) & ~15
        if heap[0] > h.scratch + 0x3f000: raise ValueError('Quest allocation bound')
        if n: machine.mem_write(ptr, bytes(n * stride))
        machine.mem_write(container, struct.pack('<QII', ptr, 0, n));finish()
    def empty_resize(machine):
        if machine.reg_read(x.UC_X86_REG_R8) & 65535: raise ValueError('Nonempty item changes unsupported')
        finish()
    hooks = {a: cleanup for a in (0x145783520, 0x1456b6cc0, 0x1456b6d50, 0x1456b6d20, 0x1456b6d90)}
    hooks.update({0x141865400: allocate, 0x141438040: allocate,
        0x145747250: empty_resize, 0x1457a0100: empty_resize, 0x145747290: empty_resize,
        0x1456b7990: lambda machine: finish()})
    for page in {a & ~4095 for a in (*hooks, 0x149921430, 0x14994aaa8, 0x14994aa60, 0x149921178)}:
        if not any(lo <= page <= hi for lo, hi, _ in uc.mem_regions()):
            uc.mem_map(page, 4096);off = h.image.offset(page - h.image.pe.base);uc.mem_write(page, h.raw[off:off + 4096])
    fixtures.update(hooks)
    packet = h.scratch + 0x10000
    def read(body):
        heap[0] = h.scratch + 0x20000
        uc.mem_write(packet, bytes(160))
        if h.call(0x145829ac0, packet) != packet or h.call(0x145835650, packet) != 1802:
            raise ValueError('Actual packet constructor / ID mismatch')
        if int.from_bytes(uc.mem_read(packet + 64, 8), 'little') != 0x149921430:
            raise ValueError('Actual suffix is not PktItemChangeList')
        uc.mem_write(h.buffer, bytes(8192))
        if body: uc.mem_write(h.buffer, body)
        h.call(h.ctor, h.obj);uc.mem_write(h.obj + 32, struct.pack('<QI', h.buffer, len(body)))
        uc.mem_write(h.obj + 48, struct.pack('<Q', h.buffer))
        return h.call(0x14582cac0, packet, h.obj, budget=300000) & 255, int.from_bytes(uc.mem_read(h.obj + 48, 8), 'little') - h.buffer
    def compare_quests(expected):
        ptr, n, cap = struct.unpack('<QII', uc.mem_read(packet + 24, 16))
        if (n, cap) != (len(expected), len(expected)): raise ValueError('Quest count differs')
        for i, r in enumerate(expected):
            at = ptr + 72 * i
            actual = (int.from_bytes(uc.mem_read(at + 8, 8), 'little'), uc.mem_read(at + 16, 1)[0],
                uc.mem_read(at + 32, 1)[0], *struct.unpack('<QQ', uc.mem_read(at + 40, 16)),
                uc.mem_read(at + 56, 1)[0], *struct.unpack('<III', uc.mem_read(at + 60, 12)))
            if actual != (r.raw08, r.raw10, r.progress.raw08, r.progress.raw10, r.progress.raw18,
                          int(r.raw38), r.raw3c, r.raw40, r.raw44): raise ValueError('Quest fields differ')
    def body_for(q, a, raw):
        quest = struct.pack('<QBBQQBIII', 0xffffffffffffffff, raw, raw, 0x8000000000000000, 2, raw, 3, 4, 0xffffffff)
        return (struct.pack('<IBH', 100 if raw == 1 else 0, raw, q) + quest * q
            + struct.pack('<H', a) + struct.pack('<BQQ', raw, 7, 0xffffffffffffffff) * a
            + bytes([raw, raw]) + bytes(8))
    cases = []
    for q in (0, 1, 2):
        for a in (0, 1, 2):
            for raw in (0, 1, 255):
                body = body_for(q, a, raw)
                expected = decode_quest_list_result(body, source_sha256=h.sha, max_collection_items=8, max_total_items=64, max_payload_size=8192)
                if read(body) != (1, len(body)): raise ValueError('Actual whole reader rejected body')
                if (struct.unpack('<I', uc.mem_read(packet + 16, 4))[0], uc.mem_read(packet + 20, 1)[0], *bytes(uc.mem_read(packet + 56, 2))) != (expected.code, expected.raw14, int(expected.raw38), int(expected.raw39)):
                    raise ValueError('Quest list fields differ')
                compare_quests(expected.quests)
                ptr, n, cap = struct.unpack('<QII', uc.mem_read(packet + 40, 16))
                if (n, cap) != (a, a): raise ValueError('Asset count differs')
                for i, r in enumerate(expected.assets):
                    at = ptr + i * 32
                    if (uc.mem_read(at + 8, 1)[0], *struct.unpack('<QQ', uc.mem_read(at + 16, 16))) != (r.raw08, r.raw10, r.raw18): raise ValueError('Asset fields differ')
                for offset in (72, 88, 104, 120):
                    if bytes(uc.mem_read(packet + offset, 16)) != bytes(16): raise ValueError('Item collection is not empty')
                cases.append(dict(q=q, a=a, raw=raw, size=len(body)))
    short = [];body = body_for(2, 2, 255)
    for size in range(len(body)):
        ok, used = read(body[:size])
        if ok or not 0 <= used <= size: raise ValueError('Short actual body accepted or overread')
        short.append(dict(size=size, consumed=used))
    rejection = bytes.fromhex('64000000000000000000000000000000000000')
    if read(rejection) != (1, 19): raise ValueError('Observed rejection is not native-readable')
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)), native_execution=True,
        network_used=False, actual_constructor=True, rejection_code=100, cases=cases, short=short,
        fragments=h.fragments, leaves=h.leaves, evidence=evidence,
        limits=['Actual packet / suffix constructors, whole readers, quest / asset callbacks and fresh resize wrappers.',
            'Allocation / empty cleanup / empty item resizers are fixtures; nonempty item changes explicitly unsupported.',
            'Previous PktQuestData fixture was wrong for ID1802; old 243-case report does not prove its real suffix.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-quest-list-corrected-replay', report)
    return path, report


if __name__ == '__main__':
    path, report = run();print(json.dumps(dict(report=str(path), cases=len(report['cases']), short=len(report['short']))))
