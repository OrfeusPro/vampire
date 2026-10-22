"""Whole current PktQuest / PktQuestProgress readers; no socket or game IO."""
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
from vampir_core.quest_record import decode_quest_record


def run():
    spec = importlib.util.spec_from_file_location('quest_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    h = archive.make_harness(extra_addresses=(0x1457a77c0, 0x1457a7a20),
                             extra_leaves=(0x144aae4e0,))
    uc = h.uc
    bindings = ((0x14994aaa8, 0x20, 0x1457a77c0), (0x14994aa60, 0x20, 0x1457a7a20),
                (h.table, 0x50, 0x144aad7f0), (h.table, 0x60, 0x144aad5f0),
                (h.table, 0x78, 0x144aad590), (h.table, 0x80, 0x144aad590),
                (h.table, 0x88, 0x144aad840))
    for table, slot, target in bindings:
        if struct.unpack_from('<Q', h.raw, h.image.offset(table - h.image.pe.base) + slot)[0] != target:
            raise ValueError('Quest input binding changed')
        page = table & ~4095
        if not any(lo <= page <= hi for lo, hi, _ in uc.mem_regions()):
            uc.mem_map(page, 4096)
            uc.mem_write(page, h.raw[h.image.offset(page - h.image.pe.base):][:4096])
    packet = h.scratch + 0x10000

    def read(body):
        # Exact initial shape used by the array callback; no constructor claim.
        uc.mem_write(packet, bytes(72))
        uc.mem_write(packet, struct.pack('<Q', 0x14994aaa8))
        uc.mem_write(packet + 0x18, struct.pack('<Q', 0x14994aa60))
        uc.mem_write(h.buffer, bytes(64))
        uc.mem_write(h.buffer, body)
        h.call(h.ctor, h.obj)
        uc.mem_write(h.obj + 0x20, struct.pack('<QI', h.buffer, len(body)))
        uc.mem_write(h.obj + 0x30, struct.pack('<Q', h.buffer))
        ok = h.call(0x1457a77c0, packet, h.obj) & 255
        consumed = int.from_bytes(uc.mem_read(h.obj + 0x30, 8), 'little') - h.buffer
        return ok, consumed

    cases = []
    for key, a, b, c, d, e in ((0, 0, 0, 0, 0, 0),
            (0x0123456789abcdef, 0xfedcba9876543210, 0x8000000000000000, 1, 0x80000000, 0xffffffff),
            (0xffffffffffffffff, 1, 0xffffffffffffffff, 0xffffffff, 2, 3)):
        for state in (0, 1, 5, 6, 7, 255):
            for progress_kind in (0, 1, 127, 255):
                for flag in (0, 1, 255):
                    body = struct.pack('<QBBQQBIII', key, state, progress_kind, a, b, flag, c, d, e)
                    if read(body) != (1, 39):
                        raise ValueError('Whole quest reader rejected full body')
                    portable = decode_quest_record(body, source_sha256=h.sha)
                    actual = (int.from_bytes(uc.mem_read(packet + 8, 8), 'little'),
                        uc.mem_read(packet + 0x10, 1)[0], uc.mem_read(packet + 0x20, 1)[0],
                        *struct.unpack('<QQ', uc.mem_read(packet + 0x28, 16)),
                        uc.mem_read(packet + 0x38, 1)[0],
                        *struct.unpack('<III', uc.mem_read(packet + 0x3c, 12)))
                    expected = (portable.raw08, portable.raw10, portable.progress.raw08,
                        portable.progress.raw10, portable.progress.raw18, int(portable.raw38),
                        portable.raw3c, portable.raw40, portable.raw44)
                    if actual != expected:
                        raise ValueError('Native quest fields differ')
                    cases.append(dict(state=state, progress_kind=progress_kind, flag=flag,
                                      body_hex=body.hex()))
    short = []
    for size in range(39):
        ok, consumed = read(body[:size])
        if ok or not 0 <= consumed <= size:
            raise ValueError('Quest short input accepted or overread')
        short.append(dict(size=size, consumed=consumed))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        native_execution=True, network_used=False, cases=cases, short=short,
        bindings=[dict(table=hex(t), slot=hex(s), target=hex(a)) for t, s, a in bindings],
        fragments=h.fragments, leaves=h.leaves,
        limits=['Whole record and nested progress readers, native scalar input with bounded memcpy fixture.',
                'Initial object shape assigned explicitly; no constructor or array allocation execution.',
                'No list envelope, handler, quest-field semantics, live acceptance or gameplay proof.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-quest-record-replay', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']), short=len(report['short']))))
