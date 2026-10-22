"""Whole ID 1810 constructor/writer/mirror reader, bounded raw output fixture."""
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
from vampir_core.quest_update import QuestUpdate, encode_quest_update, decode_quest_update


def run():
    spec = importlib.util.spec_from_file_location('quest_update_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    raw_io = 0x144aadd50
    fixtures = {raw_io: None}
    h = archive.make_harness(extra_addresses=(0x145838300, 0x14582cf30,
        0x144aae5d0, 0x144aae290, 0x144aad640, 0x144aad7c0,
        0x144aada00, 0x144aadcf0, 0x144aade10, 0x144aadc60),
        extra_leaves=(0x144aae500, 0x145829dd0, 0x145835760, 0x142108430, 0x14149b760, 0x141e4aef0),
        fixtures=fixtures)
    for name, sha in {
        'details/run-cf97103628c6/details.json': 'e62f7fc833983810fdd17dde26763a70bcb122ac952417c811c8fed588d4be65',
        'details/run-fd2ff86519da/details.json': 'e6a0c96cddafc285a1df6a3ab36cb94d40f6c75b1e6e944b58e0d8a897c9afc3',
    }.items():
        if h.audit.sha256(h.comparison / name) != sha:
            raise ValueError('Quest update export changed')
    uc, x = h.uc, h.x
    packet, output = h.scratch + 0x10000, h.scratch + 0x11000
    table, packet_table = 0x149672748, 0x149967590
    bindings = {0x38: 0x144aadcf0, 0x48: 0x144aade10, 0x78: 0x144aadc60,
        0x88: raw_io, 0xa8: 0x14149b760, 0xb8: 0x142108430, 0xe8: 0x141e4aef0}
    for slot, target in bindings.items():
        if int.from_bytes(uc.mem_read(table + slot, 8), 'little') != target:
            raise ValueError('Quest update output binding changed')
    offset = h.image.offset(packet_table - h.image.pe.base)
    if struct.unpack_from('<Q', h.raw, offset + 16)[0] != 0x145838300 or struct.unpack_from('<Q', h.raw, offset + 32)[0] != 0x14582cf30:
        raise ValueError('Quest update packet binding changed')
    chunks, widths = [], []
    fail_at = None

    def raw_fixture(machine):
        context, pointer, width = [machine.reg_read(reg) for reg in
            (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        if context != output or width not in (1, 4, 8) or not h.scratch <= pointer <= h.scratch + 0x40000 - width:
            raise ValueError('Quest update raw output bounds')
        accepted = len(widths) != fail_at
        widths.append(width)
        if accepted:
            chunks.append(bytes(machine.mem_read(pointer, width)))
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX, int(accepted))
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)

    fixtures[raw_io] = raw_fixture

    def construct():
        uc.mem_write(packet, b'\xa5' * 64)
        if h.call(0x145829dd0, packet) != packet or h.call(0x145835760, packet) != 1810:
            raise ValueError('Quest update constructor / ID changed')
        if int.from_bytes(uc.mem_read(packet, 8), 'little') != packet_table:
            raise ValueError('Quest update vptr changed')
        if bytes(uc.mem_read(packet + 0x10, 24)) != b'\xa5' * 24:
            raise ValueError('Quest constructor vector unexpectedly initialized')
        if bytes(uc.mem_read(packet + 0x28, 17)) != bytes(17):
            raise ValueError('Quest update constructor reset changed')
        h.call(0x144aada00, output)
        chunks.clear()
        widths.clear()

    def read(body):
        uc.mem_write(h.buffer, bytes(64))
        if body:
            uc.mem_write(h.buffer, body)
        h.call(h.ctor, h.obj)
        uc.mem_write(h.obj + 0x20, struct.pack('<QI', h.buffer, len(body)))
        uc.mem_write(h.obj + 0x30, struct.pack('<Q', h.buffer))
        ok = h.call(0x14582cf30, packet, h.obj) & 255
        return ok, int.from_bytes(uc.mem_read(h.obj + 0x30, 8), 'little') - h.buffer

    cases = []
    vectors = ((0.0, 0.0, 0.0), (1.0, -2.5, 3.25), (-0.0, 1.1754943508222875e-38, 3.4028234663852886e38))
    for vector in vectors:
        for word in (0, 1, 0x8000000000000000, 0xffffffffffffffff):
            for flag in (0, 1, 2, 255):
                value = QuestUpdate(vector, word, word ^ 0xffffffffffffffff, flag)
                body = encode_quest_update(value, source_sha256=h.sha)
                construct()
                uc.mem_write(packet + 0x10, struct.pack('<dddQQB', *vector, value.raw28, value.raw30, flag))
                if h.call(0x145838300, packet, output) & 255 != 1 or widths != [4, 4, 4, 8, 8, 1] or b''.join(chunks) != body:
                    raise ValueError('Quest update writer bytes differ')
                construct()
                if read(body) != (1, 29):
                    raise ValueError('Quest update mirror reader failed')
                decoded = decode_quest_update(body, source_sha256=h.sha)
                expected = struct.pack('<dddQQB', *decoded.vector, decoded.raw28, decoded.raw30, decoded.raw38)
                if bytes(uc.mem_read(packet + 0x10, len(expected))) != expected:
                    raise ValueError('Quest update mirror fields differ')
                cases.append(dict(body_hex=body.hex()))
    failures = []
    for fail_at in range(6):
        construct()
        uc.mem_write(packet + 0x10, bytes(41))
        if h.call(0x145838300, packet, output) & 255 or widths != [4, 4, 4, 8, 8, 1][:fail_at + 1]:
            raise ValueError('Quest update writer did not stop on failure')
        failures.append(dict(fail_at=fail_at, widths=widths.copy()))
    short = []
    for size in range(29):
        construct()
        ok, consumed = read(bytes(size))
        if ok or consumed > size:
            raise ValueError('Quest update short prefix accepted or overread')
        short.append(dict(size=size, consumed=consumed))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)), native_execution=True, network_used=False,
        cases=cases, writer_failures=failures, short_prefixes=short,
        limits=['Whole constructor, ID getter, writer, mirror reader and scalar/vector methods executed.',
            'Raw output append and archive memcpy are bounded fixtures, not native allocation/transport.',
            'Constructor does not initialize vector; callers must supply it.',
            'No field semantic meaning, producer, live action or server acceptance established.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-quest-update-replay', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']),
        writer_failures=len(report['writer_failures']), short_prefixes=len(report['short_prefixes']))))
