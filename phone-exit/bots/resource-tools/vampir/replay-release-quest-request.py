"""Whole current ID 1801 writer and mirror reader, bounded raw output fixture."""
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
from vampir_core.quest_request import encode_quest_list_read


def run():
    spec = importlib.util.spec_from_file_location('quest_request_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    raw_io = 0x144aadd50
    fixtures = {raw_io: None}
    h = archive.make_harness(extra_addresses=(0x145700e20, 0x14582ca50,
        0x144aada00, 0x144aade10, 0x144aadc60),
        extra_leaves=(0x144aae500, 0x142108430, 0x141c57110, 0x145829aa0, 0x145835640), fixtures=fixtures)
    evidence = {'details/run-a1a98a73de63/details.json':
        '0e30af15e3ff4bebf44bb7f6f4a44b8fa77cf19941c937516bd028f951b0e04e'}
    for path, sha in evidence.items():
        if h.audit.sha256(h.comparison / path) != sha:
            raise ValueError('Quest request export changed')
    uc, x = h.uc, h.x
    packet, output = h.scratch + 0x10000, h.scratch + 0x11000
    table = 0x149672748
    bindings = {0x48: 0x144aade10, 0x70: 0x144aadc60, 0x88: raw_io,
                0xb8: 0x142108430, 0xe0: 0x141c57110}
    for slot, target in bindings.items():
        if int.from_bytes(uc.mem_read(table + slot, 8), 'little') != target:
            raise ValueError('Quest output binding changed')
    packet_table = 0x149966f30
    offset = h.image.offset(packet_table - h.image.pe.base)
    if (struct.unpack_from('<Q', h.raw, offset + 16)[0] != 0x145700e20
            or struct.unpack_from('<Q', h.raw, offset + 32)[0] != 0x14582ca50):
        raise ValueError('Quest packet binding changed')
    chunks, widths = [], []
    fail_at = None

    def raw_fixture(machine):
        context, pointer, width = [machine.reg_read(reg) for reg in
            (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        if context != output or width not in (1, 8) or not h.scratch <= pointer <= h.scratch + 0x40000 - width:
            raise ValueError('Quest raw output bound')
        accepted = len(widths) != fail_at
        widths.append(width)
        if accepted: chunks.append(bytes(machine.mem_read(pointer, width)))
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX, int(accepted))
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)

    fixtures[raw_io] = raw_fixture

    def construct():
        uc.mem_write(packet, b'\xa5' * 32)
        if h.call(0x145829aa0, packet) != packet or h.call(0x145835640, packet) != 1801:
            raise ValueError('Quest request constructor / ID changed')
        if (int.from_bytes(uc.mem_read(packet, 8), 'little') != packet_table
                or uc.mem_read(packet + 16, 1)[0] != 0
                or bytes(uc.mem_read(packet + 24, 8)) != bytes(8)):
            raise ValueError('Quest request reset differs')
        h.call(0x144aada00, output)
        chunks.clear()
        widths.clear()

    def read(body):
        uc.mem_write(h.buffer, bytes(32))
        if body: uc.mem_write(h.buffer, body)
        h.call(h.ctor, h.obj)
        uc.mem_write(h.obj + 0x20, struct.pack('<QI', h.buffer, len(body)))
        uc.mem_write(h.obj + 0x30, struct.pack('<Q', h.buffer))
        ok = h.call(0x14582ca50, packet, h.obj) & 255
        return ok, int.from_bytes(uc.mem_read(h.obj + 0x30, 8), 'little') - h.buffer

    cases = []
    for kind in (0, 1, 7, 11, 12, 13, 127, 255):
        for value in (0, 1, 0x8000000000000000, 0xffffffffffffffff):
            construct()
            body = encode_quest_list_read(kind, value, source_sha256=h.sha)
            uc.mem_write(packet + 16, bytes([kind]))
            uc.mem_write(packet + 24, struct.pack('<Q', value))
            if h.call(0x145700e20, packet, output) & 255 != 1 or widths != [1, 8] or b''.join(chunks) != body:
                raise ValueError('Quest writer body differs')
            construct()
            if read(body) != (1, 9):
                raise ValueError('Quest mirror reader rejected full body')
            if (uc.mem_read(packet + 16, 1)[0], int.from_bytes(uc.mem_read(packet + 24, 8), 'little')) != (min(kind, 12), value):
                raise ValueError('Quest mirror fields differ')
            cases.append(dict(raw10=kind, raw18=value, body_hex=body.hex()))
    failures = []
    for fail_at in range(2):
        construct()
        if h.call(0x145700e20, packet, output) & 255 or widths != [1, 8][:fail_at + 1]:
            raise ValueError('Quest writer failure did not stop')
        if b''.join(chunks) != bytes(fail_at):
            raise ValueError('Quest writer failure prefix differs')
        failures.append(dict(fail_at=fail_at, widths=widths.copy()))
    short = []
    for size in range(9):
        construct()
        ok, consumed = read(bytes(9)[:size])
        if ok or not 0 <= consumed <= size:
            raise ValueError('Quest request short input accepted or overread')
        short.append(dict(size=size, consumed=consumed))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        evidence=evidence, native_execution=True, network_used=False, cases=cases,
        failures=failures, short=short, fragments=h.fragments, leaves=h.leaves,
        limits=['Whole packet constructor / ID / writer / mirror reader and scalar aliases execute.',
            'Raw output append is a bounded fixture; no producer, lifecycle, server acceptance or raw18 meaning proof.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-quest-request-replay', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']),
        failures=len(report['failures']), short=len(report['short']))))
