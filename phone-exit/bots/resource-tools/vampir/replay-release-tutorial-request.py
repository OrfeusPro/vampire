"""Whole ID 9903 writer and scalar methods, with explicit bounded raw IO fixture."""
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
from vampir_core.tutorial_request import encode_tutorial_request


def run():
    spec = importlib.util.spec_from_file_location('tutorial_request_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    raw_io = 0x144aadd50
    fixtures = {raw_io: None}
    h = archive.make_harness(
        extra_addresses=(0x145858ef0, 0x144aada00, 0x144aadcc0, 0x144aade40),
        extra_leaves=(0x144aae500, 0x144aadae0, 0x1418d4de0, 0x144aadaf0,
                      0x14584d050, 0x145857180), fixtures=fixtures)
    evidence = h.comparison / 'details/run-a9e1e1b3eeea/details.json'
    if h.audit.sha256(evidence) != '9cb0c83ad394995dbb4f7dd27e87628bf24457e266697dfeb64d13614af5274f':
        raise ValueError('Output archive evidence changed')
    writer_evidence = h.comparison / 'details/run-3c64f23644ab/details.json'
    if h.audit.sha256(writer_evidence) != '9cf0f12420ef9967b6771678efda1dcf518ee3886ba7defc515cd291e19bacd4':
        raise ValueError('Tutorial writer evidence changed')
    uc, x = h.uc, h.x
    packet, output = h.scratch + 0x10000, h.scratch + 0x11000
    table = 0x149672748
    bindings = {0x50: 0x144aadcc0, 0x58: 0x144aadcc0, 0x80: 0x144aade40,
                0x88: raw_io, 0xc0: 0x1418d4de0, 0xc8: 0x144aadae0, 0xf0: 0x144aadaf0}
    for slot, target in bindings.items():
        if int.from_bytes(uc.mem_read(table + slot, 8), 'little') != target:
            raise ValueError('Output archive slot differs')
    packet_table_offset = h.image.offset(0x14996b9a8 - h.image.pe.base)
    if struct.unpack_from('<Q', h.raw, packet_table_offset + 0x10)[0] != 0x145858ef0:
        raise ValueError('Tutorial writer binding differs')
    chunks, widths = [], []
    fail_at = None

    def raw_fixture(machine):
        context, pointer, width = [machine.reg_read(reg) for reg in
            (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        if context != output or width not in (1, 4) or not h.scratch <= pointer <= h.scratch + 0x40000 - width:
            raise ValueError('Raw output fixture bound')
        index = len(widths)
        widths.append(width)
        accepted = index != fail_at
        if accepted:
            chunks.append(bytes(machine.mem_read(pointer, width)))
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX, int(accepted))
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)

    fixtures[raw_io] = raw_fixture

    def construct():
        uc.mem_write(packet, b'\xa5' * 32)
        uc.mem_write(output, b'\xa5' * 64)
        if h.call(0x14584d050, packet) != packet or int.from_bytes(uc.mem_read(packet, 8), 'little') != 0x14996b9a8:
            raise ValueError('Tutorial constructor binding differs')
        if bytes(uc.mem_read(packet + 0x10, 9)) != bytes(9) or h.call(0x145857180, packet) != 9903:
            raise ValueError('Tutorial initial fields or ID differ')
        if h.call(0x144aada00, output) != output or int.from_bytes(uc.mem_read(output, 8), 'little') != table:
            raise ValueError('Output constructor binding differs')
        chunks.clear()
        widths.clear()

    cases = []
    for key in (0, 1001, 0x80000000, 0xffffffff):
        for selector in (0, 2, 0x80000000, 0xffffffff):
            for raw18 in (0, 1, 2, 255):
                construct()
                body = struct.pack('<IIB', key, selector, raw18)
                uc.mem_write(packet + 0x10, body)
                if h.call(0x145858ef0, packet, output) & 255 != 1 or widths != [4, 4, 1]:
                    raise ValueError('Tutorial writer did not complete')
                actual = b''.join(chunks)
                if actual != body or actual != encode_tutorial_request(key, selector, raw18, source_sha256=h.sha):
                    raise ValueError('Tutorial request bytes differ')
                cases.append(dict(key=key, selector=selector, raw18=raw18, body_hex=actual.hex()))
    failures = []
    body = struct.pack('<IIB', 1001, 2, 0)
    for fail_at in range(3):
        construct()
        uc.mem_write(packet + 0x10, body)
        result = h.call(0x145858ef0, packet, output) & 255
        prefix = b''.join(chunks)
        if result != 0 or widths != [4, 4, 1][:fail_at + 1] or prefix != body[:4 * fail_at]:
            raise ValueError('Tutorial failure did not stop at the rejected field')
        failures.append(dict(fail_at=fail_at, return_value=result, prefix_hex=prefix.hex()))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        evidence=[dict(path=str(p), sha256=h.audit.sha256(p)) for p in (evidence, writer_evidence)],
        fragments=h.fragments, leaves=h.leaves, output_table=hex(table),
        bindings={hex(k): hex(v) for k, v in bindings.items()}, cases=cases, failures=failures,
        native_execution=True, network_used=False,
        limits=['Whole packet/output constructors, ID getter, packet writer, aliases and scalar writers execute.',
                'Raw output IO is a bounded fixture; allocation, capacity growth and raw archive bookkeeping do not execute.',
                'Raw flag bytes 2/255 test writer preservation, not server acceptance.',
                'No producer gating, active tutorial, response, panel click or live completion claim.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-tutorial-request-replay', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']), failures=len(report['failures']))))
