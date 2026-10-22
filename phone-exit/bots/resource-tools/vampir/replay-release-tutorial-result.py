"""Whole ID 9904 constructor and reader with native scalar input; no game IO."""
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
from vampir_core.tutorial_result import decode_tutorial_result


def run():
    spec = importlib.util.spec_from_file_location('tutorial_result_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    fixtures = {address: None for address in (0x1464b0910, 0x145692af0, 0x1467cee40,
                                              0x1464c06d0, 0x1464c16d0)}
    h = archive.make_harness(extra_addresses=(0x14584d0a0, 0x14584f890, 0x1457ff150, 0x1467cabc0),
                             extra_leaves=(0x1457fee50, 0x1458571a0, 0x144aae4e0), fixtures=fixtures)
    evidence = {
        'details/run-91409cb5259a/details.json': '510a2f095db09cfa331c9a72253231bd8ecead56ad8d02af6ce53cfc3577cdfb',
        'details/run-8a2129c0aba9/details.json': 'b74b3ffe9aeb054caa8a7e5cbde10ec001ff46e2615b63cbdd3c525ea35d6869',
        'details/run-74973e2905f8/details.json': 'cde28a9f0e3e863d7183589da6c7418293cea47f3e4e0118d291690671991b1d',
        'details/run-4ec0da51a9f0/details.json': '1032df87507c1f596263b595c5af677a3312a275d7d619e58db5447e5949e7dd'}
    for path, sha in evidence.items():
        if h.audit.sha256(h.comparison / path) != sha:
            raise ValueError('Tutorial result evidence changed')
    uc = h.uc
    # This reviewed conditional leaf has no unwind entry. Pin its complete bytes,
    # including the early RET and the tail JMP to the explicit UI-mode fixture.
    clear_wait = 0x1464c19e0
    clear_bytes = bytes.fromhex('80b90803000000740ec6810803000000b101e9f9101dffc3')
    clear_offset = h.image.offset(clear_wait - h.image.pe.base)
    if h.raw[clear_offset:clear_offset + len(clear_bytes)] != clear_bytes:
        raise ValueError('Reviewed clear-wait leaf changed')
    page = clear_wait & ~4095
    if not any(lo <= page <= hi for lo, hi, _ in uc.mem_regions()):
        uc.mem_map(page, 4096)
        offset = h.image.offset(page - h.image.pe.base)
        uc.mem_write(page, h.raw[offset:offset + 4096])
    h.ranges.append((clear_wait, clear_wait + len(clear_bytes)))
    bindings = ((0x14996ba48, 0x20, 0x14584f890), (0x14996ba48, 0x28, 0x1458571a0),
                (0x14992afc0, 0x20, 0x1457ff150))
    for table, slot, target in bindings:
        offset = h.image.offset(table - h.image.pe.base)
        if struct.unpack_from('<Q', h.raw, offset + slot)[0] != target:
            raise ValueError('Tutorial result slot differs')
        page = table & ~4095
        if not any(lo <= page <= hi for lo, hi, _ in uc.mem_regions()):
            uc.mem_map(page, 4096)
            offset = h.image.offset(page - h.image.pe.base)
            uc.mem_write(page, h.raw[offset:offset + 4096])
    packet = h.scratch + 0x10000

    def read(body):
        uc.mem_write(packet, b'\xa5' * 64)
        if h.call(0x14584d0a0, packet) != packet or h.call(0x1458571a0, packet) != 9904:
            raise ValueError('Result constructor or ID differs')
        if (int.from_bytes(uc.mem_read(packet, 8), 'little') != 0x14996ba48 or
                int.from_bytes(uc.mem_read(packet + 0x18, 8), 'little') != 0x14992afc0 or
                bytes(uc.mem_read(packet + 0x10, 4)) != bytes(4) or
                bytes(uc.mem_read(packet + 0x20, 13)) != bytes(13) or
                bytes(uc.mem_read(packet + 0x30, 2)) != bytes(2)):
            raise ValueError('Result initial fields differ')
        uc.mem_write(h.buffer, bytes(64))
        if body:
            uc.mem_write(h.buffer, body)
        h.call(h.ctor, h.obj)
        uc.mem_write(h.obj + 0x20, struct.pack('<QI', h.buffer, len(body)))
        uc.mem_write(h.obj + 0x30, struct.pack('<Q', h.buffer))
        accepted = h.call(0x14584f890, packet, h.obj) & 255
        consumed = int.from_bytes(uc.mem_read(h.obj + 0x30, 8), 'little') - h.buffer
        return accepted, consumed

    cases = []
    for code in (0, 4223, 0xffffffff):
        for fields in ((0, 0, 0), (1001, 2, 1001002), (0xffffffff, 0x80000000, 0xffffffff)):
            for state in (0, 1, 2, 3, 4, 255):
                for raw30, raw31 in ((0, 0), (1, 0), (0, 1), (255, 255)):
                    body = struct.pack('<IIIIBBB', code, *fields, state, raw30, raw31)
                    if read(body) != (1, len(body)):
                        raise ValueError('Whole result reader rejected a full body')
                    expected = decode_tutorial_result(body, source_sha256=h.sha)
                    actual = (struct.unpack('<I', uc.mem_read(packet + 0x10, 4))[0],
                              *struct.unpack('<IIIB', uc.mem_read(packet + 0x20, 13)),
                              *bytes(uc.mem_read(packet + 0x30, 2)))
                    record = expected.record
                    if actual != (expected.code, record.raw08, record.raw0c, record.raw10,
                                  record.state, int(expected.raw30), int(expected.raw31)):
                        raise ValueError('Native result fields differ from the portable decoder')
                    cases.append(dict(code=code, fields=fields, state=state, raw30=raw30, raw31=raw31))
    short = []
    body = struct.pack('<IIIIBBB', 0, 1001, 2, 1001002, 1, 1, 1)
    for size in range(len(body)):
        accepted, consumed = read(body[:size])
        if accepted or consumed > size:
            raise ValueError('Truncated tutorial result accepted or overread')
        short.append(dict(size=size, consumed=consumed))
    context, events = h.scratch + 0x12000, []

    def handler_fixture(machine):
        x = h.x
        address = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c, d = [machine.reg_read(reg) for reg in
            (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        value = 0
        if address == 0x1464b0910:
            value = context
        elif address == 0x145692af0:
            if a & 255 != 1:
                raise ValueError('Clear-wait UI-mode argument differs')
            events.append('clear_wait_mode')
        elif address == 0x1467cee40:
            if b & 0xffffffff != 9904 or d or bytes(machine.mem_read(c, 24)) != bytes(24):
                raise ValueError('Result gate arguments differ')
            if machine.mem_read(context + 0x308, 1)[0] != 0:
                raise ValueError('Wait flag was not cleared before gate')
            events.append('gate_fixture')
            value = int(a & 0xffffffff == 0)
        elif address == 0x1464c06d0:
            if (a, b, c) != (context, packet, 0):
                raise ValueError('Result apply handoff differs')
            events.append('apply_fixture')
        elif address == 0x1464c16d0:
            key = int.from_bytes(machine.mem_read(packet + 0x20, 4), 'little')
            if a != context or b & 0xffffffff != key or c & 255 != 1:
                raise ValueError('Special result handoff differs')
            events.append('special_fixture')
        else:
            raise ValueError('Unexpected handler fixture')
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX, value)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)

    for address in fixtures:
        fixtures[address] = handler_fixture
    handler_cases = []
    for code in (0, 1, 4223, 9400, 0xffffffff):
        for key in (0, 1001, 0xffffffff):
            for waiting in (0, 1, 255):
                if read(struct.pack('<IIIIBBB', code, key, 2, 77, 1, 0, 0)) != (1, 19):
                    raise ValueError('Handler input decode differs')
                uc.mem_write(context + 0x308, bytes([waiting]))
                events.clear()
                h.call(0x1467cabc0, 0, 0, packet)
                expected = (['clear_wait_mode'] if waiting else []) + ['gate_fixture']
                if code == 0:
                    expected.append('apply_fixture')
                elif code == 4223:
                    expected.append('special_fixture')
                if events != expected or uc.mem_read(context + 0x308, 1)[0]:
                    raise ValueError('Handler order or wait reset differs')
                handler_cases.append(dict(code=code, key=key, waiting=waiting, events=list(events)))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        evidence=evidence, fragments=h.fragments, leaves=h.leaves, cases=cases, short=short,
        clear_wait_leaf=dict(address=hex(clear_wait), bytes=clear_bytes.hex()), handler_cases=handler_cases,
        native_execution=True, network_used=False,
        limits=['Whole packet constructor, nested constructor, ID getter and complete result/nested/scalar readers execute.',
                'The base harness substitutes bounded memcpy; no allocation or game IO executes.',
                'Whole handler and reviewed wait-clear leaf execute, but context lookup, UI mode, common gate, apply and special producer are fixtures.',
                'The gate fixture accepts only code 0; this does not establish native common-gate policy for other codes.',
                'State clamps to 3 and raw30/raw31 normalize to bool; their semantic names remain unknown.',
                'Synthetic result codes and records do not prove server acceptance or live tutorial completion.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-tutorial-result-replay', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']), short=len(report['short']),
                          handler_cases=len(report['handler_cases']))))
