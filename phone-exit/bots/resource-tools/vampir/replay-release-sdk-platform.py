"""Actual current PC initializer -> global FString -> SDK platform getter."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
INIT, GETTER, GLOBAL = 0x1411b5d00, 0x144533280, 0x14b565888


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    archive = load('platform_release_archive', HERE / 'replay-release-archive-input.py')
    h = archive.make_harness(extra_addresses=(INIT, GETTER), fixtures={})
    evidence = {'run-ae24ed5ec4b5': '967e581e07549de43d4aaa65786d284854375da1346843e4fc97de2ce159844e',
        'run-83004e31f0dc': 'bac36d80d0ddb3aa28cad7f51a4396a9b7079f932a1c18add3c08f859dcacbaf',
        'run-fff9e932d858': '917b8da0a7a108cb8a7beb2442c0f54ea86d0d3ef02e386ee642723c581826cf'}
    for name, digest in evidence.items():
        if h.audit.sha256(h.comparison / 'details' / name / 'details.json') != digest:
            raise ValueError('Reviewed platform Ghidra evidence changed')
    output, source_storage, output_storage = h.scratch + 0x11000, h.scratch + 0x12000, h.scratch + 0x13000
    captured = []
    def finish(value):
        sp = h.uc.reg_read(h.x.UC_X86_REG_RSP)
        h.uc.reg_write(h.x.UC_X86_REG_RAX, value)
        h.uc.reg_write(h.x.UC_X86_REG_RIP, int.from_bytes(h.uc.mem_read(sp, 8), 'little'))
        h.uc.reg_write(h.x.UC_X86_REG_RSP, sp + 8)
    def fixture(machine):
        address = machine.reg_read(h.x.UC_X86_REG_RIP)
        a, b = machine.reg_read(h.x.UC_X86_REG_RCX), machine.reg_read(h.x.UC_X86_REG_RDX)
        if address == 0x141426c10:
            off = h.image.offset(b - h.image.pe.base)
            if a != GLOBAL or h.raw[off:off + 6] != 'PC\0'.encode('utf-16le'):
                raise ValueError('Actual PC initializer source/destination differs')
            machine.mem_write(source_storage, h.raw[off:off + 6])
            machine.mem_write(a, struct.pack('<QII', source_storage, 3, 3))
            captured.append(dict(action='fstring_storage_fixture', source=hex(b), destination=hex(a)))
            finish(a)
        elif address == 0x141436fb0:
            if a != output or not 1 <= b <= 32:
                raise ValueError('Platform destination allocation bound')
            machine.mem_write(a, struct.pack('<Q', output_storage))
            machine.mem_write(a + 12, struct.pack('<I', b))
            captured.append(dict(action='allocation_fixture', units=b))
            finish(a)
        else:
            captured.append(dict(action='exit_registration_capture'))
            finish(0)
    for address in (0x141426c10, 0x141436fb0, 0x1487eb0ac):
        for page in (address & ~4095, (address & ~4095) + 4096):
            if not any(lo <= page <= hi for lo, hi, permissions in h.uc.mem_regions()):
                h.uc.mem_map(page, 4096)
                off = h.image.offset(page - h.image.pe.base)
                h.uc.mem_write(page, h.raw[off:off + 4096])
        h.fixtures[address] = fixture
    cases = []
    for poison in (0, 0x55, 0xaa, 0xff):
        captured.clear()
        h.uc.mem_write(GLOBAL, bytes([poison]) * 16)
        h.call(INIT, 0, budget=1024)
        for code in (3, 2, 255):
            h.uc.mem_write(output - 16, bytes([poison]) * 48)
            returned = h.call(GETTER, output, code, budget=4096)
            pointer, units, capacity = struct.unpack('<QII', bytes(h.uc.mem_read(output, 16)))
            expected = 'PC' if code == 3 else ''
            actual = bytes(h.uc.mem_read(pointer, (units - 1) * 2)).decode('utf-16le') if units else ''
            if returned != output or actual != expected or not 0 <= units <= capacity <= 32:
                raise ValueError('Native platform getter result differs')
            if bytes(h.uc.mem_read(output - 16, 16)) != bytes([poison]) * 16 or bytes(h.uc.mem_read(output + 16, 16)) != bytes([poison]) * 16:
                raise ValueError('Platform getter crossed FString destination bounds')
            cases.append(dict(poison=poison, platform_byte=code, actual=actual, guards_unchanged=True))
    report = dict(schema=1, source=str(h.source), source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        ghidra_evidence=evidence, fragments=h.fragments, cases=cases, last_fixture_events=captured,
        dependencies={p: h.audit.sha256(HERE / p) for p in ('replay-release-archive-input.py', 'replay-release-nested-read-thunk.py',
            'build-native-entry-code.py', 'build-object-zero-init-code.py', 'requirements-native.txt')},
        compatibility='not_established', network_ready=False,
        limits=['Actual PC initializer and platform getter execute through the same global FString.',
            'FString construction/allocation and exit registration are explicit fixtures; bounded CRT copy uses the existing verified import fixture.',
            'Only platform byte 3 and two unsupported fallback values; other platform labels not claimed.',
            'NID caller binding reviewed statically; console/TLS overrides, full NID lifecycle and network are not executed.'])
    target = h.audit.save_snapshot(h.comparison / 'sdk-platform-replay', report)
    print(json.dumps(dict(report=str(target), sha256=h.audit.sha256(target), cases=len(cases)), indent=2))


if __name__ == '__main__':
    main()
