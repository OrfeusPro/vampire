"""Execute current GMC2 Start with explicit CDO, FString and allocator fixtures."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
START = 0x144509080


def main():
    spec = importlib.util.spec_from_file_location('gmc_start_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    h = archive.make_harness(extra_addresses=(START, 0x141441e40), fixtures={})
    evidence = h.comparison / 'details/run-ae63693173ac/details.json'
    evidence_sha = 'e1d4f62cd84ff146340f5f60ed0802dcaad2c68cefac968d7857cb9fa088f599'
    if h.audit.sha256(evidence) != evidence_sha:
        raise ValueError('GMC2 Start Ghidra evidence changed')
    copy_evidence = h.comparison / 'details/run-bed7531e5011/details.json'
    copy_sha = '96a925705bf7e4b90c467df7901dcaf6c4cb4c436b95cef433540397f6817119'
    if h.audit.sha256(copy_evidence) != copy_sha:
        raise ValueError('GMC2 FString copy Ghidra evidence changed')
    reviewed = next(f for f in json.loads(evidence.read_text('utf-8'))['functions'] if int(f['address'], 16) == START)
    copy_reviewed = next(f for f in json.loads(copy_evidence.read_text('utf-8'))['functions'] if int(f['address'], 16) == 0x141441e40)
    for row in reviewed['instructions'] + copy_reviewed['instructions']:
        data = bytes.fromhex(row['bytes'])
        offset = h.image.offset(int(row['address'], 16) - h.image.pe.base)
        if h.raw[offset:offset + len(data)] != data:
            raise ValueError('GMC2 Start bytes differ from Ghidra')
    manager, settings, cls, receiver = [h.scratch + n for n in (0x10000, 0x11000, 0x12000, 0x13000)]
    target = h.scratch + 0x18000
    bases = ('https://alpha-apis.netmarble.com/gc2', 'https://dev-apis.netmarble.com/gc2',
             'https://apis.netmarble.com/gc2', 'https://dr-apis.netmarble.com/gc2')
    h.uc.mem_write(receiver, struct.pack('<Q', manager))
    h.uc.mem_write(cls + 0x110, struct.pack('<Q', settings))
    h.uc.mem_write(0x14b5662e0, bytes(1))  # Explicitly disable diagnostics.
    for index, text in enumerate(bases):
        payload = (text + '\0').encode('utf-16le')
        pointer = h.scratch + 0x14000 + index * 256
        h.uc.mem_write(pointer, payload)
        h.uc.mem_write(manager + 0x150 + index * 16, struct.pack('<QII', pointer, len(payload) // 2, len(payload) // 2))
    events = []

    def fixture(machine):
        address = machine.reg_read(h.x.UC_X86_REG_RIP)
        a, b, c = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX, h.x.UC_X86_REG_R8)]
        if address == 0x1444b2e50:
            result = cls
        elif address == 0x141436fb0:
            if a != manager + 0x1e8 or not 0 < b <= 128:
                raise ValueError('Start allocation fixture bound')
            machine.mem_write(a, struct.pack('<Q', target))
            machine.mem_write(a + 12, struct.pack('<I', b))
            result = a
            events.append(dict(action='growth_fixture', count=b))
        elif address == h.copy:
            if a != target or b not in [h.scratch + 0x14000 + i * 256 for i in range(4)] or not 0 < c <= 256:
                raise ValueError('Start copy fixture bound')
            machine.mem_write(a, bytes(machine.mem_read(b, c)))
            result = a
            events.append(dict(action='copy_fixture', bytes=c))
        else:
            raise ValueError('Unreviewed Start fixture')
        sp = machine.reg_read(h.x.UC_X86_REG_RSP)
        machine.reg_write(h.x.UC_X86_REG_RAX, result)
        machine.reg_write(h.x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(h.x.UC_X86_REG_RSP, sp + 8)

    for address in (0x1444b2e50, 0x141436fb0, h.copy):
        for page in (address & ~4095, (address & ~4095) + 4096):
            if not any(lo <= page <= hi for lo, hi, permissions in h.uc.mem_regions()):
                h.uc.mem_map(page, 4096)
        h.fixtures[address] = fixture
    cases = []
    for zone in range(256):
        for flag in (0, 1):
            events.clear()
            h.uc.mem_write(settings + 0x49, bytes([zone]))
            h.uc.mem_write(settings + 0xc8, bytes([flag]))
            h.uc.mem_write(0x14b1890f4, b'\xcc')
            h.uc.mem_write(manager + 0x1d8, b'\xa5' * 48)
            h.uc.mem_write(manager + 0x1e8, bytes(16))
            h.uc.mem_write(target - 16, b'\xa5' * 288)
            result = h.call(START, receiver, budget=4096)
            pointer, count, capacity = struct.unpack('<QII', bytes(h.uc.mem_read(manager + 0x1e8, 16)))
            expected = bases[zone if zone < 4 else 1]
            expected_count = len(expected) + 1
            if (result, pointer, count, capacity) != (manager + 0x1e8, target, expected_count, expected_count):
                raise ValueError('Start output FString or return differs')
            if bytes(h.uc.mem_read(pointer, count * 2)) != (expected + '\0').encode('utf-16le'):
                raise ValueError('Start selected base differs')
            if h.uc.mem_read(0x14b1890f4, 1)[0] != flag:
                raise ValueError('Start raw flag propagation differs')
            if any(bytes(h.uc.mem_read(a, n)) != b'\xa5' * n for a, n in
                   ((manager + 0x1d8, 16), (manager + 0x1f8, 16), (target - 16, 16), (target + count * 2, 256 - count * 2))):
                raise ValueError('Start crossed fixture guards')
            cases.append(dict(zone=zone, raw_c8=flag, active_base=expected, events=events.copy(), guards_unchanged=True))
    report = dict(schema=1, source=str(h.source), source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
                  ghidra_evidence_sha256=evidence_sha, copy_evidence_sha256=copy_sha, fragments=h.fragments, cases=cases,
                  dependencies={name: h.audit.sha256(HERE / name) for name in ('replay-release-archive-input.py',
                      'replay-release-nested-read-thunk.py', 'build-native-entry-code.py', 'requirements-native.txt')},
                  native_execution=True, network_ready=False,
                  limits=['Whole current GMC2 Start executes with diagnostics explicitly disabled.',
                          'Manager base strings, CDO, allocation and verified CRT copy are fixtures.',
                          'Raw +0xc8 propagation is verified; flag meaning, full startup and HTTP are not.'])
    path = h.audit.save_snapshot(h.comparison / 'gmc2-start-replay', report)
    print(json.dumps(dict(report=str(path), sha256=h.audit.sha256(path), cases=len(cases)), indent=2))


if __name__ == '__main__':
    main()
