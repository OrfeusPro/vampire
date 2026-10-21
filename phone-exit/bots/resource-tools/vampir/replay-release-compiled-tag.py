"""Current source pointer -> Version compiled tag and comparison with official HK capture."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
START, STOP, POINTER = 0x1467cff6a, 0x1467cffc1, 0x14b1bce98
CAPTURE = Path('C:/Users/Валентин/.phone-exit/diagnostics/2d1503177164c369d97ba71f1dab281c/traffic.jsonl')
CAPTURE_SHA = '6d9717ac836923b9eaaf12cc86b29b4716da2b54a3900313cf94e06c21f06fe1'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def binding(raw, image, address):
    offset = image.offset(address - image.pe.base)
    pointer_bytes = raw[offset:offset + 8]
    target = int.from_bytes(pointer_bytes, 'little')
    literal_offset = image.offset(target - image.pe.base)
    data = raw[literal_offset:literal_offset + 33]
    if not re.fullmatch(b'[0-9A-F]{32}\0', data):
        raise ValueError('Compiled tag literal format changed')
    return dict(pointer_address=hex(address), pointer_file_offset=offset, pointer_bytes=pointer_bytes.hex(),
                literal_address=hex(target), literal_file_offset=literal_offset, literal_bytes=data.hex(),
                compiled_tag=data[:-1].decode('ascii'))


def main():
    archive = load('release_tag_archive', HERE / 'replay-release-archive-input.py')
    h = archive.make_harness(extra_addresses=(START,), fixtures={})
    evidence = h.comparison / 'details/run-56062ef20a38/details.json'
    evidence_sha = '93787c26752347f476463f92ecf99d4b6f0a038f72dd2b1b43b9e81dbb85fb0d'
    if h.audit.sha256(evidence) != evidence_sha:
        raise ValueError('Current Version preparation Ghidra evidence changed')
    reviewed = json.loads(evidence.read_text('utf-8'))['pairs'][0]['new']
    for row in reviewed['instructions']:
        offset = h.image.offset(int(row['address'], 16) - h.image.pe.base)
        data = bytes.fromhex(row['bytes'])
        if h.raw[offset:offset + len(data)] != data:
            raise ValueError('Current Version preparation bytes differ')
    current = binding(h.raw, h.image, POINTER)
    rbp, stack, temporary, storage = [h.scratch + n for n in (0x10000, 0x8000, 0x18000, 0x19000)]
    expected_bytes = (current['compiled_tag'] + '\0').encode('utf-16le')
    events = []

    def fixture(machine):
        address = machine.reg_read(h.x.UC_X86_REG_RIP)
        a, b, c = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX, h.x.UC_X86_REG_R8)]
        if address == 0x141426a30:
            if (a, b) != (stack + 0x50, int(current['literal_address'], 16)):
                raise ValueError('Current tag source pointer / FString destination differs')
            machine.mem_write(temporary, expected_bytes)
            machine.mem_write(a, struct.pack('<QII', temporary, 33, 33))
            result = a
        elif address == 0x141436fb0:
            if (a, b) != (rbp + 0x50, 33):
                raise ValueError('Current tag allocation fixture bound')
            machine.mem_write(a, struct.pack('<Q', storage))
            machine.mem_write(a + 12, struct.pack('<I', 33))
            result = a
        elif address == h.copy:
            if (a, b, c) != (storage, temporary, len(expected_bytes)):
                raise ValueError('Current tag CRT copy fixture bound')
            machine.mem_write(a, bytes(machine.mem_read(b, c)))
            result = a
        else:
            raise ValueError('Unreviewed tag fixture')
        events.append(hex(address))
        sp = machine.reg_read(h.x.UC_X86_REG_RSP)
        machine.reg_write(h.x.UC_X86_REG_RAX, result)
        machine.reg_write(h.x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(h.x.UC_X86_REG_RSP, sp + 8)

    for address in (0x141426a30, 0x141436fb0, h.copy):
        for page in (address & ~4095, (address & ~4095) + 4096):
            if not any(lo <= page <= hi for lo, hi, permissions in h.uc.mem_regions()):
                h.uc.mem_map(page, 4096)
        h.fixtures[address] = fixture
    cases = []
    for poison in (0, 0x55, 0xaa, 0xff):
        events.clear()
        h.uc.mem_write(rbp + 0x40, bytes([poison]) * 48)
        h.uc.mem_write(storage - 16, b'\xa5' * 98)
        for reg, value in ((h.x.UC_X86_REG_RBP, rbp), (h.x.UC_X86_REG_RSP, stack), (h.x.UC_X86_REG_R14, 0)):
            h.uc.reg_write(reg, value)
        h.uc.emu_start(START, STOP, count=2048)
        if h.uc.reg_read(h.x.UC_X86_REG_RIP) != STOP:
            raise ValueError('Current Version tag slice instruction budget')
        if bytes(h.uc.mem_read(rbp + 0x50, 16)) != struct.pack('<QII', storage, 33, 33):
            raise ValueError('Current Version tag result descriptor differs')
        if bytes(h.uc.mem_read(storage, 66)) != expected_bytes:
            raise ValueError('Current Version tag native copy differs')
        if any(bytes(h.uc.mem_read(a, 16)) != value for a, value in
               ((rbp + 0x40, bytes([poison]) * 16), (rbp + 0x60, bytes([poison]) * 16),
                (storage - 16, b'\xa5' * 16), (storage + 66, b'\xa5' * 16))):
            raise ValueError('Current Version tag crossed guards')
        cases.append(dict(poison=poison, actual=current['compiled_tag'], events=events.copy(), guards_unchanged=True))
    inspector = load('release_tag_capture', HERE.parents[1] / 'vampir-headless/inspect-captured-login.py')
    comparison = {}

    def consume(identifier, body):
        if identifier == 1:
            comparison['version_suffix_matches'] = body.endswith(struct.pack('<H', 32) + current['compiled_tag'].encode() + struct.pack('<I', 1))
        elif identifier == 3:
            comparison['login_tag_matches'] = inspector.decode_login_payload(body, max_payload_size=65536).strings[14] == current['compiled_tag']

    inspector.inspect(CAPTURE, flow=3, expected_sha256=CAPTURE_SHA, _consume_frame=consume)
    if comparison != dict(version_suffix_matches=True, login_tag_matches=True):
        raise ValueError('Official current Version/Login tag differs from compiled source')
    old_sha = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'
    old_source = ROOT / 'client-code-snapshots' / old_sha / 'ProjectRED-Win64-Shipping.exe'
    old_raw = old_source.read_bytes()
    if hashlib.sha256(old_raw).hexdigest() != old_sha:
        raise ValueError('Historical tag source changed')
    historical = binding(old_raw, h.native.Image(old_raw), 0x14b14ae28)
    report = dict(schema=1, source=str(h.source), source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
                  ghidra_evidence_sha256=evidence_sha, binding=current, historical_source_sha256=old_sha, historical_binding=historical,
                  cases=cases, fragments=h.fragments, start=hex(START), stop=hex(STOP), native_execution=True,
                  official_capture_sha256=CAPTURE_SHA, official_comparison=comparison,
                  dependencies={name: h.audit.sha256(HERE / name) for name in ('replay-release-archive-input.py',
                      'replay-release-nested-read-thunk.py', 'build-native-entry-code.py', 'requirements-native.txt')},
                  capture_inspector_sha256=h.audit.sha256(HERE.parents[1] / 'vampir-headless/inspect-captured-login.py'),
                  network_used=False, limits=['Current native Version preparation tag slice executes on four object fills.',
                      'FString storage/allocation and verified CRT copy are bounded fixtures; full Version preparation is not executed.',
                      'Compiled public tag matches both Version suffix and strict Login field in the successful HK capture.',
                      'No captured credentials, runtime overrides, network replay or server acceptance of a changed bot request.'])
    path = h.audit.save_snapshot(h.comparison / 'compiled-tag-replay', report)
    print(json.dumps(dict(report=str(path), sha256=h.audit.sha256(path), binding=current, historical_binding=historical), indent=2))


if __name__ == '__main__':
    main()
