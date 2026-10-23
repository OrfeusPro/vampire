"""Current exported tag assignment slice; no capture, network or profile promotion."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent
EXPORTS = {'run-571e3ba7330a': '4280b5fc70e7708ecf95248adba6aeedcb7cd0755ac2da034ce0fc162a1770a5'}
ENTRY, START, STOP = 0x1467ce6a0, 0x1467ce8da, 0x1467ce931
POINTER = 0x14b1b9e98


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def binding(raw, image):
    offset = image.offset(POINTER-image.pe.base)
    pointer = raw[offset:offset+8]
    address = int.from_bytes(pointer, 'little')
    literal_offset = image.offset(address-image.pe.base)
    data = raw[literal_offset:literal_offset+33]
    if not re.fullmatch(b'[0-9A-F]{32}\0', data):
        raise ValueError('Current compiled tag literal format changed')
    return dict(pointer_address=hex(POINTER), pointer_file_offset=offset, pointer_bytes=pointer.hex(),
        literal_address=hex(address), literal_file_offset=literal_offset, compiled_tag=data[:-1].decode('ascii'))


def replay(root=None):
    harness = load('compiled_tag_current_harness', HERE/'native-request-harness-11316.py')
    h = harness.make_harness(EXPORTS, {ENTRY}, root=root)
    info = binding(h.raw, h.image)
    rows = h.fragments[0]['instructions']
    first = next(r for r in rows if int(r['address'], 16) == START)
    if first['text'] != 'MOV RDX,qword ptr [0x14b1b9e98]':
        raise ValueError('Current tag pointer instruction differs')
    rbp, stack, temporary, storage = [h.scratch+n for n in (0x10000, 0x8000, 0x18000, 0x19000)]
    expected = (info['compiled_tag']+'\0').encode('utf-16le')
    events = []

    def construct(machine):
        a, b = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX)]
        if (a, b) != (stack+0x50, int(info['literal_address'], 16)):
            raise ValueError('Tag constructor fixture binding differs')
        machine.mem_write(temporary, expected)
        machine.mem_write(a, struct.pack('<QII', temporary, 33, 33))
        events.append('construct')
        h.finish(a)

    def allocate(machine):
        a, b = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX)]
        if (a, b) != (rbp+0x50, 33):
            raise ValueError('Tag allocation fixture binding differs')
        machine.mem_write(a, struct.pack('<Q', storage))
        machine.mem_write(a+12, struct.pack('<I', 33))
        events.append('allocate')
        h.finish(a)

    h.add_fixture(0x141426950, construct)
    h.add_fixture(0x141436ed0, allocate)
    # Default harness memcpy is bounded to synthetic memory; tighten arguments.
    def copy(machine):
        a, b, count = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX, h.x.UC_X86_REG_R8)]
        if (a, b, count) != (storage, temporary, 66):
            raise ValueError('Tag copy fixture binding differs')
        machine.mem_write(a, bytes(machine.mem_read(b, count)))
        events.append('copy')
        h.finish(a)
    h.add_fixture(0x1487f5ab9, copy)
    cases = []
    for poison in (0, 0x55, 0xaa, 0xff):
        events.clear()
        h.uc.mem_write(rbp+0x40, bytes([poison])*48)
        h.uc.mem_write(storage-16, b'\xa5'*98)
        for register, value in ((h.x.UC_X86_REG_RBP, rbp), (h.x.UC_X86_REG_RSP, stack), (h.x.UC_X86_REG_R14, 0)):
            h.uc.reg_write(register, value)
        h.uc.emu_start(START, STOP, count=2048)
        if h.uc.reg_read(h.x.UC_X86_REG_RIP) != STOP:
            raise ValueError('Tag slice instruction budget exceeded')
        if bytes(h.uc.mem_read(rbp+0x50, 16)) != struct.pack('<QII', storage, 33, 33):
            raise ValueError('Tag descriptor differs')
        if bytes(h.uc.mem_read(storage, 66)) != expected:
            raise ValueError('Native tag copy differs')
        for address, value in ((rbp+0x40, bytes([poison])*16), (rbp+0x60, bytes([poison])*16),
                               (storage-16, b'\xa5'*16), (storage+66, b'\xa5'*16)):
            if bytes(h.uc.mem_read(address, 16)) != value:
                raise ValueError('Tag slice crossed canary')
        cases.append(dict(poison=poison, tag=info['compiled_tag'], events=events.copy(), canaries_unchanged=True))
    return dict(schema=1, source=str(h.source), source_sha256=h.sha, binding=info, cases=cases,
        evidence=h.evidence, start=hex(START), stop=hex(STOP), network_ready=False,
        dependencies={name: hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            (Path(__file__).name, 'native-request-harness-11316.py', 'build-native-entry-code.py',
             'extract-native-enums.py', 'build-object-zero-init-code.py', 'requirements-native.txt')},
        limits=['Actual exported tag assignment slice only; full Version preparation and Login consumer not executed.',
            'FString ASCII conversion, allocation and memcpy are explicit bounded fixtures.',
            'No official current capture, network, active cache or server compatibility check; no runtime profile promotion.'])


if __name__ == '__main__':
    report = replay()
    audit = load('tag_current_save', HERE/'audit-client-release.py')
    path = audit.save_snapshot(Path('F:/PhoneExit Resources/Vampir/code-clues/compiled-tag-11316'), report)
    print(json.dumps(dict(report=str(path), cases=len(report['cases']), binding=report['binding'])))
