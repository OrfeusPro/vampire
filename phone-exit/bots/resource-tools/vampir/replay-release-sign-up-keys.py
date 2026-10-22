"""Whole current SDK key initializers; bounded FString and atexit fixtures only."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
KEYS = (
    (0x1411b0350, 0x14b564d70, 'countryCode'),
    (0x1411b0380, 0x14b564d20, 'credential'),
    (0x1411b03e0, 0x14b564d00, 'deviceKey'),
    (0x1411b0440, 0x14b564da0, 'errorCode'),
    (0x1411b05c0, 0x14b564d10, 'nmDeviceKey'),
    (0x1411b05f0, 0x14b564d80, 'os'),
    (0x1411b06b0, 0x14b564df0, 'resultData'),
)
DETAILS = 'details/run-618b0a5322d7/details.json'
DETAILS_SHA = 'd138a428d29a6fa58f721767120fbdc73b295df3c05dbae395f968c9087d2153'
DEPENDENCIES = ('replay-release-archive-input.py', 'replay-release-nested-read-thunk.py',
    'build-native-entry-code.py', 'build-object-zero-init-code.py', 'extract-native-enums.py',
    'audit-client-release.py', 'requirements-native.txt')


def run():
    spec = importlib.util.spec_from_file_location('signup_key_archive', HERE / DEPENDENCIES[0])
    archive = importlib.util.module_from_spec(spec); spec.loader.exec_module(archive)
    context, events = {}, []

    def finish(machine, value=0):
        sp = machine.reg_read(h.x.UC_X86_REG_RSP)
        machine.reg_write(h.x.UC_X86_REG_RAX, value)
        machine.reg_write(h.x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(h.x.UC_X86_REG_RSP, sp + 8)

    def fstring(machine):
        destination, source = (machine.reg_read(reg) for reg in (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX))
        if destination != context['destination'] or events:
            raise ValueError('Unexpected key constructor call')
        offset = h.image.offset(source - h.image.pe.base)
        data = h.raw[offset:offset + 256]
        end = next((i for i in range(0, len(data), 2) if data[i:i + 2] == b'\0\0'), None)
        if end is None:
            raise ValueError('Key literal exceeds bound')
        text = data[:end].decode('utf-16le')
        if text != context['text']:
            raise ValueError('Compiled key literal changed')
        payload = data[:end + 2]
        pointer = h.scratch + 0x18000
        machine.mem_write(pointer, payload)
        machine.mem_write(destination, struct.pack('<QII', pointer, len(payload) // 2, len(payload) // 2))
        events.append(dict(kind='fstring_fixture', destination=hex(destination), literal=hex(source),
            literal_bytes=payload.hex(), text=text))
        finish(machine, destination)

    def atexit(machine):
        address = machine.reg_read(h.x.UC_X86_REG_RCX)
        if len(events) != 1 or address != context['destructor']:
            raise ValueError('Unexpected destructor registration')
        events.append(dict(kind='atexit_fixture', destructor=hex(address)))
        finish(machine)

    h = archive.make_harness(extra_addresses=[address for address, _, _ in KEYS],
        fixtures={0x141426c10: fstring, 0x1487eb0ac: atexit})
    evidence = h.comparison / DETAILS
    if h.audit.sha256(evidence) != DETAILS_SHA:
        raise ValueError('Reviewed key export changed')
    fragments = [f for f in h.fragments if h.image.pe.base + f['root_begin_rva'] in {a for a, _, _ in KEYS}]
    if len(fragments) != len(KEYS):
        raise ValueError('Key initializer fragments changed')
    cases = []
    for address, destination, text in KEYS:
        fragment = next(f for f in fragments if h.image.pe.base + f['root_begin_rva'] == address)
        rows = fragment['instructions']
        if [r['mnemonic'] for r in rows] != ['sub', 'lea', 'lea', 'call', 'lea', 'add', 'jmp']:
            raise ValueError('Unexpected whole initializer shape')
        if (rows[3]['direct_target'], rows[-1]['direct_target']) != (0x141426c10, 0x1487eb0ac):
            raise ValueError('Unexpected initializer backend')
        for poison in (0, 0x55, 0xaa, 0xff):
            events.clear(); context.update(destination=destination, text=text, destructor=rows[4]['rip_references'][0])
            h.uc.mem_write(destination - 16, bytes([poison]) * 48)
            h.call(address, 0, budget=64)
            if len(events) != 2:
                raise ValueError('Initializer did not complete')
            pointer, count, capacity = struct.unpack('<QII', bytes(h.uc.mem_read(destination, 16)))
            payload = text.encode('utf-16le') + b'\0\0'
            if count != len(payload) // 2 or capacity != count or bytes(h.uc.mem_read(pointer, len(payload))) != payload:
                raise ValueError('Key descriptor or content differs')
            if any(bytes(h.uc.mem_read(p, 16)) != bytes([poison]) * 16 for p in (destination - 16, destination + 16)):
                raise ValueError('Key initializer crossed descriptor bounds')
            cases.append(dict(address=hex(address), destination=hex(destination), poison=poison,
                text=text, events=list(events)))
    report = dict(schema=1, source=str(h.source), source_sha256=h.sha, native_execution=True, network_used=False,
        tool_sha256=h.audit.sha256(Path(__file__)), dependencies={name: h.audit.sha256(HERE / name) for name in DEPENDENCIES},
        evidence=dict(path=str(evidence), sha256=DETAILS_SHA), fragments=fragments, cases=cases,
        limits=['Seven whole key initializers execute; FString construction and destructor registration are bounded fixtures.',
            'Destructor bodies, SDK owner constructor, request assembly, JSON serialization, HTTP and response parsing do not execute.',
            'Compiled key names do not establish a live registration or the current values returned by settings getters.'])
    target = h.audit.save_snapshot(h.comparison / 'sign-up-keys-replay', report)
    return target, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
