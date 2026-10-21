"""Execute new SDK settings prefix, GMC2 constructor and version getter."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
SETTINGS, SETTINGS_STOP, GMC, VERSION = 0x1444b4100, 0x1444b41a9, 0x1444c5080, 0x14452baa0


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    archive = load('sdk_default_archive', HERE / 'replay-release-archive-input.py')
    h = archive.make_harness(extra_addresses=(SETTINGS, GMC, VERSION), fixtures={})
    evidence = h.comparison / 'details/run-1d8612e8e473/details.json'
    evidence_sha = '361f02451d80318880d8f59586c7e54124b52af725aed0e088d60b675a96c74d'
    if h.audit.sha256(evidence) != evidence_sha:
        raise ValueError('Reviewed SDK Ghidra evidence changed')
    rows = {r['address']: r for f in h.fragments for r in f['instructions']}
    if SETTINGS_STOP not in rows:
        raise ValueError('Settings prefix end is not an instruction boundary')
    h.uc.mem_map(0x24000000, 0x10000)
    obj, heap = 0x24001000, [0x24004000]
    captured, base_calls = {}, []
    def finish(value):
        x = h.x
        sp = h.uc.reg_read(x.UC_X86_REG_RSP)
        h.uc.reg_write(x.UC_X86_REG_RAX, value)
        h.uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(h.uc.mem_read(sp, 8), 'little'))
        h.uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
    def fixture(machine):
        x = h.x
        address = machine.reg_read(x.UC_X86_REG_RIP)
        destination, source = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX)]
        if address == 0x1417cbc10:
            if destination != obj:
                raise ValueError('Unexpected settings base receiver')
            base_calls.append(address)
            finish(destination)
            return
        if not obj <= destination <= obj + 0x300 - 16 or destination in captured:
            raise ValueError('SDK constructor string destination bound or duplicate')
        width = 2 if address == 0x141426c10 else 1
        offset = h.image.offset(source - h.image.pe.base)
        data = h.raw[offset:offset + 512]
        end = next((i for i in range(0, len(data) - width + 1, width) if data[i:i + width] == bytes(width)), None)
        if end is None:
            raise ValueError('SDK literal text bound')
        text = data[:end].decode('utf-16le' if width == 2 else 'ascii')
        payload = text.encode('utf-16le') + bytes(2)
        pointer = heap[0]
        heap[0] += (len(payload) + 15) & ~15
        if heap[0] > 0x2400f000:
            raise ValueError('SDK string fixture storage bound')
        machine.mem_write(pointer, payload)
        machine.mem_write(destination, struct.pack('<QII', pointer, len(payload) // 2, len(payload) // 2))
        captured[destination] = dict(source=hex(source), source_bytes=data[:end + width].hex(), text=text)
        finish(destination)
    for address in (0x1417cbc10, 0x141426c10, 0x141426a30):
        for page in (address & ~4095, (address & ~4095) + 4096):
            if not any(lo <= page <= hi for lo, hi, permissions in h.uc.mem_regions()):
                h.uc.mem_map(page, 4096)
                off = h.image.offset(page - h.image.pe.base)
                h.uc.mem_write(page, h.raw[off:off + 4096])
        if h.fixtures is None:
            raise ValueError('Expected mutable fixture dictionary')
        h.fixtures[address] = fixture
    cases = []
    for poison in (0, 0x55, 0xaa, 0xff):
        captured.clear(); base_calls.clear(); heap[0] = 0x24004000
        h.uc.mem_write(obj - 16, bytes([poison]) * 0x340)
        stack = h.scratch + 0x30000
        h.uc.reg_write(h.x.UC_X86_REG_RSP, stack)
        h.uc.reg_write(h.x.UC_X86_REG_RCX, obj)
        h.uc.emu_start(SETTINGS, SETTINGS_STOP, count=2048)
        if h.uc.reg_read(h.x.UC_X86_REG_RIP) != SETTINGS_STOP:
            raise ValueError('Settings prefix instruction budget')
        fields = {name: captured[obj + offset]['text'] for name, offset in
            (('Market', 0x28), ('GameCode', 0x38), ('SDKType', 0x50), ('WindowsEmailClientId', 0x68),
             ('AndroidEmailClientId', 0x78), ('IosEmailClientId', 0x88), ('NetmarbleClientId', 0x98))}
        fields.update(BuildCode=h.uc.mem_read(obj + 0x48, 1)[0], SDKZone=h.uc.mem_read(obj + 0x49, 1)[0])
        expected = dict(Market='', GameCode='thered', SDKType='Global', WindowsEmailClientId='',
            AndroidEmailClientId='', IosEmailClientId='', NetmarbleClientId='', BuildCode=0, SDKZone=1)
        if fields != expected or base_calls != [0x1417cbc10] or len(captured) != 7:
            raise ValueError('New SDK constructor defaults differ')
        cases.append(dict(kind='settings-prefix', poison=poison, values=fields, literals=list(captured.values())))
        captured.clear(); base_calls.clear(); heap[0] = 0x24004000
        h.uc.mem_write(obj - 16, bytes([poison]) * 0x340)
        # Diagnostic output disabled explicitly, not inferred as active game state.
        h.uc.mem_write(0x14b5662e0, bytes(1))
        if h.call(GMC, obj, budget=10000) != obj:
            raise ValueError('GMC constructor return differs')
        fields = {hex(offset): captured[obj + offset]['text'] for offset in (0x150, 0x160, 0x170, 0x180, 0x190, 0x1c8)}
        if fields['0x170'] != 'https://apis.netmarble.com/gc2' or fields['0x190'] != 'netmarbles' or fields['0x1c8'] != 'netmarbles-v5':
            raise ValueError('New GMC profile constructor fields differ')
        if bytes(h.uc.mem_read(obj - 16, 16)) != bytes([poison]) * 16 or bytes(h.uc.mem_read(obj + 0x260, 16)) != bytes([poison]) * 16:
            raise ValueError('GMC constructor crossed object bounds')
        cases.append(dict(kind='gmc-constructor', poison=poison, values=fields, literals=list(captured.values())))
    captured.clear(); heap[0] = 0x24004000
    if h.call(VERSION, obj) != obj or captured[obj]['text'] != '5.2.11':
        raise ValueError('SDK version getter differs')
    cases.append(dict(kind='sdk-version', literal=captured[obj]))
    report = dict(schema=1, source=str(h.source), source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        ghidra_evidence_sha256=evidence_sha, fragments=h.fragments, cases=cases,
        settings_prefix=dict(start=hex(SETTINGS), end_exclusive=hex(SETTINGS_STOP)),
        dependencies={p: h.audit.sha256(HERE / p) for p in ('replay-release-archive-input.py', 'replay-release-nested-read-thunk.py',
            'build-native-entry-code.py', 'requirements-native.txt')},
        capstone_version=h.env.capstone.__version__, unicorn_version=h.env.unicorn.__version__,
        compatibility='not_established', network_ready=False,
        limits=['Actual settings prefix, full GMC constructor with diagnostics disabled and SDK version getter execute.',
            'Base object, FString construction and storage are bounded fixtures; no config overrides or engine lifecycle.',
            'Game-specific client ID/market overrides, PC label binding and GMC request pipeline remain unverified for this release.'])
    target = h.audit.save_snapshot(h.comparison / 'sdk-defaults-replay', report)
    print(json.dumps(dict(report=str(target), sha256=h.audit.sha256(target), cases=len(cases)), indent=2))


if __name__ == '__main__':
    main()
