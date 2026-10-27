# Generated candidate by generate-sdk-replays-11318.py; review and native replay required.
"""Source-bound PC initializer and switch getter, in synthetic memory only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
HERE = Path(__file__).resolve().parent
INIT, GETTER, GLOBAL = (0x1411b5c10, 0x144532710, 0x14b564888)
EXPORTS = {'run-9e79cd7f7832': 'f36731187d67c70ad75494ff2b2b5535bd287de7d11f221bda0d55a8c8017856', 'run-1a7e48a82067': 'f63ec39e371d6757c1fa8889657fc53368f71723bcc46217823baac17fa38fe9', 'run-8b262adbaa98': '6da48cc0ed1312cb30f3141e86f01ea9569ae81b4f08d853c2efca264bd98fcb', 'run-934cf393e845': '66bf70420bebe7cf3530e7fee7cb01459629459bb78a0b309850954a696516d9', 'run-b66ea903e973': '3afe56601081a2fb64a90f1196585a55415e56c37f05b4dc950d7e25a0116b95', 'run-f808531f96e5': 'b0c641b4af6e227ca2fece365d842fac58c069fe3b333652be397c4477151478'}

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def replay(root=None):
    harness = load('platform_11316_harness', HERE / 'native-request-harness-11316.py')
    h = harness.make_harness(EXPORTS, {INIT, GETTER}, root=root, source_sha256='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c', copy_thunk=0x1487f60d9)
    getter = next((f for f in h.fragments if int(f['address'], 16) == GETTER and f.get('block_coverage_complete')))
    if not getter.get('block_coverage_complete') or not set(getter['decompiler_block_starts']) <= {r['address'] for r in getter['instructions']}:
        raise ValueError('Platform switch blocks incomplete')
    output, source_storage, output_storage = [h.scratch + n for n in (69632, 73728, 77824)]
    events = []

    def fixture(machine):
        address = machine.reg_read(h.x.UC_X86_REG_RIP)
        a, b = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX)]
        result = 0
        if address == 0x141426b30:
            off = h.image.offset(b - h.image.pe.base)
            if a != GLOBAL or h.raw[off:off + 6] != 'PC\x00'.encode('utf-16le'):
                raise ValueError('PC initializer literal/destination differs')
            machine.mem_write(source_storage, h.raw[off:off + 6])
            machine.mem_write(a, struct.pack('<QII', source_storage, 3, 3))
            events.append(dict(action='literal_storage_fixture', source=hex(b), destination=hex(a)))
            result = a
        elif address == 0x141436ed0:
            if a != output or not 1 <= b <= 32:
                raise ValueError('Platform allocation bound')
            machine.mem_write(a, struct.pack('<Q', output_storage))
            machine.mem_write(a + 12, struct.pack('<I', b))
            result = a
        elif address == 0x1487e976c:
            events.append(dict(action='exit_registration_fixture'))
        else:
            raise ValueError('Unreviewed platform fixture')
        h.finish(result)
    for address in (0x141426b30, 0x141436ed0, 0x1487e976c):
        h.add_fixture(address, fixture)
    cases = []
    for poison in (0, 85, 170, 255):
        events.clear()
        h.uc.mem_write(GLOBAL, bytes([poison]) * 16)
        h.call(INIT, budget=1024)
        for code in (3, 2, 255):
            h.uc.mem_write(output - 16, bytes([poison]) * 48)
            h.uc.reg_write(h.x.UC_X86_REG_RDX, code)
            returned = h.call(GETTER, output, budget=4096)
            pointer, count, capacity = struct.unpack('<QII', bytes(h.uc.mem_read(output, 16)))
            if returned != output or not 0 <= count <= capacity <= 32:
                raise ValueError('Platform getter return/count differs')
            if count and (not h.scratch <= pointer <= h.scratch + 262144 - count * 2):
                raise ValueError('Platform output data bound')
            data = bytes(h.uc.mem_read(pointer, count * 2)) if count else b''
            if count and data[-2:] != bytes(2):
                raise ValueError('Platform output not terminated')
            actual = data[:-2].decode('utf-16le') if count else ''
            if actual != ('PC' if code == 3 else ''):
                raise ValueError('Platform getter output differs')
            if any((bytes(h.uc.mem_read(at, 16)) != bytes([poison]) * 16 for at in (output - 16, output + 16))):
                raise ValueError('Platform getter changed canaries')
            cases.append(dict(poison=poison, platform_byte=code, actual=actual, canaries_unchanged=True))
    return dict(schema=1, source=str(h.source), source_sha256=h.sha, evidence=h.evidence, cases=cases, getter_instruction_count=len(getter['instructions']), decompiler_block_starts=getter['decompiler_block_starts'], copy_import=h.copy_import, fixtures=[hex(a) for a in sorted(h.fixtures)], dependencies={name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in ('replay-sdk-platform-11318.py', 'native-request-harness-11316.py', 'build-native-entry-code.py', 'extract-native-enums.py', 'build-object-zero-init-code.py')}, native_execution=True, network_ready=False, limits=['Actual PC initializer and switch getter execute through the same global, using the source jump table.', 'FString storage/allocation, memcpy and exit registration are fixtures.', 'Only platform byte 3 and two unsupported values are tested; other platform labels, caller binding, TLS/console overrides and auth are not claimed.'])
if __name__ == '__main__':
    report = replay()
    native = load('platform_11316_root', HERE / 'build-native-entry-code.py')
    audit = load('platform_11316_snapshot', HERE / 'audit-client-release.py')
    path = audit.save_snapshot(native.ROOT / 'code-clues/sdk-platform-11318', report)
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
