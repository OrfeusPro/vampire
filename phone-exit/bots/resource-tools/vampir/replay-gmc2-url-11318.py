# Generated candidate by generate-sdk-replays-11318.py; review and native replay required.
"""Execute the current inline GMC2 URL builder and its explicit dependencies."""
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import struct
import sys
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
from vampir_core.sdk_config import assemble_gmc2_config_url_ascii
EXPORTS = {'run-9e79cd7f7832': 'f36731187d67c70ad75494ff2b2b5535bd287de7d11f221bda0d55a8c8017856', 'run-1a7e48a82067': 'f63ec39e371d6757c1fa8889657fc53368f71723bcc46217823baac17fa38fe9', 'run-8b262adbaa98': '6da48cc0ed1312cb30f3141e86f01ea9569ae81b4f08d853c2efca264bd98fcb', 'run-934cf393e845': '66bf70420bebe7cf3530e7fee7cb01459629459bb78a0b309850954a696516d9', 'run-b66ea903e973': '3afe56601081a2fb64a90f1196585a55415e56c37f05b4dc950d7e25a0116b95', 'run-f808531f96e5': 'b0c641b4af6e227ca2fece365d842fac58c069fe3b333652be397c4477151478'}
INITIALIZERS = (0x1411b3260, 0x1411b3290, 0x1411b32c0)
GLOBALS = (0x14b5648d8, 0x14b5648e8, 0x14b5648f8)
START, STOP = (0x1444fa608, 0x1444fa91d)

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def replay(root=None):
    harness = load('gmc_url_11316_harness', HERE / 'native-request-harness-11316.py')
    h = harness.make_harness(EXPORTS, {0x1444fa480, 0x1445323c0, 0x14452af30, 0x1417619b0, *INITIALIZERS}, leaves={0x141453890: 'e944283a07'}, root=root, source_sha256='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c', copy_thunk=0x1487f60d9)
    rbp, manager, settings, cls = [h.scratch + n for n in (65536, 81920, 86016, 90112)]
    heap, events = ([h.scratch + 131072], [])

    def put(destination, text):
        if not (h.scratch <= destination <= h.scratch + 262144 - 16 or destination in GLOBALS):
            raise ValueError('GMC2 string destination bound')
        data = (text + '\x00').encode('utf-16le')
        if len(data) > 512 or heap[0] + len(data) >= h.scratch + 188416:
            raise ValueError('GMC2 string allocation bound')
        pointer = heap[0] if text else 0
        if pointer:
            h.uc.mem_write(pointer, data)
            heap[0] += len(data) + 15 & ~15
        count = len(data) // 2 if text else 0
        h.uc.mem_write(destination, struct.pack('<QII', pointer, count, count))

    def literal(address):
        off = h.image.offset(address - h.image.pe.base)
        data = h.raw[off:off + 256]
        end = next((i for i in range(0, 254, 2) if data[i:i + 2] == bytes(2)), None)
        if end is None:
            raise ValueError('GMC2 literal bound')
        return data[:end].decode('utf-16le')

    def fixture(machine):
        address = machine.reg_read(h.x.UC_X86_REG_RIP)
        a, b = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX)]
        result = 0
        if address == 0x141426b30:
            value = literal(b)
            if a in GLOBALS:
                if value != ('A', 'B', 'C')[GLOBALS.index(a)]:
                    raise ValueError('GMC2 build initializer literal differs')
            elif a != rbp or value != '5.2.11':
                raise ValueError('GMC2 SDK version fixture differs')
            put(a, value)
            result = a
            events.append(dict(action='literal_storage', destination=hex(a), value=value))
        elif address == 0x141436ed0:
            if a != rbp + 32 or b != 2:
                raise ValueError('GMC2 build getter allocation bound')
            pointer = heap[0]
            heap[0] += 16
            if heap[0] >= h.scratch + 188416:
                raise ValueError('GMC2 build getter heap bound')
            machine.mem_write(a, struct.pack('<Q', pointer))
            machine.mem_write(a + 12, struct.pack('<I', b))
            result = a
        elif address == 0x1444b22e0:
            result = cls
        elif address == 0x141483080:
            if not h.scratch + 131072 <= a < h.scratch + 188416:
                raise ValueError('GMC2 free fixture bound')
        elif address != 0x1487e976c:
            raise ValueError('Unreviewed GMC2 fixture')
        h.finish(result)
    fixtures = (0x141426b30, 0x141436ed0, 0x1444b22e0, 0x141483080, 0x1487e976c)
    for address in fixtures:
        h.add_fixture(address, fixture)
    h.uc.mem_write(cls + 272, struct.pack('<Q', settings))

    def run(base, group, code, market):
        heap[0] = h.scratch + 131072
        events.clear()
        h.uc.mem_write(rbp - 256, b'\xa5' * 2848)
        for address in INITIALIZERS:
            h.call(address, budget=1024)
        put(manager + 488, base)
        put(manager + 456, group)
        put(settings + 40, market)
        h.uc.mem_write(settings + 72, bytes([code]))
        for register, value in ((h.x.UC_X86_REG_RSP, h.scratch + 32768), (h.x.UC_X86_REG_RBP, rbp), (h.x.UC_X86_REG_R15, manager), (h.x.UC_X86_REG_R14, 0)):
            h.uc.reg_write(register, value)
        h.uc.emu_start(START, STOP, count=30000)
        if h.uc.reg_read(h.x.UC_X86_REG_RIP) != STOP:
            raise ValueError('GMC2 URL instruction budget exhausted')
        begin, cursor, end = struct.unpack('<QQQ', bytes(h.uc.mem_read(rbp + 240, 24)))
        if begin != rbp + 272 or end != rbp + 2320 or (not begin <= cursor < end) or (cursor - begin) % 2:
            raise ValueError('GMC2 inline builder bounds differ')
        actual = bytes(h.uc.mem_read(begin, cursor - begin)).decode('utf-16le')
        if bytes(h.uc.mem_read(end, 16)) != b'\xa5' * 16:
            raise ValueError('GMC2 inline builder end canary changed')
        expected = assemble_gmc2_config_url_ascii(base=base, group=group, sdk_version='5.2.11', build_code=code, market=market)
        if actual != expected:
            raise ValueError('GMC2 native URL differs from portable helper')
        return dict(base=base, group=group, build_code=code, market=market, actual=actual, events=events.copy(), end_canary_unchanged=True)
    cases = [run(base, 'netmarbles-v5', code, market) for base, code, market in itertools.product(('https://config.invalid', 'https://config.invalid/', ''), (0, 1, 2, 255), ('nmp', 'epicgames'))]
    cases.extend([run('https://config.invalid', '', 0, ''), run('https://config.invalid', 'a/b', 2, 'a b&c=1'), run('https://apis.netmarble.com/gc2', 'netmarbles-v5', 0, 'nmp')])
    return dict(schema=1, source=str(h.source), source_sha256=h.sha, evidence=h.evidence, cases=cases, start=hex(START), stop=hex(STOP), copy_import=h.copy_import, fixtures=[hex(a) for a in sorted(h.fixtures)], dependencies={name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in ('replay-gmc2-url-11318.py', 'native-request-harness-11316.py', 'build-native-entry-code.py', 'extract-native-enums.py', 'build-object-zero-init-code.py')}, portable_helper_sha256=hashlib.sha256((HERE.parents[1] / 'vampir-shared/vampir_core/sdk_config.py').read_bytes()).hexdigest(), native_execution=True, network_ready=False, limits=['Actual current URL slice, three build initializers, build/version getters, ASCII append and verified copy tail execute.', 'Manager/settings/CDO, FString storage/allocation, memcpy/free and exit registration are fixtures.', 'All cases fit inline storage; growth target is not intercepted and is not covered.', 'No complete Refresh, HTTP headers, active startup inputs, authentication or network.'])
if __name__ == '__main__':
    report = replay()
    native = load('gmc_url_11316_root', HERE / 'build-native-entry-code.py')
    audit = load('gmc_url_11316_snapshot', HERE / 'audit-client-release.py')
    path = audit.save_snapshot(native.ROOT / 'code-clues/gmc2-url-11318', report)
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
