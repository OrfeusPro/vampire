"""Current GMC2 URL slice, native build initializers/getters and ASCII append."""
import importlib.util
import itertools
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
from vampir_core.sdk_config import assemble_gmc2_config_url_ascii

START, STOP = 0x1444fb178, 0x1444fb48d
INITIALIZERS = (0x1411b3350, 0x1411b3380, 0x1411b33b0)
GLOBALS = (0x14b5658d8, 0x14b5658e8, 0x14b5658f8)
BUILD, VERSION, APPEND = 0x144532f30, 0x14452baa0, 0x141761ae0


def make_harness(extra_addresses=()):
    spec = importlib.util.spec_from_file_location('gmc_url_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    h = archive.make_harness(extra_addresses=(START, BUILD, VERSION, APPEND, *INITIALIZERS, *extra_addresses),
                             extra_leaves=(0x141453970,), fixtures={})
    evidence = {'run-ae63693173ac': 'e1d4f62cd84ff146340f5f60ed0802dcaad2c68cefac968d7857cb9fa088f599',
                'run-ff5be244c76f': 'f4caea5a759d9639db82abcfa1298e474a8dcdce29f630879ffaea7245d276d2',
                'run-e2265b35851b': '9f6f21bebd5ce191051fe997d1feaf7128492eaa3886b27dedac141b9aa94541',
                'run-379a720f244e': 'd3489b6de5916d4107ef35d7204a2fb746f715b480f0847140b66572f4aa2f02',
                'run-1d8612e8e473': '361f02451d80318880d8f59586c7e54124b52af725aed0e088d60b675a96c74d'}
    for name, sha in evidence.items():
        path = h.comparison / 'details' / name / 'details.json'
        if h.audit.sha256(path) != sha:
            raise ValueError('GMC2 URL Ghidra evidence changed')
        for function in json.loads(path.read_text('utf-8'))['functions']:
            for row in function.get('instructions', []):
                payload = bytes.fromhex(row['bytes'])
                offset = h.image.offset(int(row['address'], 16) - h.image.pe.base)
                if h.raw[offset:offset + len(payload)] != payload:
                    raise ValueError('GMC2 URL bytes differ from Ghidra')
    rbp, manager, settings, cls = [h.scratch + n for n in (0x10000, 0x14000, 0x15000, 0x16000)]
    heap, events = [h.scratch + 0x20000], []

    def put(destination, text):
        if not (h.scratch <= destination <= h.scratch + 0x40000 - 16 or destination in GLOBALS):
            raise ValueError('GMC2 FString fixture destination')
        payload = (text + '\0').encode('utf-16le')
        pointer = heap[0] if text else 0
        if len(payload) > 512 or heap[0] + len(payload) >= h.scratch + 0x2e000:
            raise ValueError('GMC2 FString fixture size')
        if pointer:
            h.uc.mem_write(pointer, payload)
            heap[0] += (len(payload) + 15) & ~15
        count = len(payload) // 2 if text else 0
        h.uc.mem_write(destination, struct.pack('<QII', pointer, count, count))

    def literal(address):
        offset = h.image.offset(address - h.image.pe.base)
        data = h.raw[offset:offset + 256]
        end = next(i for i in range(0, len(data) - 1, 2) if data[i:i + 2] == bytes(2))
        return data[:end].decode('utf-16le')

    def finish(result):
        sp = h.uc.reg_read(h.x.UC_X86_REG_RSP)
        h.uc.reg_write(h.x.UC_X86_REG_RAX, result)
        h.uc.reg_write(h.x.UC_X86_REG_RIP, int.from_bytes(h.uc.mem_read(sp, 8), 'little'))
        h.uc.reg_write(h.x.UC_X86_REG_RSP, sp + 8)

    def fixture(machine):
        address = machine.reg_read(h.x.UC_X86_REG_RIP)
        a, b = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX)]
        result = 0
        if address == 0x141426c10:
            text = literal(b)
            if a in GLOBALS and text != ('A', 'B', 'C')[GLOBALS.index(a)]:
                raise ValueError('Actual build initializer literal changed')
            if a not in GLOBALS and (a != rbp or text != '5.2.11'):
                raise ValueError('Unexpected version literal fixture')
            put(a, text)
            result = a
            events.append(dict(action='literal_storage_fixture', destination=hex(a), literal=text))
        elif address == 0x141436fb0:
            if a != h.gmc_build_output or b != 2:
                raise ValueError('Build getter allocation fixture bound')
            pointer = heap[0]
            heap[0] += 16
            machine.mem_write(a, struct.pack('<Q', pointer))
            machine.mem_write(a + 12, struct.pack('<I', b))
            result = a
        elif address == 0x1444b2e50:
            result = cls
        elif address == 0x141483160:
            if not h.scratch + 0x20000 <= a < h.scratch + 0x2e000:
                raise ValueError('GMC2 free fixture bound')
        elif address != 0x1487eb0ac:
            raise ValueError('Unreviewed GMC2 URL fixture')
        finish(result)

    fixtures = (0x141426c10, 0x141436fb0, 0x1444b2e50, 0x141483160, 0x1487eb0ac)
    for address in fixtures:
        for page in (address & ~4095, (address & ~4095) + 4096):
            if not any(lo <= page <= hi for lo, hi, permissions in h.uc.mem_regions()):
                h.uc.mem_map(page, 4096)
        h.fixtures[address] = fixture
    h.uc.mem_write(cls + 0x110, struct.pack('<Q', settings))

    def run(base, group, code, market):
        heap[0] = h.scratch + 0x20000
        events.clear()
        h.uc.mem_write(rbp - 0x100, b'\xa5' * 0xb20)
        for initializer in INITIALIZERS:
            h.call(initializer, 0, budget=1024)
        put(manager + 0x1e8, base)
        put(manager + 0x1c8, group)
        put(settings + 0x28, market)
        h.uc.mem_write(settings + 0x48, bytes([code]))
        for reg, value in ((h.x.UC_X86_REG_RSP, h.scratch + 0x8000), (h.x.UC_X86_REG_RBP, rbp),
                           (h.x.UC_X86_REG_R15, manager), (h.x.UC_X86_REG_R14, 0)):
            h.uc.reg_write(reg, value)
        h.uc.emu_start(START, STOP, count=30000)
        if h.uc.reg_read(h.x.UC_X86_REG_RIP) != STOP:
            raise ValueError('GMC2 URL instruction budget')
        begin, cursor, end = struct.unpack('<QQQ', bytes(h.uc.mem_read(rbp + 0xf0, 24)))
        if begin != rbp + 0x110 or end != rbp + 0x910 or not begin <= cursor < end or (cursor - begin) % 2:
            raise ValueError('GMC2 builder fixture bounds')
        actual = bytes(h.uc.mem_read(begin, cursor - begin)).decode('utf-16le')
        expected = assemble_gmc2_config_url_ascii(base=base, group=group, sdk_version='5.2.11', build_code=code, market=market)
        if actual != expected:
            raise ValueError('Current native URL differs from portable helper')
        if bytes(h.uc.mem_read(end, 16)) != b'\xa5' * 16:
            raise ValueError('GMC2 builder crossed end guard')
        return dict(base=base, group=group, build_code=code, market=market, actual=actual,
                    events=events.copy(), end_guard_unchanged=True)

    h.gmc_evidence, h.gmc_fixtures, h.gmc_run = evidence, fixtures, run
    h.gmc_put, h.gmc_heap, h.gmc_finish = put, heap, finish
    h.gmc_rbp, h.gmc_manager, h.gmc_settings, h.gmc_class = rbp, manager, settings, cls
    h.gmc_build_output = rbp + 0x20
    return h


def main():
    h = make_harness()
    cases = [h.gmc_run(base, 'netmarbles-v5', code, market) for base, code, market in
             itertools.product(('https://config.invalid', 'https://config.invalid/', ''), (0, 1, 2, 255), ('nmp', 'epicgames'))]
    cases.append(h.gmc_run('https://config.invalid', '', 0, ''))
    cases.append(h.gmc_run('https://config.invalid', 'a/b', 2, 'a b&c=1'))
    cases.append(h.gmc_run('https://apis.netmarble.com/gc2', 'netmarbles-v5', 0, 'nmp'))
    report = dict(schema=1, source=str(h.source), source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
                  ghidra_evidence=h.gmc_evidence, fragments=h.fragments, cases=cases,
                  start=hex(START), stop=hex(STOP), fixtures=[hex(a) for a in h.gmc_fixtures], native_execution=True,
                  dependencies={name: h.audit.sha256(HERE / name) for name in ('replay-release-archive-input.py',
                      'replay-release-nested-read-thunk.py', 'build-native-entry-code.py', 'requirements-native.txt')},
                  portable_helper_sha256=h.audit.sha256(HERE.parents[1] / 'vampir-shared/vampir_core/sdk_config.py'),
                  network_ready=False,
                  limits=['Current Refresh URL slice, native build initializers/getter, SDK version getter and ASCII append execute.',
                          'Manager/settings/CDO, FString storage/allocation, free, exit registration and verified CRT copy are fixtures.',
                          'All cases fit the native inline builder; growth is not intercepted or claimed.',
                          'No complete Refresh, request headers/HTTP, active runtime values or authentication.'])
    path = h.audit.save_snapshot(h.comparison / 'gmc2-url-replay', report)
    print(json.dumps(dict(report=str(path), sha256=h.audit.sha256(path), cases=len(cases)), indent=2))


if __name__ == '__main__':
    main()
