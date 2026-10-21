"""Current SDK defaults + initializers + actual market selector and zone override."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
OVERRIDE, SELECTOR, MARKET_GETTER = 0x145658ca0, 0x14560c680, 0x14452abd0
INITIALIZERS = (0x14125b800, 0x14125b830, 0x14125b860, 0x14125b8c0)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    archive = load('override_release_archive', HERE / 'replay-release-archive-input.py')
    h = archive.make_harness(extra_addresses=(0x1444b4100, OVERRIDE, SELECTOR, MARKET_GETTER, *INITIALIZERS), fixtures={})
    evidence = {'run-8ffb7dbcdcff': '4d32fe8932f3121d9155540b737b09137434cc3a67ed023e267bf6beb51539c9',
        'run-f43686dcac55': '30fd3276d957fc9dff241c215ba1a4810df7cab6d3b3dec85272819c679f0c65',
        'run-27454953ad4c': '13b6067cbbd5b220ecf0c32183d87fe434120e8b841ef922f0aebf52906320cf'}
    reviewed = {}
    for name, sha in evidence.items():
        path = h.comparison / 'details' / name / 'details.json'
        if h.audit.sha256(path) != sha:
            raise ValueError('Reviewed override evidence changed')
        reviewed.update({int(f['address'], 16): f for f in json.loads(path.read_text('utf-8'))['functions']})
    # Comparators and the override's shared tail are reviewed Ghidra leaf bodies.
    leaves = []
    for address in (0x14145f2c0, 0x14145f310, 0x1445530b0):
        rows = reviewed[address if address in reviewed else OVERRIDE]['instructions']
        if address == 0x1445530b0:
            rows = [row for row in rows if address <= int(row['address'], 16) < address + 7]
            if [row['bytes'] for row in rows] != ['890d2a60c306', 'c3']:
                raise ValueError('Override shared tail changed')
        cursor, data = address, bytearray()
        for row in rows:
            if int(row['address'], 16) != cursor:
                raise ValueError('Comparator Ghidra instruction gap')
            part = bytes.fromhex(row['bytes'])
            data.extend(part); cursor += len(part)
        off = h.image.offset(address - h.image.pe.base)
        if h.raw[off:off + len(data)] != data:
            raise ValueError('Comparator bytes differ from Ghidra')
        h.ranges.append((address, cursor))
        leaves.append(dict(address=hex(address), bytes=data.hex(), file_offset=off))
    def map_page(page):
        if any(lo <= page <= hi for lo, hi, permissions in h.uc.mem_regions()):
            return
        h.uc.mem_map(page, 4096)
        try:
            off = h.image.offset(page - h.image.pe.base)
        except ValueError:
            if not any(s['rva'] <= page - h.image.pe.base < s['rva'] + s['size'] for s in h.image.pe.sections):
                raise ValueError('Unreviewed non-PE memory page')
            return
        h.uc.mem_write(page, h.raw[off:off + 4096])
    for leaf in leaves:
        map_page(int(leaf['address'], 16) & ~4095)
    map_page(0x1489f6400 & ~4095)
    settings, class_object, env_object, sdk_object = [h.scratch + n for n in (0x11000, 0x14000, 0x15000, 0x16000)]
    heap, options, events = [h.scratch + 0x20000], {}, []
    def allocate(size):
        pointer = heap[0]
        heap[0] += (size + 15) & ~15
        if heap[0] > h.scratch + 0x2e000:
            raise ValueError('Override fixture allocation bound')
        return pointer
    globals_allowed = {0x14b5e8f88, 0x14b5e8f78, 0x14b5e8fc8, 0x14b5e8fb8}
    def put_string(destination, text):
        if not (h.scratch <= destination <= h.scratch + 0x40000 - 16 or destination in globals_allowed):
            raise ValueError('Override FString destination bound')
        payload = text.encode('utf-16le') + bytes(2)
        if len(payload) > 256:
            raise ValueError('Override string bound')
        pointer = allocate(len(payload)) if text else 0
        if pointer:
            h.uc.mem_write(pointer, payload)
        h.uc.mem_write(destination, struct.pack('<QII', pointer, len(payload) // 2 if text else 0, len(payload) // 2 if text else 0))
    def literal(address):
        off = h.image.offset(address - h.image.pe.base)
        data = h.raw[off:off + 256]
        end = next(i for i in range(0, len(data) - 1, 2) if data[i:i + 2] == bytes(2))
        return data[:end].decode('utf-16le')
    def finish(value=0):
        sp = h.uc.reg_read(h.x.UC_X86_REG_RSP)
        h.uc.reg_write(h.x.UC_X86_REG_RAX, value)
        h.uc.reg_write(h.x.UC_X86_REG_RIP, int.from_bytes(h.uc.mem_read(sp, 8), 'little'))
        h.uc.reg_write(h.x.UC_X86_REG_RSP, sp + 8)
    def fixture(machine):
        address = machine.reg_read(h.x.UC_X86_REG_RIP)
        a, b, c = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX, h.x.UC_X86_REG_R8)]
        result = 0
        if address == 0x141426c10:
            put_string(a, literal(b)); result = a
        elif address == 0x141436fb0:
            if a not in (settings + 0x28, settings + 0x38, settings + 0x98) or not 0 <= b <= 128:
                raise ValueError('Override capacity fixture bound')
            machine.mem_write(a, struct.pack('<Q', allocate(b * 2) if b else 0))
            machine.mem_write(a + 12, struct.pack('<I', b))
            result = a
        elif address == 0x1444b2e50:
            result = class_object
        elif address == 0x14560c530:
            result = sdk_object if options['sdk_present'] else 0
        elif address == 0x141439550:
            if a != env_object + 0x48:
                raise ValueError('Environment receiver differs')
            put_string(b, options['environment']); result = b
        elif address == 0x14152d6a0:
            result = h.scratch + 0x18000
        elif address == 0x14158ef20:
            if a != h.scratch + 0x18000 or literal(b) != 'NMENV=':
                raise ValueError('Market command-line key changed')
            if options['nmenv'] is not None:
                put_string(c, options['nmenv']); result = 1
            events.append(dict(action='command_line_value_fixture', key='NMENV=', present=options['nmenv'] is not None))
        elif address == 0x1417cbc10:
            if a != settings:
                raise ValueError('SDK base fixture receiver differs')
        elif address not in (0x141483160, 0x1487eb0ac):
            raise ValueError('Unreviewed override fixture')
        finish(result)
    fixture_addresses = (0x141426c10, 0x141436fb0, 0x1444b2e50, 0x14560c530, 0x141439550,
        0x14152d6a0, 0x14158ef20, 0x1417cbc10, 0x141483160, 0x1487eb0ac)
    for address in fixture_addresses:
        map_page(address & ~4095); map_page((address & ~4095) + 4096)
        h.fixtures[address] = fixture
    def text(address):
        pointer, count, capacity = struct.unpack('<QII', bytes(h.uc.mem_read(address, 16)))
        if not 0 <= count <= capacity <= 128:
            raise ValueError('Override output FString bounds')
        return bytes(h.uc.mem_read(pointer, (count - 1) * 2)).decode('utf-16le') if count else ''
    cases = []
    def run(environment, nmenv, sdk_present=True, sdk_handle=True):
        options.update(environment=environment, nmenv=nmenv, sdk_present=sdk_present)
        events.clear(); heap[0] = h.scratch + 0x20000
        h.uc.mem_write(settings - 16, b'\xa5' * 0x250)
        h.uc.mem_write(class_object + 0x110, struct.pack('<Q', settings))
        h.uc.mem_write(sdk_object + 0x38, struct.pack('<Q', 1 if sdk_handle else 0))
        h.uc.mem_write(0x14b5e9ce0, struct.pack('<Q', env_object))
        h.uc.mem_write(0x14b5662e0, bytes(1))  # Disable diagnostic output only.
        stack = h.scratch + 0x30000
        h.uc.reg_write(h.x.UC_X86_REG_RSP, stack)
        h.uc.reg_write(h.x.UC_X86_REG_RCX, settings)
        h.uc.emu_start(0x1444b4100, 0x1444b41a9, count=2048)
        if h.uc.reg_read(h.x.UC_X86_REG_RIP) != 0x1444b41a9:
            raise ValueError('SDK prefix budget')
        for initializer in INITIALIZERS:
            h.call(initializer, 0, budget=1024)
        h.uc.mem_write(settings + 0xc8, b'\xff')
        h.call(OVERRIDE, 0, budget=30000)
        actual = dict(market=text(settings + 0x28), game_code=text(settings + 0x38), client_id=text(settings + 0x98),
            build_code=h.uc.mem_read(settings + 0x48, 1)[0], sdk_zone=h.uc.mem_read(settings + 0x49, 1)[0], raw_c8=h.uc.mem_read(settings + 0xc8, 1)[0])
        epic = nmenv is not None and nmenv.lower() == 'epicgames' and sdk_present and sdk_handle
        expected = dict(market='epicgames' if epic else 'nmp', game_code='thered', client_id='18e6xn1vuR1lGrvR',
            build_code=0, sdk_zone=2 if environment in ('real', 'REAL', 'Real', 'rEaL') else 1, raw_c8=0)
        if actual != expected:
            raise ValueError('Override result differs: ' + repr((options, actual, expected)))
        if bytes(h.uc.mem_read(settings - 16, 16)) != b'\xa5' * 16 or bytes(h.uc.mem_read(settings + 0x228, 16)) != b'\xa5' * 16:
            raise ValueError('Override crossed SDK object guards')
        if len(events) != int(sdk_present and sdk_handle):
            raise ValueError('NMENV parser fixture called through wrong gate')
        cases.append(dict(environment=environment, nmenv=nmenv, sdk_present=sdk_present, sdk_handle=sdk_handle,
            actual=actual, events=events.copy(), guards_unchanged=True))
    for env in ('real', 'REAL', 'Real', 'rEaL', '', 'dev', 'alpha', 'dr', 'production', ' real', 'real ', 'reals', 'réal'):
        for market in (None, '', 'nmp', 'NMP', 'epicgames', 'EPICGAMES', 'gpgpc', 'unknown'):
            run(env, market)
    run('real', 'epicgames', sdk_present=False)
    run('real', 'epicgames', sdk_handle=False)
    report = dict(schema=1, source=str(h.source), source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        ghidra_evidence=evidence, fragments=h.fragments, comparator_leaves=leaves, cases=cases,
        fixtures=[hex(a) for a in fixture_addresses], native_execution=True, compatibility='not_established', network_ready=False,
        dependencies={p: h.audit.sha256(HERE / p) for p in ('replay-release-archive-input.py', 'replay-release-nested-read-thunk.py',
            'build-native-entry-code.py', 'requirements-native.txt')},
        limits=['Actual SDK prefix, four global initializers, whole game override, market getter/selector and both comparators execute.',
            'Class/CDO, singleton objects, environment string, FString storage/growth, CRT copy, free and exit registration are fixtures.',
            'FParse value output is an explicit fixture for NMENV=; real command-line parsing and active game inputs are not executed.',
            'No full startup, GMC2 request/HTTP, NID authentication or live server compatibility proof.'])
    target = h.audit.save_snapshot(h.comparison / 'sdk-overrides-replay', report)
    print(json.dumps(dict(report=str(target), sha256=h.audit.sha256(target), cases=len(cases)), indent=2))


if __name__ == '__main__':
    main()
