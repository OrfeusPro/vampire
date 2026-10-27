# Generated candidate by generate-sdk-replays-11318.py; review and native replay required.
"""Current GMC2 geo bindings and native country update; synthetic JSON helpers."""
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import struct
HERE = Path(__file__).resolve().parent
EXPORTS = {'run-9e79cd7f7832': 'f36731187d67c70ad75494ff2b2b5535bd287de7d11f221bda0d55a8c8017856', 'run-1a7e48a82067': 'f63ec39e371d6757c1fa8889657fc53368f71723bcc46217823baac17fa38fe9', 'run-8b262adbaa98': '6da48cc0ed1312cb30f3141e86f01ea9569ae81b4f08d853c2efca264bd98fcb', 'run-934cf393e845': '66bf70420bebe7cf3530e7fee7cb01459629459bb78a0b309850954a696516d9', 'run-b66ea903e973': '3afe56601081a2fb64a90f1196585a55415e56c37f05b4dc950d7e25a0116b95', 'run-f808531f96e5': 'b0c641b4af6e227ca2fece365d842fac58c069fe3b333652be397c4477151478'}

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def replay(root=None):
    native = load('geo_source', HERE / 'build-native-entry-code.py')
    root = Path(root) if root else native.ROOT
    source = root / 'client-code-snapshots/d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c/ProjectRED-Win64-Shipping.exe'
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != source.parent.name:
        raise ValueError('GMC2 geo source changed')
    image = native.Image(raw)
    off = image.offset(0x14145f1e0 - image.pe.base)
    compare = raw[off:off + 71]
    if hashlib.sha256(compare).hexdigest() != '591d6b9ae17a1ebc090ce3e9b853202de35bfecd86a36324752503d4548097c0':
        raise ValueError('GMC2 country compare changed')
    harness = load('geo_harness', HERE / 'native-request-harness-11316.py')
    functions = {0x1444c4510, 0x1444fa480, 0x1444df100, 0x1444cf800, 0x1444f8e10, 0x1445518c0, 0x14447d210, 0x14447d460, 0x1411b05c0}
    h = harness.make_harness(EXPORTS, functions, leaves={0x14145f1e0: compare.hex()}, root=root, source_sha256='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c', copy_thunk=0x1487f60d9)
    links = []
    for owner, target, kind in ((0x1444fa480, 0x1444df100, 'LEA'), (0x1444df100, 0x1444cf800, 'CALL'), (0x1444cf800, 0x1444f8e10, 'CALL'), (0x1444f8e10, 0x1445518c0, 'CALL')):
        f = next((f for f in h.fragments if int(f['address'], 16) == owner))
        rows = [r for r in f['instructions'] if r['text'].startswith(kind + ' ') and hex(target) in r['text']]
        if len(rows) != 1:
            raise ValueError('GMC2 geo source link missing/ambiguous')
        links.append(dict(owner=hex(owner), target=hex(target), instruction=rows[0]))
    rbp, manager, settings, cls, response = [h.scratch + n for n in (65536, 81920, 86016, 90112, 94208)]
    heap, options, events = ([0], {}, [])

    def put(destination, value):
        if not (h.scratch <= destination <= h.scratch + 262144 - 16 or destination == 0x14b563df0):
            raise ValueError('GMC2 geo FString destination bound')
        if value is None:
            h.uc.mem_write(destination, bytes(16))
            return
        data = (value + '\x00').encode('utf-16le')
        if len(data) > 512 or heap[0] + len(data) >= h.scratch + 188416:
            raise ValueError('GMC2 geo string heap bound')
        pointer = heap[0]
        heap[0] += len(data) + 15 & ~15
        h.uc.mem_write(pointer, data)
        h.uc.mem_write(destination, struct.pack('<QII', pointer, len(data) // 2, len(data) // 2))

    def text(destination):
        if not (h.scratch <= destination <= h.scratch + 262144 - 16 or destination == 0x14b563df0):
            raise ValueError('GMC2 geo FString object bound')
        pointer, count, capacity = struct.unpack('<QII', bytes(h.uc.mem_read(destination, 16)))
        if not 0 <= count <= capacity <= 256:
            raise ValueError('GMC2 geo FString counts')
        if not count:
            return ''
        if not h.scratch <= pointer <= h.scratch + 262144 - count * 2:
            raise ValueError('GMC2 geo string data bound')
        data = bytes(h.uc.mem_read(pointer, count * 2))
        if data[-2:] != bytes(2):
            raise ValueError('GMC2 geo string terminator')
        return data[:-2].decode('utf-16le')

    def fixture(machine):
        at = machine.reg_read(h.x.UC_X86_REG_RIP)
        a, b, c = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX, h.x.UC_X86_REG_R8)]
        result = 0
        if at in (0x141426950, 0x141426b30):
            width = 1 if at == 0x141426950 else 2
            off = h.image.offset(b - h.image.pe.base)
            data = h.raw[off:off + 512]
            end = next((n for n in range(0, 512, width) if data[n:n + width] == bytes(width)), None)
            if end is None:
                raise ValueError('GMC2 geo constructor literal bound')
            put(a, data[:end].decode('ascii' if width == 1 else 'utf-16le'))
            result = a
        elif at == 0x1444b1850:
            result = cls
        elif at == 0x1416b0660:
            if a != cls:
                raise ValueError('GMC2 geo CDO binding differs')
            machine.mem_write(cls + 272, struct.pack('<Q', settings))
            events.append(['initialize'])
        elif at == 0x14447d210:
            key = text(c)
            expected = 'resultData' if not events else 'geoIp'
            if key != expected or a != (response if expected == 'resultData' else rbp):
                raise ValueError('GMC2 nested field binding differs')
            if b != (rbp if expected == 'resultData' else rbp - 56):
                raise ValueError('GMC2 nested destination differs')
            machine.mem_write(b, bytes(16))
            events.append(['nested', key])
            result = b
        elif at == 0x14447d460:
            key = text(c)
            if a != rbp - 56 or key not in ('clientIp', 'geoLocation'):
                raise ValueError('GMC2 string field binding differs')
            if b != (rbp - 88 if key == 'clientIp' else rbp + 56):
                raise ValueError('GMC2 string destination differs')
            put(b, options[key])
            events.append(['string', key])
            result = b
        elif at == 0x141441d60:
            if a != settings + 1008 or b != rbp + 56:
                raise ValueError('GMC2 country assignment binding differs')
            machine.mem_write(a, bytes(machine.mem_read(b, 16)))
            events.append(['country-assignment'])
            result = a
        elif at == 0x141483080:
            if not h.scratch + 131072 <= a < heap[0]:
                raise ValueError('GMC2 geo free bound')
        elif at != 0x1487e976c:
            raise ValueError('Unreviewed GMC2 geo fixture')
        h.finish(result)
    for at in (0x141426950, 0x141426b30, 0x1444b1850, 0x1416b0660, 0x14447d210, 0x14447d460, 0x141441d60, 0x141483080, 0x1487e976c):
        h.add_fixture(at, fixture)
    h.uc.mem_write(0x14b5652e0, bytes(1))
    cases = []
    keys = None
    for poison, old, new, ip, lazy in itertools.product((0, 85, 170, 255), (None, '', 'JP', 'HK'), (None, '', 'A1', 'a1', 'JP', 'HK', 'A1x'), (None, '', '1.1.1.1'), (False, True)):
        heap[0] = h.scratch + 131072
        events.clear()
        options.update(clientIp=ip, geoLocation=new)
        h.uc.mem_write(settings, bytes([poison]) * 1280)
        h.uc.mem_write(rbp - 384, bytes([poison]) * 768)
        h.call(0x1444c4510, receiver=manager, budget=4096)
        h.call(0x1411b05c0, budget=1024)
        keys = {hex(offset): text(manager + offset) for offset in (192, 208, 224, 240)}
        if list(keys.values()) != ['geoIp', 'clientIp', 'geoLocation', 'isoCountry'] or text(0x14b563df0) != 'resultData':
            raise ValueError('GMC2 geo constructor key bindings differ')
        put(settings + 56, 'old-ip-fixture')
        put(settings + 1008, old)
        h.uc.mem_write(cls + 272, struct.pack('<Q', 0 if lazy else settings))
        for name, value in dict(RSP=rbp - 256, RBP=rbp, RCX=manager, RDX=response).items():
            h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + name), value)
        h.uc.emu_start(0x1444f8e3c, 0x1444f8f03, count=10000)
        if h.uc.reg_read(h.x.UC_X86_REG_RIP) != 0x1444f8f03:
            raise ValueError('GMC2 geo instruction budget')
        preserved = new is not None and new.lower() == 'a1' and bool(old)
        wanted = old if preserved else new
        if text(settings + 56) != (ip or '') or text(settings + 1008) != (wanted or ''):
            raise ValueError('GMC2 geo/country result differs')
        if sum((e[0] == 'country-assignment' for e in events)) != int(not preserved):
            raise ValueError('GMC2 country gate differs')
        if bytes(h.uc.mem_read(settings + 992, 16)) != bytes([poison]) * 16 or bytes(h.uc.mem_read(settings + 1024, 16)) != bytes([poison]) * 16:
            raise ValueError('GMC2 country canaries changed')
        cases.append(dict(poison=poison, old_country=old, incoming_country=new, incoming_ip=ip, lazy_cdo=lazy, country=text(settings + 1008), ip=text(settings + 56), preserved=preserved, events=events.copy(), canaries_unchanged=True))
    return dict(schema=1, source=str(h.source), source_sha256=h.sha, evidence=h.evidence, keys=keys, links=links, cases=cases, native_execution=True, network_ready=False, dependencies={name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in ('replay-gmc2-geo-11318.py', 'native-request-harness-11316.py', 'build-native-entry-code.py', 'extract-native-enums.py', 'build-object-zero-init-code.py')}, limits=['Actual constructor/resultData initializer, geo caller slice, SetCountryCode with notification/logging disabled and compare execute.', 'JSON nested/string wrappers, FString storage/assignment/free, exit registration and CDO getters are fixtures.', 'Callback chain is static only; full JSON conversion, constants/cache update, notification, actual route/IP, browser and authentication not executed.'])
if __name__ == '__main__':
    report = replay()
    audit = load('geo_snapshot', HERE / 'audit-client-release.py')
    path = audit.save_snapshot(Path('F:/PhoneExit Resources/Vampir/code-clues/gmc2-geo-11318'), report)
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
