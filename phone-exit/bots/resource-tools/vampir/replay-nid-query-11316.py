"""Current native ASCII query encoder and explicit serializer/caller links."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
SHA = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
EXPORTS = {'run-cd25b4a7660d': '8906d32083c6889a5f9ac118899d13fb2e03c45f398c10270d8a3143e6af3a2a',
    'run-bdb7533f59ee': '8ab07dc9d0542e95324e9af17f528f9c5438a0d1d0d7740fe9b157ab1d112834',
    'run-988ec3bf8f0a': 'ac636f8488eb37a37646b4213878b4db9bb4c7567e5eddb2569195e346c0f6fd'}
EXPORTS['run-649b566d2b6e'] = 'a8c91092a8f3d87d80bf9e0bfa3c20b92e552c4639ef2f65ededd3bc5e57410b'
LEAVES = {0x141c0c360: (672, '663726f7c82a66ae51abe32b2f2fe17e7cc91ed1ab171caf47e6367fd6810f77'),
    0x1415b3090: (102, '6fafe4a5bef6c84ba8b5f0daac1379c237e228a7c343fc50ab135801adc87f95')}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def replay(root=None):
    native = load('nid_query_source', HERE/'build-native-entry-code.py')
    root = Path(root) if root else native.ROOT
    raw = (root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe').read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA: raise ValueError('NID query source SHA changed')
    image = native.Image(raw); leaves = {}
    for address, (size, expected) in LEAVES.items():
        offset = image.offset(address-image.pe.base); data = raw[offset:offset+size]
        if hashlib.sha256(data).hexdigest() != expected: raise ValueError('NID query leaf SHA changed')
        leaves[address] = data.hex()
    harness = load('nid_query_harness', HERE/'native-request-harness-11316.py')
    leaves[0x141453890] = 'e924223a07'
    h = harness.make_harness(EXPORTS, {0x141c19460, 0x14458d3d0, 0x1450e3c80, 0x1417619b0}, leaves=leaves, root=root)
    links = ((0x1450e3c80, 0x1450e4b80, 0x14458d3d0), (0x14458d3d0, None, 0x141c19460))
    verified_links = []
    for owner, callsite, target in links:
        function = next(f for f in h.fragments if int(f['address'], 16) == owner)
        matches = [r for r in function['instructions'] if (callsite is None or int(r['address'], 16) == callsite)
                   and r['text'] == 'CALL '+hex(target)]
        if len(matches) != 1: raise ValueError('NID query caller link differs')
        verified_links.append(dict(owner=hex(owner), callsite=matches[0]['address'], target=hex(target)))
    output, descriptor = h.scratch+0x10000, h.scratch+0x11000
    heap = [h.scratch+0x20000]

    def text(address):
        pointer, count, capacity = struct.unpack('<QII', bytes(h.uc.mem_read(address, 16)))
        if not 0 <= count <= capacity <= 2048: raise ValueError('NID query FString counts')
        if not count: return ''
        if not h.scratch <= pointer <= h.scratch+0x40000-count*2: raise ValueError('NID query FString bound')
        data = bytes(h.uc.mem_read(pointer, count*2))
        if data[-2:] != bytes(2): raise ValueError('NID query terminator')
        return data[:-2].decode('utf-16le')

    def put(value, destination=output):
        if not h.scratch <= destination <= h.scratch+0x40000-16: raise ValueError('NID query destination bound')
        data = (value+'\0').encode('utf-16le')
        if len(data) > 4096 or heap[0]+len(data) >= h.scratch+0x30000: raise ValueError('NID query heap bound')
        pointer = heap[0]; heap[0] += (len(data)+15)&~15
        h.uc.mem_write(pointer, data); h.uc.mem_write(destination, struct.pack('<QII', pointer, len(data)//2, len(data)//2))

    def fixture(machine):
        at = machine.reg_read(h.x.UC_X86_REG_RIP)
        a, b, c = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX, h.x.UC_X86_REG_R8)]
        if at == 0x1414366c0:
            if a != output or b > 1024: raise ValueError('NID query reserve fixture bound')
        elif at == 0x1414465f0:
            if b != 4 or not h.scratch <= c < h.scratch+0x40000-2: raise ValueError('NID query conversion fixture bound')
            value = int.from_bytes(machine.mem_read(c, 2), 'little')
            if not 32 <= value <= 126: raise ValueError('NID query ASCII fixture scope')
            machine.mem_write(a, bytes([value, 0, 0, 0]))
        elif at == 0x141429e10:
            if a != output or c != 3: raise ValueError('NID query escaped append fixture bound')
            value = bytes(machine.mem_read(b, c*2)).decode('utf-16le')
            if len(value) != 3 or value[0] != '%' or any(v not in '0123456789ABCDEF' for v in value[1:]):
                raise ValueError('NID query hex format differs')
            put(text(a)+value)
        elif at == 0x141429c80:
            if a != output or not 32 <= b & 65535 <= 126: raise ValueError('NID query safe append scope')
            put(text(a)+chr(b & 65535))
        elif at != 0x1487e8ce0: raise ValueError('Unreviewed NID query fixture')
        h.finish(a)
    for at in (0x1414366c0, 0x1414465f0, 0x141429e10, 0x141429c80, 0x1487e8ce0): h.add_fixture(at, fixture)
    sys.path.insert(0, str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.auth_request import _escape_ascii
    values = [chr(n) for n in range(32, 127)] + ['', 'a b+c&d=e%f/?#', ''.join(chr(n) for n in range(32, 127)), '0123456789ABCDEF']
    cases = []
    for poison in (0, 0x55, 0xaa, 0xff):
        # Native whitelist initialization executes once per cold state, then warm.
        h.uc.mem_write(0x14b408a0c, bytes(260))
        for value in values:
            heap[0] = h.scratch+0x20000
            h.uc.mem_write(output-16, bytes([poison])*48)
            raw_value = value.encode('utf-16le')
            h.uc.mem_write(descriptor+32, raw_value or bytes(2))
            h.uc.mem_write(descriptor, struct.pack('<QII', descriptor+32, len(value), len(value)))
            h.uc.reg_write(h.x.UC_X86_REG_RDX, descriptor)
            h.call(0x141c19460, receiver=output, budget=100000)
            encoded = text(output); expected = _escape_ascii(value) if value else ''
            if encoded != expected: raise ValueError('NID query differs from portable encoder')
            if bytes(h.uc.mem_read(output-16, 16)) != bytes([poison])*16 or bytes(h.uc.mem_read(output+16, 16)) != bytes([poison])*16:
                raise ValueError('NID query canaries changed')
            cases.append(dict(poison=poison, value=value, encoded=encoded, canaries_unchanged=True))
    rbp, owner, buffer = h.scratch+0x14000, h.scratch+0x18000, h.scratch+0x1a000
    query, writes, stages = [''], [], []

    def url_fixture(machine):
        at = machine.reg_read(h.x.UC_X86_REG_RIP)
        a, b = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX)]
        if at == 0x1414b0050:
            if a != rbp+0x3b0 or b != rbp+0x450: raise ValueError('NID map copy binding differs')
            stages.append('map-copy')
        elif at == 0x14458d3d0:
            if a != rbp+0x3a0 or b != rbp+0x3b0: raise ValueError('NID serializer binding differs')
            put(query[0], a); stages.append('serializer')
        elif at == 0x1414277b0:
            if a not in (owner+0x48, owner+0x58) or b != buffer: raise ValueError('NID URL owner binding differs')
            data = bytes(machine.mem_read(b, 2048))
            end = next((n for n in range(0, 2048, 2) if data[n:n+2] == bytes(2)), None)
            if end is None: raise ValueError('NID URL termination bound')
            value = data[:end].decode('utf-16le'); put(value, a); writes.append([a-owner, value])
        elif at == 0x141483080:
            if not h.scratch+0x20000 <= a < heap[0]: raise ValueError('NID URL free fixture bound')
        else: raise ValueError('Unreviewed NID URL fixture')
        h.finish(a)
    for at in (0x1414b0050, 0x14458d3d0, 0x1414277b0, 0x141483080): h.add_fixture(at, url_fixture)
    url_cases = []
    for poison in (0, 0x55, 0xaa, 0xff):
        for base in ('', 'https://members.netmarble.com/auth', 'https://fixture.invalid/auth/', 'https://fixture.invalid/auth?old=1'):
            for value in ('', 'gameCode=thered&x=a%20b', 'empty=&x=%2B%26%3D%25'):
                heap[0] = h.scratch+0x20000; writes.clear(); stages.clear(); query[0] = value
                h.uc.mem_write(rbp-0x100, bytes([poison])*0x900)
                put(base, rbp-0xc8)
                h.uc.mem_write(rbp+0x540, struct.pack('<QQQ', buffer, buffer, buffer+2048))
                for reg, val in ((h.x.UC_X86_REG_RBP, rbp), (h.x.UC_X86_REG_RSP, rbp-0x100), (h.x.UC_X86_REG_R13, owner)):
                    h.uc.reg_write(reg, val)
                h.uc.emu_start(0x1450e4a95, 0x1450e4c29, count=10000)
                if h.uc.reg_read(h.x.UC_X86_REG_RIP) != 0x1450e4c29: raise ValueError('NID URL instruction budget')
                expected = base+'?'+value
                if writes != [[0x48, expected], [0x58, expected]] or stages != ['map-copy', 'serializer']:
                    raise ValueError('NID URL assembly/owner writes differ')
                url_cases.append(dict(poison=poison, base=base, synthetic_query=value, owner_writes=writes.copy()))
    return dict(schema=1, source=str(h.source), source_sha256=SHA, evidence=h.evidence,
        leaves={hex(k):dict(size=v[0], sha256=v[1]) for k,v in LEAVES.items()}, verified_links=verified_links,
        cases=cases, url_cases=url_cases, native_execution=True, network_ready=False,
        dependencies={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('replay-nid-query-11316.py','native-request-harness-11316.py','build-native-entry-code.py','extract-native-enums.py','build-object-zero-init-code.py')},
        portable_encoder_sha256=hashlib.sha256((HERE.parents[1]/'vampir-shared/vampir_core/auth_request.py').read_bytes()).hexdigest(),
        limits=['Whole encoder loop plus real whitelist initialization/lookup and hex leaf execute for printable ASCII.',
            'Single UTF-16-unit conversion, reserve/append storage and stack-cookie helper are fixtures; Unicode is excluded.',
            'URL assembly and owner +0x48/+0x58 write bindings execute with map copy, query serialization, FString owner storage/free fixtures; inline buffer has no growth.',
            'Map iteration/serialization, Unicode, real owner storage implementation, browser and authentication are not executed.'])


if __name__ == '__main__':
    report = replay(); audit = load('nid_query_save', HERE/'audit-client-release.py')
    path = audit.save_snapshot(Path('F:/PhoneExit Resources/Vampir/code-clues/nid-query-11316'), report)
    print(json.dumps(dict(report=str(path), cases=len(report['cases']), url_cases=len(report['url_cases']))))
