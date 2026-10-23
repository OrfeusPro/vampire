"""Whole Fetch callback: exact first-game terms gate, synthetic results, no HTTP."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
SOURCE_SHA = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
EXPORT = ('run-313ff5f10ab1', 'd376e82c676025619f3973f6ba86389e192bb85b48223a76d46529d9b914756e')
CALLBACK = 0x145603ab0


def load(name):
    spec = importlib.util.spec_from_file_location('fetch_' + name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def replay():
    events, fixtures = [], {}
    h = None
    def capture(address):
        def invoke(uc):
            x = h.x
            a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
            result = 0
            if address == 0x1456151f0:
                events.append(dict(kind='log', owner=a, pair=b, step=c & 255))
            elif address == 0x14561b6a0:
                events.append(dict(kind='sign_in', owner=a, channel=b & 255, step=c & 255))
            elif address == 0x14561a200:
                events.append(dict(kind='terms', owner=a))
            elif address == 0x145609600:
                uc.mem_write(b, b'\0' * 16)
                result = b
                events.append(dict(kind='error_text', pair=c))
            elif address == 0x141426c10:
                uc.mem_write(a, b'\0' * 16)
                result = a
            elif address == 0x14561b2b0:
                events.append(dict(kind='message', selector=b & 255))
            else:
                raise ValueError('Unexpected Fetch fixture')
            sp = uc.reg_read(x.UC_X86_REG_RSP)
            uc.reg_write(x.UC_X86_REG_RAX, result)
            uc.reg_write(x.UC_X86_REG_RIP, struct.unpack('<Q', bytes(uc.mem_read(sp, 8)))[0])
            uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
        return invoke
    for address in (0x1456151f0, 0x14561b6a0, 0x14561a200, 0x145609600, 0x141426c10, 0x14561b2b0):
        fixtures[address] = capture(address)
    h = load('replay-release-archive-input').make_harness(extra_addresses=(CALLBACK,), fixtures=fixtures)
    evidence = h.comparison / 'details' / EXPORT[0] / 'details.json'
    if hashlib.sha256(evidence.read_bytes()).hexdigest() != EXPORT[1]:
        raise ValueError('Fetch export changed')
    data = json.loads(evidence.read_text('utf-8'))
    if data['new_source_sha256'] != SOURCE_SHA: raise ValueError('Fetch export source changed')
    for f in data['functions']:
        if not f['decompilation_completed']: raise ValueError('Fetch export incomplete')
        for row in f['instructions']:
            offset = h.image.offset(int(row['address'], 16) - h.image.pe.base)
            code = bytes.fromhex(row['bytes'])
            if h.raw[offset:offset + len(code)] != code: raise ValueError('Fetch instruction changed')
    leaves = {0x144532750: '837904000f94c0c3', 0x141a2d1b0: '8b410cc3', 0x14180e6e0: '488b4128c3'}
    for address, hex_bytes in leaves.items():
        code = bytes.fromhex(hex_bytes)
        offset = h.image.offset(address - h.image.pe.base)
        if h.raw[offset:offset + len(code)] != code: raise ValueError('Fetch getter changed')
        page = address & ~4095
        if not any(lo <= page <= hi for lo, hi, _ in h.uc.mem_regions()): h.uc.mem_map(page, 4096)
        h.uc.mem_write(address, code)
        h.ranges.append((address, address + len(code)))
    enums, rejected = load('extract-native-enums').extract(h.raw)
    wanted = {'ENetmarbleSDKStep': {'Fetch': 11, 'SignUpForGuest': 12, 'SignUpForNetmarble': 13,
              'SignInForGuest': 14, 'SignInForNetmarble': 15},
              'ENMChannelType': {'Netmarble': 33, 'Guest': 100, 'Launcher': 200},
              'ENetmarbleSDKCode': {'ShowBasicTerm': 30050027}}
    enum_rows = {}
    for family, values in wanted.items():
        if any(r['enum'] == family for r in rejected): raise ValueError('Ambiguous Fetch enum')
        rows = [r for r in enums[family] if r['name'].split('::')[-1] in values]
        if {r['name'].split('::')[-1]: r['value'] for r in rows} != values:
            raise ValueError('Fetch enum mapping changed')
        enum_rows[family] = rows
    storage, control, owner, pair, response = [h.scratch + n for n in (0x1000, 0x1800, 0x2000, 0x2800, 0x3000)]
    cases = []
    for success in (False, True):
        for code in (0, 30050026, 30050027, 30050012):
            for context in (1202, 1203, 1204):
                events.clear()
                h.uc.mem_write(storage, struct.pack('<QQ', owner, control))
                h.uc.mem_write(control, struct.pack('<QII', 0, 4, 1))
                h.uc.mem_write(pair, struct.pack('<QQ', response, 0))
                h.uc.mem_write(response, b'\0' * 64)
                h.uc.mem_write(response + 4, struct.pack('<I', 0 if success else 1))
                h.uc.mem_write(response + 12, struct.pack('<I', code))
                h.uc.mem_write(response + 40, struct.pack('<Q', context))
                h.call(CALLBACK, storage, pair)
                expected = ['log', 'sign_in'] if success else (['log', 'terms'] if (code, context) == (30050027, 1203) else ['log', 'error_text', 'message'])
                if [e['kind'] for e in events] != expected: raise ValueError('Fetch gate differs')
                if events[0] != dict(kind='log', owner=owner, pair=pair, step=11): raise ValueError('Fetch log changed')
                if success and events[1] != dict(kind='sign_in', owner=owner, channel=33, step=15):
                    raise ValueError('Fetch SignIn handoff changed')
                if expected[-1] == 'message' and events[-1]['selector'] != 6: raise ValueError('Fetch error selector changed')
                if struct.unpack('<I', bytes(h.uc.mem_read(control + 8, 4)))[0] != 4: raise ValueError('Fetch owner count changed')
                cases.append(dict(success=success, code=code, context=context, events=list(events), owner_count=4))
    for name, own, ctrl, count in (('no-control', owner, 0, 4), ('expired', owner, control, 0), ('no-owner', 0, control, 4)):
        events.clear()
        h.uc.mem_write(storage, struct.pack('<QQ', own, ctrl))
        h.uc.mem_write(control, struct.pack('<QII', 0, count, 1))
        h.call(CALLBACK, storage, pair)
        if events or struct.unpack('<I', bytes(h.uc.mem_read(control + 8, 4)))[0] != count:
            raise ValueError('Fetch expired owner produced action')
        cases.append(dict(owner_gate=name, events=[]))
    return dict(schema=1, source=str(h.source), source_sha256=SOURCE_SHA, callback=hex(CALLBACK),
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependencies={n + '.py': hashlib.sha256((HERE / (n + '.py')).read_bytes()).hexdigest() for n in (
            'replay-release-archive-input', 'replay-release-nested-read-thunk', 'build-native-entry-code',
            'build-object-zero-init-code', 'extract-native-enums', 'audit-client-release')},
        evidence=dict(path=str(evidence), sha256=EXPORT[1]), functions=data['functions'], enums=enum_rows,
        getter_bytes={hex(a): b for a, b in leaves.items()}, cases=cases, network_requests=0,
        limits=['Whole Fetch callback and three native getters; logger/UI/terms/SignIn are captures.',
                'Enum names derive from current contiguous PE descriptors, not string order.',
                'Raw response fields are synthetic; SDK Fetch HTTP and error construction are not executed.',
                'Exact Fetch gate does not authorize fallback on launcher/sign-in 1203.',
                'No real terms, registration, auth token, player or character is modified.'])


if __name__ == '__main__':
    report = replay()
    audit = load('audit-client-release')
    target = audit.save_snapshot(load('build-native-entry-code').ROOT / 'code-clues/release-fetch-result', report)
    print(json.dumps(dict(report=str(target), sha256=audit.sha256(target), cases=len(report['cases']), network_requests=0)))
