"""Whole current game sign-in callback with explicit external captures; no HTTP."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
CALLBACK = 0x145605100
SHA = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
EXPORTS = (
    ('run-e0b2e7fef500', '2542f275a915286ae02709624bfacca4ca7034649104138c2e76abb790a5d794'),
    ('run-480aabc11edb', '6dcb121d9b4f3afcbe19aaed870bc7a59d463613c00ce73a6d35c543498d4e3e'),
    ('run-bd88fe6b96de', 'fdfccac0bee932c873ddf224a86b975e3fea3f2b20ef3a2b33be8e5ab4b35c73'),
    ('run-122867bb3bc4', '7640a2cd9a17d7ff0d76f1a28b735deab08483d24036400ad12adebd2732e159'),
    ('run-6092fea5749a', '96ca33af8b1026fe13594afacc28c960ee358c002038cc7a406792a2bfd38fa3'),
    ('run-1d064761d70c', 'c439dba14da9fb7294249dbf53ced371c1307d3b35c55dd0556c4c9bfa10fec3'),
)


def load(name):
    spec = importlib.util.spec_from_file_location('signin_' + name.replace('-', '_'), HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def replay():
    archive = load('replay-release-archive-input')
    # Capture external actions only. No complete logging, UI or SDK lifecycle.
    fixtures = {}
    events = []
    h = None
    def capture(address):
        def call(uc):
            x = h.x
            a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
            result = 0
            if address == 0x1456151f0:
                events.append(dict(kind='log', owner=a, pair=b, step=c & 255))
            elif address == 0x145609600:
                uc.mem_write(b, b'\0' * 16)
                events.append(dict(kind='error_text', pair=c))
                result = b
            elif address == 0x141426c10:
                uc.mem_write(a, b'\0' * 16)
                result = a
            elif address == 0x14561b2b0:
                events.append(dict(kind='message', selector=b & 255))
            elif address == 0x1445fc660:
                pointer = struct.unpack('<Q', bytes(uc.mem_read(b, 8)))[0]
                events.append(dict(kind='manager_action', pointer=hex(pointer)))
            elif address == 0x145615e40:
                events.append(dict(kind='child_action'))
            else:
                raise ValueError('Unreviewed callback fixture')
            sp = uc.reg_read(x.UC_X86_REG_RSP)
            uc.reg_write(x.UC_X86_REG_RAX, result)
            uc.reg_write(x.UC_X86_REG_RIP, struct.unpack('<Q', bytes(uc.mem_read(sp, 8)))[0])
            uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
        return call
    for address in (0x1456151f0, 0x145609600, 0x141426c10, 0x14561b2b0, 0x1445fc660, 0x145615e40):
        fixtures[address] = capture(address)
    h = archive.make_harness(extra_addresses=(CALLBACK,), fixtures=fixtures)
    folder = h.comparison / 'details'
    evidence = []
    functions = {}
    for name, expected in EXPORTS:
        path = folder / name / 'details.json'
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Sign-in export changed')
        data = json.loads(path.read_text('utf-8'))
        if data['new_source_sha256'] != SHA:
            raise ValueError('Sign-in export source mismatch')
        evidence.append(dict(path=str(path), sha256=expected))
        for f in data['functions']:
            if not f['decompilation_completed']: raise ValueError('Incomplete sign-in export')
            functions[f['address']] = f
            for row in f['instructions']:
                offset = h.image.offset(int(row['address'], 16) - h.image.pe.base)
                raw = bytes.fromhex(row['bytes'])
                if h.raw[offset:offset + len(raw)] != raw: raise ValueError('Sign-in instruction changed')
    route = []
    for caller, target in ((0x14561b6a0, 0x144503c80), (0x144503c80, 0x144503d00),
                           (0x144503d00, 0x144504980), (CALLBACK, 0x1456151f0),
                           (0x1444e7630, 0x141409e10)):
        rows = functions[hex(caller)]['instructions']
        sites = [r['address'] for r in rows if r['text'] == 'CALL ' + hex(target)]
        if not sites: raise ValueError('Required sign-in handoff missing')
        route.append(dict(caller=hex(caller), target=hex(target), callsites=sites))
    leaves = {0x144532750: '837904000f94c0c3', 0x141a2d1b0: '8b410cc3', 0x14180e6e0: '488b4128c3'}
    for address, hex_bytes in leaves.items():
        code = bytes.fromhex(hex_bytes)
        offset = h.image.offset(address - h.image.pe.base)
        if h.raw[offset:offset + len(code)] != code: raise ValueError('Sign-in getter changed')
        page = address & ~4095
        if not any(lo <= page <= hi for lo, hi, _ in h.uc.mem_regions()):
            h.uc.mem_map(page, 4096)
        h.uc.mem_write(address, code)
        h.ranges.append((address, address + len(code)))
    leaf = 0x145608220
    offset = h.image.offset(leaf - h.image.pe.base)
    if h.raw[offset:offset + 5] != bytes.fromhex('e9dbceffff'):
        raise ValueError('Game callback thunk changed')
    storage, control, pair, response, owner, manager = [h.scratch + n for n in (0x1000, 0x1800, 0x2000, 0x3000, 0x4000, 0x5000)]
    h.uc.mem_write(0x14b5e8ec0, struct.pack('<Q', manager))
    profiles = [(0, 0, 0), (1, 0, 1203),
                (1, 40040011, 429), (1, 40040011, 502), (1, 40040011, 200),
                (1, 30050012, 429), (1, 30050012, 502), (1, 30050012, 1203)]
    cases = []
    for step in (0, 14, 15, 255):
        for result, code, status in profiles:
            for child in (False, True):
                events.clear()
                h.uc.mem_write(storage, struct.pack('<QQQ', owner, control, step))
                h.uc.mem_write(control, struct.pack('<QII', 0, 4, 1))
                h.uc.mem_write(pair, struct.pack('<QQ', response, 0))
                h.uc.mem_write(response, b'\0' * 64)
                h.uc.mem_write(response + 4, struct.pack('<I', result))
                h.uc.mem_write(response + 12, struct.pack('<I', code))
                h.uc.mem_write(response + 40, struct.pack('<Q', status))
                h.uc.mem_write(manager + 0x58, struct.pack('<Q', int(child)))
                h.call(CALLBACK, storage, pair)
                expected = ['log']
                if step in (14, 15):
                    if result == 0:
                        expected += ['manager_action'] + (['child_action'] if child else [])
                    elif code in (40040011, 30050012) and status in (429, 502):
                        expected += ['manager_action']
                    else:
                        expected += ['error_text', 'message']
                if [e['kind'] for e in events] != expected:
                    raise ValueError('Unexpected whole sign-in callback branch')
                if events[0] != dict(kind='log', owner=owner, pair=pair, step=step):
                    raise ValueError('Sign-in log arguments changed')
                for event in events:
                    if event['kind'] == 'message' and event['selector'] != (7 if step == 14 else 8):
                        raise ValueError('Sign-in message selector changed')
                    if event['kind'] == 'manager_action':
                        pointer = '0x143b92dd0' if result == 0 else '0x144570980'
                        if event['pointer'] != pointer: raise ValueError('Sign-in action changed')
                count = struct.unpack('<I', bytes(h.uc.mem_read(control + 8, 4)))[0]
                if count != 4: raise ValueError('Sign-in owner pin unbalanced')
                cases.append(dict(step=step, field_4=result, field_c=code, field_28=status,
                    child_present=child, events=list(events), owner_count=count))
    for label, own, ctrl, count in (('no-control', owner, 0, 4), ('expired', owner, control, 0), ('no-owner', 0, control, 4)):
        events.clear()
        h.uc.mem_write(storage, struct.pack('<QQQ', own, ctrl, 14))
        h.uc.mem_write(control, struct.pack('<QII', 0, count, 1))
        h.call(CALLBACK, storage, pair)
        if events: raise ValueError('Expired owner produced an action')
        if struct.unpack('<I', bytes(h.uc.mem_read(control + 8, 4)))[0] != count:
            raise ValueError('Expired owner count changed')
        cases.append(dict(owner_gate=label, events=[]))
    return dict(schema=1, source=str(h.source), source_sha256=SHA,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), evidence=evidence,
        dependencies={name + '.py': hashlib.sha256((HERE / (name + '.py')).read_bytes()).hexdigest()
            for name in ('replay-release-archive-input', 'replay-release-nested-read-thunk',
                         'build-native-entry-code', 'build-object-zero-init-code', 'extract-native-enums', 'audit-client-release')},
        callback=hex(CALLBACK), route=route, getter_bytes={hex(k): v for k, v in leaves.items()},
        functions=list(functions.values()), cases=cases, network_requests=0,
        limits=['Whole callback and three getter leaves execute on the current EXE in Unicorn.',
                'Logger, error-text/string construction, message UI, manager and child actions are fixtures/captures.',
                'SDK HTTP, error construction, queue, callback binding and complete caller lifecycle are not executed.',
                'Raw result fields are synthetic; field_28=1203 is a boundary case, not a decoded live SDK error.',
                'No code interprets token contents, signs in or creates a player/character.'])


if __name__ == '__main__':
    report = replay()
    audit = load('audit-client-release')
    root = load('build-native-entry-code').ROOT
    target = audit.save_snapshot(root / 'code-clues/release-game-sign-in-result', report)
    print(json.dumps(dict(report=str(target), sha256=audit.sha256(target), cases=len(report['cases']), network_requests=0)))
