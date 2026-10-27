"""Whole sign-in callback field traversal with explicit JSON/persistence boundaries."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHA = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
CTOR = '33d248c7416802000000488d055fd4060548895108488901488d0559d4060548894120488d0566d4060548894128488d053bcf060548894130488d0510cf060548894138488d0555d4060548894140488d0562d4060548894148488d05efa2060548894150488bc148895110488951184889515848895160488951704889517848c781800000000200000048899188000000899190000000488991980000008991a0000000488991a80000008991b0000000488991b80000008991c0000000488991c80000008991d0000000488991d80000008991e0000000488991e80000008991f0000000488991f800000089910001000048899108010000899110010000488991180100008991200100004889912801000089913001000048899138010000899140010000488991480100008991500100004889915801000089916001000048899168010000899170010000488991780100008991800100004889918801000089919001000048899198010000488991a0010000488991a8010000488991b0010000488991b8010000488991c0010000c3'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def run():
    h = load('native-request-harness-11316').make_harness({
        'run-e3abc26162e7': '0c9394ae43e34f37e6bf092b6788883dee745525de939b4f67c2544703c24d42',
        'run-7ecda68a9805': '2b6c4eb8f049945e94e9ba4987f3bd4b0c45313c277db66113c59b375928f6c8'},
        {0x1444d3a30, 0x1444c2010, 0x144552560},
        leaves={0x1444c2f20: CTOR}, source_sha256=SHA, copy_thunk=None)
    native = load('build-native-entry-code'); shapes = load('audit-launcher-shape-11318')
    coverage = {f['address']: len(shapes.normalize_function(native, h.image, f)['shape']) for f in h.fragments}
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    constructor = list(decoder.disasm(bytes.fromhex(CTOR), 0x1444c2f20))
    if constructor[-1].mnemonic != 'ret' or any(i.mnemonic.startswith(('j', 'call', 'ret')) for i in constructor[:-1]):
        raise ValueError('Constructor is not the reviewed straight-line leaf')
    uc, x, b = h.uc, h.x, h.scratch
    owner, closure, weak, pair, response, sdk, manager, settings = [b+n for n in
        (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000)]
    objects, strings, events = {}, {}, []
    arena = [b+0x10000]

    def reg(name): return uc.reg_read(getattr(x, 'UC_X86_REG_'+name))
    def get(at, size=8): return int.from_bytes(uc.mem_read(at, size), 'little')
    def put(at, value, size=8): uc.mem_write(at, value.to_bytes(size, 'little'))
    def wide(at):
        data = bytearray()
        for offset in range(0, 2048, 2):
            unit = bytes(uc.mem_read(at+offset, 2))
            if unit == b'\0\0': return data.decode('utf-16le')
            data.extend(unit)
        raise ValueError('Identity string fixture exceeds bound')
    def text(at): return wide(get(at)) if get(at+8, 4) else ''
    def string(at, value):
        data = (value+'\0').encode('utf-16le'); target = arena[0]
        if target+len(data) >= b+0x28000: raise ValueError('Identity fixture arena exhausted')
        arena[0] += (len(data)+15)&~15
        uc.mem_write(target, data); put(at, target); put(at+8, len(data)//2, 4); put(at+12, len(data)//2, 4)
        strings[target] = value
    def noop(machine): h.finish()
    def empty(machine): uc.mem_write(reg('RDX'), bytes(16)); h.finish(reg('RDX'))
    def literal(machine): string(reg('RCX'), wide(reg('RDX'))); h.finish(reg('RCX'))
    def body_string(machine): uc.mem_write(reg('RCX'), bytes(16)); h.finish(reg('RCX'))
    def init_json(machine): objects[reg('RCX')] = current['body']; h.finish(reg('RCX'))
    def key(at):
        # The two global FStrings are fixtures, checked against native references
        # below; all auth member keys come from the executed native constructor.
        if at == 0x14b563df0: return 'resultData'
        if at == 0x14b563c60: return 'accessToken'
        if at == 0x14b563da0: return 'errorCode'
        return text(at)
    def has(machine):
        value = key(reg('RDX')); events.append(('has', value))
        h.finish(int(value in objects.get(reg('RCX'), {})))
    def object_value(machine):
        value = objects[reg('RCX')].get(key(reg('R8')))
        if not isinstance(value, dict): raise ValueError('Expected object fixture')
        objects[reg('RDX')] = value; h.finish(reg('RDX'))
    def string_value(machine):
        value = objects[reg('RCX')].get(key(reg('R8')), '')
        if not isinstance(value, str): raise ValueError('Expected string fixture')
        string(reg('RDX'), value); h.finish(reg('RDX'))
    def assign(machine):
        at, value = reg('RCX'), text(reg('RDX'))
        if at not in (sdk+0x78, sdk+0x68): raise ValueError('Unexpected SDK string destination')
        string(at, value); events.append(('sdk-write', at-sdk, value)); h.finish(at)
    def country_assign(machine):
        if reg('RCX') != sdk+0x210: raise ValueError('Country member offset differs')
        value = text(reg('RDX')); string(reg('RCX'), value)
        events.append(('country-write', value)); h.finish(reg('RCX'))
    def player(machine):
        if reg('RCX') != settings or reg('R8') != 0: raise ValueError('Player setter arguments differ')
        events.append(('player-setter', text(reg('RDX')))); h.finish()
    def save(machine):
        if reg('RCX') != settings: raise ValueError('Save receiver differs')
        events.append(('save',)); h.finish(0)
    def followup(machine):
        if reg('RCX') != sdk: raise ValueError('Load receiver differs')
        events.append(('load',)); h.finish()
    def dispatch(machine):
        if reg('RCX') != owner or reg('RDX') != pair: raise ValueError('Original response handoff differs')
        events.append(('dispatch-original',)); h.finish()
    def free(machine):
        if reg('RCX') not in strings: raise ValueError('Unexpected fixture string release')
        h.finish()
    def status(machine): events.append(('status', objects[reg('RDX')])); h.finish()
    def init_sdk(machine):
        if reg('RCX') != manager: raise ValueError('SDK manager receiver differs')
        put(manager+0x110, sdk); events.append(('sdk-init',)); h.finish()
    fixtures = {
        0x144531be0: lambda machine: h.finish(1), 0x140bd6440: lambda machine: h.finish(response),
        0x1414266a0: body_string, 0x144486840: init_json, 0x14180e560: lambda machine: h.finish(200),
        0x14447f020: lambda machine: h.finish(1), 0x14447dfa0: has, 0x14447d210: object_value,
        0x14447d460: string_value, 0x141426b30: literal, 0x141427760: assign,
        0x14452b920: empty, 0x1444b1730: lambda machine: h.finish(manager), 0x1416b0660: init_sdk,
        0x141441d60: country_assign, 0x1445528f0: player, 0x144543990: save, 0x144532980: followup,
        0x144476600: noop, 0x141483080: free, 0x144543150: noop, 0x144553070: noop,
        0x144538320: lambda machine: h.finish(settings), 0x141445be0: noop,
        0x14452b3a0: lambda machine: h.finish(settings), 0x14452b910: lambda machine: h.finish(settings),
        0x14454f840: noop, 0x14452bc90: lambda machine: h.finish(settings), 0x144541190: noop,
        0x141426950: body_string, 0x1445528e0: noop, 0x1444e6ac0: dispatch,
        0x14452ec60: status, 0x1444f77c0: noop,
    }
    for at, fn in fixtures.items(): h.add_fixture(at, fn)
    put(0x14b5652e0, 0, 1); put(0x14b1880f4, 0, 1); put(0x14b2f214b, 0, 1)
    definitions = [('no-result', {}), ('token-only', {'resultData': {'accessToken': 'sdk-token-fixture'}}),
        ('no-player', {'resultData': {'playerInfo': {}}})]
    for token in (False, True):
        for country in (False, True):
            for region in (False, True):
                for status_present in (False, True):
                    p = {'playerId': 'player-fixture'}
                    if country: p['joinedCountryCode'] = 'HK'
                    if region: p['gameRegion'] = 'JP'
                    if status_present: p['playerStatus'] = {'synthetic': 1}
                    r = {'playerInfo': {'player': p}}
                    if token: r['accessToken'] = 'sdk-token-fixture'
                    definitions.append(('player-fields', {'resultData': r}))
    definitions.append(('empty-fields', {'resultData': {'accessToken': '', 'playerInfo': {'player': {
        'playerId': '', 'joinedCountryCode': '', 'gameRegion': ''}}}}))
    rows = []; keys = None
    for initialize in (False, True):
        for name, body in definitions:
            current = dict(body=body); objects.clear(); strings.clear(); events.clear(); arena[0] = b+0x10000
            for at, size in ((owner, 0x200), (closure, 0x60), (weak, 0x20), (sdk, 0x300), (manager, 0x200)):
                uc.mem_write(at, bytes(size))
            h.call(0x1444c2f20, owner)
            keys = {hex(n): wide(get(owner+n)) for n in range(0x20, 0x58, 8)}
            put(closure, owner); put(closure+8, settings); put(closure+0x10, weak)
            put(closure+0x18, settings); put(closure+0x30, settings); put(weak+8, 2, 4)
            put(pair, response); put(pair+8, 0); put(manager+0x110, 0 if initialize else sdk)
            string(sdk+0x78, 'old-sdk-fixture'); string(sdk+0x68, 'old-region-fixture')
            string(sdk+0x210, 'old-country-fixture')
            uc.reg_write(x.UC_X86_REG_RDX, pair)
            try: h.call(0x1444d3a30, closure, budget=100000)
            except Exception as exception: raise RuntimeError('Identity '+name+' stopped at '+hex(reg('RIP'))) from exception
            r = body.get('resultData', {}); p = r.get('playerInfo', {}).get('player')
            expected_token = r.get('accessToken', 'old-sdk-fixture')
            expected_region = p.get('gameRegion', 'old-region-fixture') if p is not None else 'old-region-fixture'
            expected_country = p.get('joinedCountryCode', 'old-country-fixture') if p is not None else 'old-country-fixture'
            if (text(sdk+0x78), text(sdk+0x68), text(sdk+0x210)) != (expected_token, expected_region, expected_country):
                raise ValueError('Identity values crossed or absent fields overwrote SDK state')
            if get(weak+8, 4) != 2 or events.count(('dispatch-original',)) != 1:
                raise ValueError('Identity lifetime/handoff differs')
            wanted = [('player-setter', p.get('playerId', '')), ('save',), ('load',)] if p is not None else []
            observed = [e for e in events if e[0] in ('player-setter', 'save', 'load')]
            if observed != wanted: raise ValueError('Identity player persistence order differs')
            if events.count(('sdk-init',)) != int(initialize and 'resultData' in body):
                raise ValueError('SDK lazy initialization differs')
            rows.append(dict(name=name, lazy_init=initialize, body=body, sdk_access_token=text(sdk+0x78),
                game_region=text(sdk+0x68), joined_country=text(sdk+0x210), events=events.copy()))
    audit = load('audit-client-release')
    report = dict(source_sha256=SHA, tool_sha256=audit.sha256(Path(__file__)), exports=h.evidence,
        constructor=dict(address='0x1444c2f20', bytes=CTOR, sha256=hashlib.sha256(bytes.fromhex(CTOR)).hexdigest(), keys=keys),
        cases=rows, coverage=coverage, native_execution=True, network_used=False, profile_activation=False,
        limits=['Whole sign-in callback, source-checked straight-line constructor leaf, SDK context getter and country setter execute with diagnostics disabled.',
            'HTTP status/body, JSON parser/presence/getters, global resultData/accessToken key identity and FString operations are fixtures.',
            'Player setter, Save, Load, manager singleton/lazy initializer and post-sign-in events are fixtures; no persistence or fresh SDK state claim.',
            'Country member assignment is captured at SDK+210; its storage helper is not executed. Player status consumers are captures; idpInfo is absent.',
            'Dispatcher is a capture of the original response; actual dispatcher/queue lifetime was checked separately. No real auth or client compatibility claim.'])
    return audit.save_snapshot(h.root/'code-clues/launcher-identity-11318', report), report


if __name__ == '__main__':
    path, report = run(); print(json.dumps(dict(artifact=str(path), cases=len(report['cases']))))
