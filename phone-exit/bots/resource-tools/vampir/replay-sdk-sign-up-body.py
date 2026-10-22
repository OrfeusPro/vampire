"""Bounded SDK SignUp body replay; reuse reviewed SignIn JSON/getter fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
SEGMENTS = ((0x1444ff84b, 0x1444ff963), (0x1444ffa86, 0x1444ffb19))


def build(*, source_snapshot=None):
    spec = importlib.util.spec_from_file_location('signup_body_base', HERE / 'replay-sdk-sign-in-body.py')
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)
    sources = {}
    for name, digest in (
        ('sdk-sign-in-body-replay.json', '8d4bb20917faeb90bdc25d2176388d99587f4c1d3ad2c4e3a22c5d391e5ec2d7'),
        ('sdk-sign-up-index.json', 'b7f40d41d1d21994d5a3a1f2cc0b44f717a7c75b9fa7da712787b34d26d6c4f7')):
        path = ROOT / 'code-clues' / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest: raise ValueError('SDK source evidence changed')
        sources[name] = json.loads(path.read_text('utf-8'))
    prior, signup = sources.values()
    source = Path(source_snapshot) if source_snapshot is not None else Path(prior['source'])
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256'] or signup['sha256'] != prior['sha256']:
        raise ValueError('Installed client changed')
    image = base.config.native.Image(raw)
    fragments = prior['fragments'] + signup['fragments']
    initializers = {f['root_begin_rva'] for f in prior['fragments'] if f['root_begin_rva'] < 0x2000000}
    base.SEGMENTS = SEGMENTS
    cases = []
    for country, platform in (('UA', 'PC'), ('KR', 'pc')):
        for credential in (None, dict(channelCode=33, channelAccessToken='provider-token-fixture')):
            fixture = dict(nmDeviceKey='nm-fixture', deviceKey='device-fixture', countryCode=country,
                           os=platform, credential=credential)
            replay = base.Replay(raw, image, fragments, prior['constructor_leaf'], initializers)
            replay.fixture = fixture
            for rva in sorted(initializers): replay.function(rva + image.pe.base)
            pair, obj, table = replay.base + 0x5100, replay.base + 0x5200, replay.base + 0x5300
            replay.uc.mem_write(pair, struct.pack('<QQ', obj if credential else 0, 0))
            replay.uc.mem_write(obj, struct.pack('<Q', table))
            replay.uc.mem_write(table + 8, struct.pack('<Q', 0x1450e50d0))
            for start, end in SEGMENTS:
                for name, value in dict(rsp=replay.stack, rbp=replay.rbp, r14=pair, rsi=0,
                                        r12=0, rbx=0xffffffff).items():
                    replay.uc.reg_write(getattr(replay.x, 'UC_X86_REG_' + name.upper()), value)
                replay.uc.emu_start(start, end, count=8192)
                if replay.uc.reg_read(replay.x.UC_X86_REG_RIP) != end: raise ValueError('SignUp replay budget exceeded')
            expected = {k: v for k, v in fixture.items() if k != 'credential'}
            if credential: expected['credential'] = credential
            if replay.body != expected: raise ValueError('SignUp body differs from observed fields')
            cases.append(dict(fixture=fixture, body=replay.body, events=replay.events))
    literals = [base.config.read_literal(raw, image, a) for a in (0x1494d7e90, 0x1494d7e98)]
    if [x['text'] for x in literals] != ['authUrl', 'v1/sign-up']: raise ValueError('SignUp endpoint literals changed')
    return dict(schema_version=1, source=str(source), sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        base_tool_sha256=hashlib.sha256((HERE / 'replay-sdk-sign-in-body.py').read_bytes()).hexdigest(),
        segments=[dict(start=hex(a), end_exclusive=hex(b)) for a, b in SEGMENTS],
        fragments=signup['fragments'], literals=literals, cases=cases, network_ready=False,
        limitations=['Only SignUp body slices and existing compiled key initializers executed.',
                    'Settings/device getters, credential GetObject, JSON values/map, memory helpers are fixtures/captures.',
                    'Endpoint lookup/append/POST and SignUp response remain static, not executed here.',
                    'No live SignUp, player creation or game session.'])


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-snapshot', type=Path)
    args = parser.parse_args()
    result = build(source_snapshot=args.source_snapshot)
    payload = (json.dumps(result, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    if args.source_snapshot is not None:
        path = ROOT / 'code-clues/sdk-sign-up-body-replays' / hashlib.sha256(payload).hexdigest() / 'manifest.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.read_bytes() != payload:
            raise ValueError('Immutable replay result changed')
    else:
        path = ROOT / 'code-clues/sdk-sign-up-body-replay.json'
    path.write_bytes(payload)
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(result['cases']))))
