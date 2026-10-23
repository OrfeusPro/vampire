"""Current result mapper, reached native instructions only; no game/network."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHA = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
EXPORT_SHA = '2932518bc30a1c7c09a79b99d1497e7374d4d3b1f1c7ff8a6741036e0a30fbb8'


def replay():
    spec = importlib.util.spec_from_file_location('release_lobby_mapper', HERE / 'replay-result-error-text.py')
    mapper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mapper)
    mapper.ENTRY, mapper.CONSTRUCT = 0x145810700, 0x141426a30
    source = mapper.native.ROOT / 'client-code-snapshots' / SHA / 'ProjectRED-Win64-Shipping.exe'
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA: raise ValueError('Lobby source SHA changed')
    image = mapper.native.Image(raw)
    folder = mapper.native.ROOT / 'ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details'
    path = folder / 'run-88a1dfed6648/details.json'
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != EXPORT_SHA: raise ValueError('Lobby export SHA changed')
    report = json.loads(payload)
    if report['new_source_sha256'] != SHA: raise ValueError('Lobby export source mismatch')
    function = next(f for f in report['functions'] if f['address'] == '0x145810700')
    if not function['decompilation_completed']: raise ValueError('Incomplete lobby mapper')
    for row in function['instructions']:
        offset = image.offset(int(row['address'], 16) - image.pe.base)
        code = bytes.fromhex(row['bytes'])
        if raw[offset:offset + len(code)] != code: raise ValueError('Lobby mapper instruction changed')
    caller_path = folder / 'run-116ea21f2ddb/details.json'
    caller_payload = caller_path.read_bytes()
    caller_sha = 'eff8ba1fe14ba36d29ca14a96e8278c1e14d93b9b8e181d37042354e9518eb7b'
    if hashlib.sha256(caller_payload).hexdigest() != caller_sha: raise ValueError('Lobby caller export changed')
    caller_report = json.loads(caller_payload)
    if caller_report['new_source_sha256'] != SHA: raise ValueError('Lobby caller source mismatch')
    caller = next(f for f in caller_report['functions'] if f['address'] == '0x145fd5120')
    if not caller['decompilation_completed']: raise ValueError('Incomplete lobby caller')
    for row in caller['instructions']:
        offset = image.offset(int(row['address'], 16) - image.pe.base)
        code = bytes.fromhex(row['bytes'])
        if raw[offset:offset + len(code)] != code: raise ValueError('Lobby caller instruction changed')
    call = next(row for row in caller['instructions'] if row['address'] == '0x145fd51d1')
    if call['bytes'] != 'e82ab583ff' or call['text'] != 'CALL 0x145810700':
        raise ValueError('Lobby fallback call changed')
    cases = [mapper.Replay(raw, image).execute(code) for code in (0, 10036, 10048, 1, 0xffffffff)]
    expected = {0: 'Success', 10036: 'IsInspect', 10048: 'BlockedInfo', 1: '', 0xffffffff: ''}
    if {row['code']: row['key'] for row in cases} != expected: raise ValueError('Current lobby labels differ')
    return dict(source_sha256=SHA, method='bounded_native', entry=hex(mapper.ENTRY),
                evidence=[dict(path=str(path), sha256=EXPORT_SHA), dict(path=str(caller_path), sha256=caller_sha)],
                fallback_caller='0x145fd5120', cases=cases, network_requests=0,
                fixtures=['FString constructor captures reached source ASCII literal'],
                limits=['Reached whole mapper paths only; not all switch values tested',
                        'Caller/table overrides/popup not executed; label does not prove server cause'])


if __name__ == '__main__':
    report = replay()
    payload = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')
    digest = hashlib.sha256(payload).hexdigest()
    output = Path('F:/PhoneExit Resources/Vampir/code-clues/release-lobby-errors') / digest / 'manifest.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and output.read_bytes() != payload: raise ValueError('Lobby report collision')
    output.write_bytes(payload)
    print(json.dumps(dict(report=str(output), sha256=digest, keys={r['code']: r['key'] for r in report['cases']})))
