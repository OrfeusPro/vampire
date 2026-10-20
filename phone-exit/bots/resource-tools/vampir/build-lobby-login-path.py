"""Discover verified direct callers of existing lobby bindings; no network IO."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lobby_calls', HERE / 'build-entry-window-code.py')
calls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calls)
native = calls.native
TARGETS = {
    0x145744fa0: 'PktLobbyLogin constructor',
    0x1467a7150: 'Lobby handler registration',
    0x144aaa9c0: 'Lobby success continuation wrapper',
    0x145d39440: 'Game server record lookup',
    0x145d4afe0: 'Server list model update',
    0x1467a9360: 'Lobby Login prepare',
    0x144aa89b0: 'Lobby packet send',
}
SOURCE_SHA = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'


def build():
    upstream_path = native.ROOT / 'code-clues/headless-packet-bindings.json'
    upstream = json.loads(upstream_path.read_text('utf-8'))
    raw = Path(upstream['source']).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SOURCE_SHA or digest != upstream['sha256']:
        raise ValueError('Client changed: refresh lobby bindings before use')
    image = native.Image(raw)
    candidates = []
    for section in image.pe.sections:
        if section['name'] == '.text':
            candidates.extend(calls.direct_call_candidates(raw, section['raw'],
                section['raw_size'], image.pe.address, TARGETS))
    roots = {image.roots[f] for address, _ in candidates
        if (f := image.containing(address)) is not None}
    fragments = native.decode_ranges(image, roots)
    rows = {row['address']: row for fragment in fragments for row in fragment['instructions']}
    verified, rejected = [], []
    for address, target in candidates:
        row = rows.get(address)
        if not calls.checked_call(row, target):
            rejected.append(dict(address=address, target=target))
            continue
        root = image.roots[image.containing(address)][0] + image.pe.base
        verified.append(dict(target_name=TARGETS[target], target=target, root=root, instruction=row))
    literals = []
    seen = set()
    for row in rows.values():
        for address in row['rip_references']:
            if address in seen: continue
            seen.add(address)
            try: offset = image.offset(address - image.pe.base)
            except ValueError: continue
            for encoding, pattern in [('utf-16le', rb'(?:[\x20-\x7e]\x00){5,}'), ('ascii', rb'[\x20-\x7e]{5,}')]:
                match = re.match(pattern, raw[offset:offset + 2048])
                if match:
                    literals.append(dict(address=address, file_offset=offset, encoding=encoding,
                        text=match.group().decode(encoding), referenced_by=row['address']))
                    break
    return dict(schema_version=1, source=upstream['source'], source_sha256=digest,
        upstream_sha256=hashlib.sha256(upstream_path.read_bytes()).hexdigest(),
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        targets=[dict(address=a, name=n) for a, n in TARGETS.items()],
        calls=verified, rejected_candidates=rejected, literals=literals, fragments=fragments,
        limitations=['Verified static direct-call edges, not executed lifecycle.',
            'Analyst labels and referenced text do not establish field semantics.',
            'No game process, credentials, network or server-compatible session.'])


if __name__ == '__main__':
    report = build()
    output = native.ROOT / 'code-clues/lobby-login-path.json'
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(output), sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
        calls=len(report['calls']), roots=len({r['root'] for r in report['calls']}))))
