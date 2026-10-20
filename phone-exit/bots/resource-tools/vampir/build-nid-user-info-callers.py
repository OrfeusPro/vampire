"""Verified callers of the reviewed SDK UserInfo pointer-chain getters."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('nid_user_info_calls', HERE / 'build-entry-window-code.py')
calls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calls)
native = calls.native
TARGETS = {0x144521e80: 'UserInfo getter', 0x144524800: 'UserInfo settings wrapper'}


def build():
    manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
    raw = Path(manifest['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest['source_sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    candidates = []
    for section in image.pe.sections:
        if section['name'] == '.text':
            candidates.extend(calls.direct_call_candidates(raw, section['raw'], section['raw_size'], image.pe.address, TARGETS))
    roots = {image.roots[entry] for a, _ in candidates if (entry := image.containing(a)) is not None}
    fragments, failed = [], []
    for root in sorted(roots):
        try: fragments.extend(native.decode_ranges(image, {root}))
        except ValueError: failed.append(hex(image.pe.base + root[0]))
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    edges = [dict(target=hex(target), role=TARGETS[target],
                  root=hex(image.pe.base + image.roots[image.containing(address)][0]), instruction=rows[address])
             for address, target in candidates if calls.checked_call(rows.get(address), target)]
    return dict(source=manifest['source'], source_sha256=manifest['source_sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                calls=edges, fragments=fragments, failed_roots=failed,
                limitations=['Verified E8 call boundaries only; indirect/tail callers not covered.',
                             'Caller identity does not prove UserInfo field writes or initializer semantics.',
                             'No game execution, process memory, account or network.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/nid-user-info-callers.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                         calls=len(report['calls']), roots=sorted({r['root'] for r in report['calls']}),
                         failed=report['failed_roots'])))
