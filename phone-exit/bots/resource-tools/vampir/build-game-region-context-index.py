"""Find verified literal/getter references for game region context."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

calls = module('region_calls', 'build-entry-window-code.py')
inputs = module('region_inputs', 'build-game-login-input-index.py')
native = calls.native


def build():
    manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
    raw = Path(manifest['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest['source_sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    literals = []
    for text in ('UseRegion', 'UseNetmarbleJoinedCountry', 'gameRegion'):
        for encoding in ('ascii', 'utf-16le'):
            data = (text + '\0').encode(encoding)
            for section in image.pe.sections:
                if section['name'] not in ('.rdata', '.data'): continue
                start, end = section['raw'], section['raw'] + section['raw_size']
                cursor = start
                while (offset := raw.find(data, cursor, end)) != -1:
                    cursor = offset + len(data)
                    literals.append(dict(text=text, encoding=encoding, address=image.pe.address(offset),
                        file_offset=offset, bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest()))
    targets = {r['address'] for r in literals}
    refs = native.rip_candidates(image, targets) + inputs.memory_candidates(image, targets)
    getter = 0x144aaa9d0
    direct = []
    for s in image.pe.sections:
        if s['name'] == '.text':
            direct += calls.direct_call_candidates(raw, s['raw'], s['raw_size'], image.pe.address, {getter})
    roots = {image.roots[entry] for address, _ in refs + direct if (entry := image.containing(address)) is not None}
    fragments, failed = [], []
    for root in sorted(roots):
        try: fragments += native.decode_ranges(image, {root})
        except ValueError: failed.append(hex(image.pe.base + root[0]))
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    references = [dict(root=hex(image.pe.base + f['root_begin_rva']), instruction=r, target=hex(t))
        for f in fragments for r in f['instructions'] for t in r['rip_references'] if t in targets]
    getter_calls = [dict(root=hex(image.pe.base + image.roots[image.containing(a)][0]), instruction=rows[a])
        for a, t in direct if calls.checked_call(rows.get(a), t)]
    candidates = [dict(root=hex(image.pe.base + f['root_begin_rva']), instruction=r)
        for f in fragments for r in f['instructions'] if ' + 0x100]' in r['operands']]
    return dict(source=manifest['source'], source_sha256=manifest['source_sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), literals=literals,
        references=references, getter_calls=getter_calls, candidate_field100=candidates,
        failed_roots=failed, fragments=fragments,
        limitations=['Exact source literals and instruction-boundary verified direct/RIP references.',
            'Common memory encoding prefilter and direct calls only; failed decodes remain gaps.',
            'Offset100 candidates are not object identity or field semantics; inspect Ghidra.',
            'No game launch, profile/credentials, process memory or network.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/game-region-context-index.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        literal_roots=sorted({r['root'] for r in report['references']}),
        field100_roots=sorted({r['root'] for r in report['candidate_field100']}),
        getter_calls=len(report['getter_calls']), failed_roots=report['failed_roots'])))
