"""Find caller candidates for remaining Login context; no semantic inference."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('login_context_calls', HERE / 'build-entry-window-code.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
TARGETS = {0x145564550, 0x144aaa530}


def build():
    evidence = json.loads((base.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
    raw = Path(evidence['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != evidence['source_sha256']: raise ValueError('Client changed')
    image = base.native.Image(raw)
    candidates = []
    for section in image.pe.sections:
        if section['name'] != '.text': continue
        candidates += base.direct_call_candidates(raw, section['raw'], section['raw_size'],
            lambda offset: image.pe.base + section['rva'] + offset - section['raw'], TARGETS)
    roots = {image.roots[entry] for address, _ in candidates if (entry := image.containing(address)) is not None}
    fragments = base.native.decode_ranges(image, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    calls = [dict(instruction=rows[a], target=hex(t), root=hex(image.pe.base + image.roots[image.containing(a)][0]))
        for a, t in candidates if base.checked_call(rows.get(a), t)]
    active_roots = {r['root'] for r in calls}
    stores = [dict(root=hex(image.pe.base + f['root_begin_rva']), instruction=r)
        for f in fragments if hex(image.pe.base + f['root_begin_rva']) in active_roots
        for r in f['instructions'] if r['mnemonic'] == 'mov' and
        r['operands'].startswith('byte ptr [') and ' + 0x18],' in r['operands']]
    # An address window is a search boundary, not proof of a class layout.
    nearby, skipped = [], []
    for root in sorted({r for r in image.roots.values() if 0x5556000 <= r[0] < 0x5572000}):
        try: decoded = base.native.decode_ranges(image, {root})
        except ValueError:
            skipped.append(hex(image.pe.base + root[0]))
            continue
        for fragment in decoded:
            for row in fragment['instructions']:
                if (' + 0x18]' in row['operands'] and 'rsp' not in row['operands'] and
                        'byte ptr' in row['operands']):
                    nearby.append(dict(root=hex(image.pe.base + root[0]), instruction=row))
    return dict(source=evidence['source'], source_sha256=evidence['source_sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        helper_sha256=hashlib.sha256((HERE / 'build-entry-window-code.py').read_bytes()).hexdigest(),
        calls=calls, candidate_byte18_stores=stores, fragments=fragments,
        nearby_search_range=['0x145556000', '0x145572000'], nearby_byte18_candidates=nearby,
        nearby_undecoded_roots=skipped,
        limitations=['Direct-call candidates decoded from enclosing unwind roots.',
            'Byte +18 stores may target unrelated objects; no alias proof or field semantics.',
            'Nearby address window is not a class boundary; undecoded roots remain unknown.',
            'Not exhaustive indirect/tail calls or policy initialization; inspect Ghidra before interpretation.'])


if __name__ == '__main__':
    report = build()
    path = base.ROOT / 'code-clues/login-context-candidates.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        calls=len(report['calls']), candidate_stores=report['candidate_byte18_stores'],
        base_constructor_callers=[r['root'] for r in report['calls'] if r['target'] == '0x144aaa530'])))
