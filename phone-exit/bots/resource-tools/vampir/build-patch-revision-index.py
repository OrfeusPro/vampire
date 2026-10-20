"""Find candidate revision-field references near reviewed patch backends.

The address window is a search scope, not a proven class boundary. No game IO.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('patch_revision_native', HERE / 'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
WINDOW = (0x144a90000, 0x144aa4000)


def build():
    manifest_path = native.ROOT / 'ghidra/entry-manifest.json'
    manifest = json.loads(manifest_path.read_text('utf-8'))
    raw = Path(manifest['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest['source_sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    roots = sorted({root for root in image.roots.values() if WINDOW[0] <= image.pe.base + root[0] < WINDOW[1]})
    candidates, fragments, failed = [], [], []
    for root in roots:
        try: decoded = native.decode_ranges(image, {root})
        except ValueError:
            failed.append(hex(image.pe.base + root[0])); continue
        hits = [dict(root=hex(image.pe.base + root[0]), instruction=r)
                for f in decoded for r in f['instructions'] if '+ 0x1b0]' in r['operands']]
        if hits:
            candidates.extend(hits)
            fragments.extend(decoded)
    return dict(source=manifest['source'], source_sha256=manifest['source_sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                search_window=[hex(a) for a in WINDOW], roots_considered=len(roots),
                candidates=candidates, fragments=fragments, failed_roots=failed,
                limitations=['Bounded method-neighborhood search, not exhaustive field xrefs or object dataflow.',
                             'Field displacement alone does not prove object identity or revision semantics.',
                             'Decode failures are explicit gaps; candidates require Ghidra review before use.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/patch-revision-index.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                         roots=report['roots_considered'], failed=report['failed_roots'],
                         candidates=[dict(root=r['root'], address=hex(r['instruction']['address']),
                                          operands=r['instruction']['operands']) for r in report['candidates']])))
