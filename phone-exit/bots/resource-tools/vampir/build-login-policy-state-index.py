"""Source-bound singleton state references; candidates are not exhaustive writes."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('login_policy_index_base', HERE / 'build-game-login-input-index.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
TARGETS = {0x14b573398, 0x14b57f360, 0x14b520cb8}


def build():
    prior_path = base.native.ROOT / 'code-clues/login-policy-inputs-replay.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['source_sha256']: raise ValueError('Client changed')
    image = base.native.Image(raw)
    candidates = base.native.rip_candidates(image, TARGETS) + base.memory_candidates(image, TARGETS)
    roots = {image.roots[entry] for address, _ in candidates if (entry := image.containing(address)) is not None}
    fragments = base.native.decode_ranges(image, roots)
    refs = [dict(target=hex(target), root=hex(image.pe.base + fragment['root_begin_rva']), instruction=row)
        for fragment in fragments for row in fragment['instructions'] for target in row['rip_references'] if target in TARGETS]
    return dict(source=prior['source'], source_sha256=prior['source_sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        upstream_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
        indexer_sha256=hashlib.sha256((HERE / 'build-game-login-input-index.py').read_bytes()).hexdigest(),
        references=refs, fragments=fragments,
        limitations=['Common RIP memory encoding candidates decoded from enclosing unwind roots.',
            'Reviewed leaf getters are in the upstream replay; this index requires unwind roots.',
            'Not exhaustive xrefs, write analysis or observed singleton state.'])


if __name__ == '__main__':
    report = build()
    path = base.native.ROOT / 'code-clues/login-policy-state-index.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        references=len(report['references']), roots=sorted({r['root'] for r in report['references']}))))
