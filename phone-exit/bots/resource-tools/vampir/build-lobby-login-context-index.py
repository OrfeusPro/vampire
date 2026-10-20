"""Find source-bound lobby getter callers and candidate context writes."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lobby_context_calls', HERE / 'build-entry-window-code.py')
calls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calls)
native = calls.native
TARGETS = {0x144aa8880: 'lobby peer getter', 0x144aab510: 'game server ID setter'}


def build():
    upstream_path = native.ROOT / 'code-clues/lobby-login-path.json'
    upstream = json.loads(upstream_path.read_text('utf-8'))
    raw = Path(upstream['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != upstream['source_sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    candidates = []
    for s in image.pe.sections:
        if s['name'] == '.text':
            candidates.extend(calls.direct_call_candidates(raw, s['raw'], s['raw_size'], image.pe.address, TARGETS))
    roots = {image.roots[f] for a, _ in candidates if (f := image.containing(a)) is not None}
    fragments, failed = [], []
    for root in sorted(roots):
        try: fragments.extend(native.decode_ranges(image, {root}))
        except ValueError: failed.append(dict(root=image.pe.base + root[0], reason='not fully linear-decoded'))
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    edges = [dict(root=image.pe.base + image.roots[image.containing(a)][0], target=t,
        target_name=TARGETS[t], instruction=rows[a]) for a, t in candidates if calls.checked_call(rows.get(a), t)]
    context_writes = [dict(root=image.pe.base + f['root_begin_rva'], instruction=r)
        for f in fragments for r in f['instructions'] if r['mnemonic'].startswith('mov') and
        any(v in r['operands'].split(',')[0] for v in ('+ 0x64]', '+ 0x270]'))]
    return dict(schema_version=1, source=upstream['source'], source_sha256=upstream['source_sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        upstream_sha256=hashlib.sha256(upstream_path.read_bytes()).hexdigest(),
        calls=edges, candidate_writes=context_writes, failed_roots=failed, fragments=fragments,
        limitations=['Call boundaries are verified against decoded PE unwind ranges.',
            'Candidate field writes are not classified by object identity; inspect Ghidra/dataflow before interpretation.',
            'Failed linear decodes are explicit gaps, not negative evidence. No runtime/account/network IO.'])


if __name__ == '__main__':
    report = build()
    out = native.ROOT / 'code-clues/lobby-login-context-index.json'
    out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(out), sha256=hashlib.sha256(out.read_bytes()).hexdigest(),
        calls=len(report['calls']), writes=[dict(root=hex(r['root']), address=hex(r['instruction']['address']),
        operands=r['instruction']['operands']) for r in report['candidate_writes']], failed=report['failed_roots'])))
