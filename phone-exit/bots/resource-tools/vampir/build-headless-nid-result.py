"""Bind NID result routing and query globals to compiled-client initializers."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('nid_native_result', HERE / 'build-headless-sdk-config.py')
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)


def build():
    prior = json.loads((config.native.ROOT / 'code-clues/headless-auth-index.json').read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('Native result source changed')
    image = config.native.Image(raw)
    roots = {image.roots[image.containing(a)] for a in (0x1450ed4f0, 0x1450ee6b0)}
    fragments = config.native.decode_ranges(image, roots)
    rows = [r for f in fragments for r in f['instructions']]
    # These are descriptor globals read by the two selected functions, not guessed strings.
    globals_read = {a if a % 16 == 8 else a - 8 for r in rows for a in r['rip_references']
                    if 0x14b5644c8 <= a < 0x14b564600}
    candidates = config.native.rip_candidates(image, globals_read)
    init_roots = {image.roots[image.containing(a)] for a, _ in candidates
                  if image.containing(a) and image.roots[image.containing(a)] not in roots}
    initializers = config.native.decode_ranges(image, init_roots)
    bindings = []
    for fragment in initializers:
        instructions = fragment['instructions']
        for n, row in enumerate(instructions):
            if row['mnemonic'] != 'lea' or not row['operands'].startswith('rcx,'):
                continue
            targets = set(row['rip_references']) & globals_read
            if not targets or n == 0 or n + 1 >= len(instructions):
                continue
            previous, following = instructions[n - 1], instructions[n + 1]
            if (previous['mnemonic'] != 'lea' or not previous['operands'].startswith('rdx,')
                    or following['direct_target'] != 0x141421150 or following['mnemonic'] != 'call'):
                continue
            literals = [config.read_literal(raw, image, a) for a in previous['rip_references']]
            literals = [v for v in literals if v]
            if len(literals) != 1 or len(targets) != 1:
                raise ValueError('Result initializer binding ambiguous')
            bindings.append(dict(global_address=next(iter(targets)), source=literals[0],
                source_instruction=previous['address'], destination_instruction=row['address'],
                constructor_call=following['address'], root=fragment['root_begin_rva'] + image.pe.base))
    if {r['global_address'] for r in bindings} != globals_read:
        raise ValueError('Result descriptor initializer coverage incomplete')
    diagnostics = []
    for row in rows:
        if row['mnemonic'] == 'lea':
            for a in row['rip_references']:
                literal = config.read_literal(raw, image, a)
                if literal and 'FNetmarbleIDContent::' in literal['text']:
                    diagnostics.append(dict(instruction=row['address'], **literal))
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        fragments=fragments, initializers=initializers, bindings=bindings, diagnostics=diagnostics,
        native_execution=False, network_ready=False, limitations=[
            'Static instruction-boundary verified global initializer/caller graph only.',
            'FString constructor arguments observed, constructor/runtime state not executed.',
            'OnResult validations/token adoption/callbacks and active context remain unproven.'])


if __name__ == '__main__':
    report = build()
    path = config.native.ROOT / 'code-clues/headless-nid-result.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        bindings=len(report['bindings'])), indent=2))
