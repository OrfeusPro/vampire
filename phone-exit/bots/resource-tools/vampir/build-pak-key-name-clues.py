"""Preserve verified compiled EncryptionKey name xrefs; no key-value inference."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def build():
    spec = importlib.util.spec_from_file_location('pak_key_flow', HERE / 'build-headless-cdn-json-flow.py')
    flow = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(flow)
    config = flow.body.head.headers.uri.http.preparation.url.settings.config
    native = config.native
    prior_path = native.ROOT / 'code-clues/headless-cdn-json-flow.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('EXE no longer matches key-name research source')
    image = native.Image(raw)
    literal = config.read_literal(raw, image, 0x1491b7690)
    if literal['text'] != 'EncryptionKey':
        raise ValueError('Compiled name anchor changed')
    candidates = native.rip_candidates(image, {literal['address']})
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a, _ in candidates if image.containing(a)})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    references = []
    for address, target in candidates:
        row = rows.get(address)
        if row and row['mnemonic'] == 'lea' and target in row['rip_references']:
            references.append(dict(instruction=address, target=target,
                                   root_begin_rva=image.roots[image.containing(address)][0]))
    contexts = []
    for fragment in fragments:
        for row in fragment['instructions']:
            if row['mnemonic'] != 'lea':
                continue
            for target in row['rip_references']:
                text = config.read_literal(raw, image, target)
                if text:
                    contexts.append(dict(instruction=row['address'], root_begin_rva=fragment['root_begin_rva'], **text))
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                literal=literal, references=references, context_literals=contexts, fragments=fragments,
                key_recovered=False, network_ready=False,
                limitations=['LEA instruction boundaries and literal bytes verified; name coincidence does not prove PAK-key binding.',
                    'Roots contain AssetRegistry or EOSSDK.Platform/artifact context strings; exact runtime semantics are not executed.',
                    'No key values, account configuration, game process/memory or network used; game code is disassembled only.'])


if __name__ == '__main__':
    report = build()
    path = Path('F:/PhoneExit Resources/Vampir/code-clues/pak-key-name-clues.json')
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                          verified_references=len(report['references']), key_recovered=False), indent=2))
