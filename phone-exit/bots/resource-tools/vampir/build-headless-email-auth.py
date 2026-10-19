"""Index the distinct FEmailAuth family in pinned compiled client code."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('email_auth_config', HERE / 'build-headless-sdk-config.py')
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)
PREFIXES = ('Netmarble::Service::FEmailAuth::', 'Netmarble::Service::FEmailAuthContent::',
            'Netmarble::Service::FEmailAuthCredential::',
            'Netmarble::Service::FNetmarbleIDContent::CheckPossibleToOpen(')


def build():
    prior = json.loads((config.native.ROOT / 'code-clues/headless-auth-index.json').read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('Email auth source changed')
    image = config.native.Image(raw)
    symbols = []
    for match in re.finditer(rb'[ -~]{12,}', raw):
        text = match.group().decode('ascii')
        if '__cdecl' not in text or not any(p in text for p in PREFIXES):
            continue
        address = image.pe.address(match.start())
        literal = config.read_literal(raw, image, address)
        if not literal or literal['text'] != text:
            raise ValueError('Email diagnostic literal boundary mismatch')
        symbols.append(literal)
    targets = {s['address']: s for s in symbols}
    candidates = config.native.rip_candidates(image, targets)
    fragments = config.native.decode_ranges(image, {image.roots[image.containing(a)] for a, _ in candidates if image.containing(a)})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    references, rejected = [], []
    for address, target in candidates:
        row = rows.get(address)
        if not row or row['mnemonic'] != 'lea' or target not in row['rip_references']:
            rejected.append(dict(address=address, target=target))
            continue
        references.append(dict(symbol=targets[target]['text'], instruction=address,
                               root=image.pe.base + image.roots[image.containing(address)][0]))
    constants = []
    for row in rows.values():
        if row['mnemonic'] != 'lea':
            continue
        for address in row['rip_references']:
            literal = config.read_literal(raw, image, address)
            if literal and '__cdecl' not in literal['text'] and not literal['text'].startswith('.?A'):
                constants.append(dict(instruction=row['address'], **literal))
    found = {r['symbol'] for r in references}
    missing = [s['text'] for s in symbols if s['text'] not in found]
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), prefixes=PREFIXES,
        symbols=symbols, references=references, fragments=fragments, constants=constants,
        rejected=rejected, missing=missing, native_execution=False, network_ready=False,
        limitations=['Static source-bound diagnostic/LEA/function graph; no email input, login or HTTP.',
            'FEmailAuth family is distinct from FNetmarbleIDProvider; active provider selection not established.',
            'Names and literal proximity do not establish full credential/callback semantics.'])


if __name__ == '__main__':
    report = build()
    target = config.native.ROOT / 'code-clues/headless-email-auth.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
        symbols=len(report['symbols']), references=len(report['references']),
        roots=len({f['root_begin_rva'] for f in report['fragments']}), missing=report['missing']), indent=2))
