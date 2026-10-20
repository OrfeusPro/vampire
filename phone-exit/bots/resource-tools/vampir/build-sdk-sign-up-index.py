"""Locate SDK first-player registration using the existing diagnostic indexer."""
import hashlib
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')


def build():
    path = HERE / 'build-headless-auth-index.py'
    spec = importlib.util.spec_from_file_location('sdk_signup_auth_index', path)
    auth = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(auth)
    selectors = ['Netmarble::Service::FAuthImpl::SignUp(',
                 'Netmarble::Service::FAuthImpl::ExecSignUp(']
    native = auth.native
    meta = json.loads((ROOT / 'code-clues/headless-network-index.json').read_text('utf-8'))
    raw = Path(meta['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != meta['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    symbols = []
    for match in re.finditer(rb'[ -~]{8,}', raw):
        name = match.group().decode('ascii')
        selected = [s for s in selectors if s in name]
        if not selected: continue
        address = image.pe.address(match.start())
        if address is None: continue
        if raw[match.end()] != 0: raise ValueError('Unterminated SDK diagnostic')
        symbols.append(dict(name=name, selectors=selected, address=address, file_offset=match.start(),
                            sha256=hashlib.sha256(match.group() + b'\0').hexdigest()))
    targets = {x['address']: x for x in symbols}
    candidates = native.rip_candidates(image, targets)
    roots = {image.roots[f] for address, _ in candidates if (f := image.containing(address)) is not None}
    fragments = native.decode_ranges(image, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    xrefs = []
    for address, target in candidates:
        row = rows.get(address)
        if row is None or row['mnemonic'] != 'lea' or target not in row['rip_references']:
            raise ValueError('Diagnostic reference did not match instruction boundary')
        xrefs.append(dict(symbol=targets[target]['name'], instruction=row,
                          root=image.pe.base + image.roots[image.containing(address)][0]))
    present = {s for x in symbols for s in x['selectors']}
    result = dict(schema_version=1, source=meta['source'], sha256=meta['sha256'], selectors=selectors,
                  symbols=symbols, xrefs=xrefs, fragments=fragments,
                  missing=[s for s in selectors if s not in present])
    result['indexer_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    result['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result['scope'] = 'Static SDK SignUp diagnostic references; not a verified request or live registration.'
    return result


if __name__ == '__main__':
    result = build()
    path = ROOT / 'code-clues/sdk-sign-up-index.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        missing=result['missing'], roots=sorted(set(hex(x['root']) for x in result['xrefs'])))))
