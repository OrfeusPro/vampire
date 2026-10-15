"""Index exact native widget-path literals and verified RIP LEA references.

References are source evidence, not proof of CreateUI execution or popup visibility.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ui_native', HERE / 'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
ROOT = native.ROOT
ALLOWED = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_/.')


def canonical_path(text):
    parts = text.split('.')
    if len(parts) > 2:
        return None
    path = parts[0]
    if not path.startswith('/Game/'):
        if '/' not in path or path.startswith('/'):
            return None
        path = '/Game/RED/UI/' + path
    if not path.startswith('/Game/RED/UI/'):
        return None
    base = path.rsplit('/', 1)[-1]
    if not base.startswith('WBP_') or any(part in ('', '..', '.') for part in path[1:].split('/')):
        return None
    if len(parts) == 2 and parts[1] not in (base, base + '_C'):
        return None
    return path


def literals(data, known_paths):
    def valid(position):
        return (position >= 0 and position + 1 < len(data) and data[position + 1] == 0
                and chr(data[position]) in ALLOWED)
    needle = 'WBP_'.encode('utf-16le')
    position, found = 0, {}
    while True:
        position = data.find(needle, position)
        if position < 0:
            break
        start, end = position, position + len(needle)
        while position - start < 1024 and valid(start - 2):
            start -= 2
        while end - position < 1024 and valid(end):
            end += 2
        if data[end:end + 2] == b'\0\0':
            text = data[start:end].decode('utf-16le')
            path = canonical_path(text)
            if path in known_paths:
                found[start] = dict(file_offset=start, text=text, canonical_path=path,
                    encoding='utf-16le', sha256=hashlib.sha256(data[start:end + 2]).hexdigest())
        position += len(needle)
    return list(found.values())


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    source = json.loads((ROOT / 'code-clues/native-enums.json').read_text(encoding='utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Native executable changed')
    directory = ROOT / 'ui-catalog'
    index_path = directory / 'index.json'
    index = json.loads(index_path.read_text(encoding='utf-8'))
    resources = {}
    for item in index['windows']:
        for path in item['paths']:
            resources.setdefault(path, []).append(item)
    strings = literals(data, resources)
    image = native.Image(data)
    targets = {image.pe.address(row['file_offset']): row for row in strings}
    if None in targets:
        raise ValueError('UI literal outside mapped image')
    candidates = native.rip_candidates(image, targets)
    roots = {image.roots[function] for address, _ in candidates
             if (function := image.containing(address)) is not None}
    groups = {root: [] for root in roots}
    for function in image.ranges:
        if image.roots[function] in groups:
            groups[image.roots[function]].append(function)
    fragments, decode_failures = [], []
    for root, functions in groups.items():
        try:
            fragments.extend(native.decode_ranges(image, {root}, functions=functions))
        except ValueError as error:
            decode_failures.append(dict(root_begin_rva=root[0], ranges=functions, reason=str(error)))
    instructions = {row['address']: (fragment, index, row)
                    for fragment in fragments for index, row in enumerate(fragment['instructions'])}
    references, unresolved = [], []
    for address, target in candidates:
        match = instructions.get(address)
        if match is None:
            unresolved.append(dict(address=address, literal=targets[target], reason='no_decoded_unwind_range'))
            continue
        fragment, index, row = match
        if row['mnemonic'] != 'lea' or target not in row['rip_references']:
            unresolved.append(dict(address=address, literal=targets[target], reason='not_verified_instruction_boundary'))
            continue
        references.append(dict(instruction=row, literal=targets[target],
            root_begin_rva=fragment['root_begin_rva'],
            fragment={k: v for k, v in fragment.items() if k != 'instructions'},
            context=fragment['instructions'][max(0, index - 2):index + 13],
            runtime_binding_verified=False, used_for_bot_input=False))
    linked_paths = {row['literal']['canonical_path'] for row in references}
    resource_proofs = {}
    for path in sorted({row['canonical_path'] for row in strings}):
        variants = []
        for item in resources[path]:
            file = directory / item['file']
            report = json.loads(file.read_text(encoding='utf-8'))
            if path not in report['resource_paths']:
                raise ValueError('Catalog path mismatch')
            variants.append(dict(catalog_file=item['file'], catalog_sha256=hashlib.sha256(file.read_bytes()).hexdigest(),
                name=report['name'], source=report['source'], entry=report['entry'],
                asset_sha256=report['asset_sha256'], body_sha256=report['body_sha256'], popup=report['popup']))
        resource_proofs[path] = variants
    result = dict(source=source['source'], sha256=source['sha256'],
        catalog_sha256=hashlib.sha256(index_path.read_bytes()).hexdigest(), capstone_version=native.capstone.__version__,
        literals=strings, references=references, unresolved_candidates=unresolved, resources=resource_proofs,
        decode_failures=decode_failures,
        paths_without_verified_lea=sorted(set(resources) - linked_paths),
        limitations=['Only exact UTF-16LE WBP paths and RIP-relative LEA, not every reference form.',
                     'Resource paths/contexts do not prove CreateUI invocation, visibility, enabled state or Android parity.',
                     'Source Windows native image and cooked catalog; no game execution or phone commands.'])
    target = ROOT / 'code-clues/native-ui-links.json'
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(literals=len(strings), literal_paths=len(resource_proofs), verified_references=len(references),
        linked_paths=len(linked_paths), linked_popup_paths=sum(any(v['popup'] for v in resource_proofs[path]) for path in linked_paths),
        unresolved=len(unresolved), decode_failures=len(decode_failures), decoded_fragments=len(fragments))))


if __name__ == '__main__':
    main()
