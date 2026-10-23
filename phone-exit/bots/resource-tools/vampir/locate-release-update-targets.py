"""Find bounded native candidates from reviewed literal anchors; never port roles."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent


def load_native():
    spec = importlib.util.spec_from_file_location('update_target_native', HERE / 'build-native-entry-code.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if module.capstone.__version__ != '5.0.6':
        raise ValueError('Pinned Capstone required')
    return module


def locate(raw, anchors, native):
    image = native.Image(raw)
    targets, literals = {}, {}
    for anchor in anchors:
        data = (anchor['text'] + '\0').encode(anchor['encoding'])
        positions, cursor = [], 0
        while True:
            offset = raw.find(data, cursor)
            if offset < 0: break
            if len(positions) >= 16: raise ValueError('Literal match budget exceeded')
            cursor = offset + 1
            address = image.pe.address(offset)
            positions.append(address)
            targets.setdefault(address, []).append(anchor['id'])
        literals[anchor['id']] = positions
    refs = native.rip_candidates(image, targets)
    roots = {}
    for address, target in refs:
        containing = image.containing(address)
        if containing is not None:
            root = image.roots[containing]
            roots.setdefault(root, []).append((address, target))
    if len(roots) > 32: raise ValueError('Explicit anchor roots exceed budget')
    decoded, gaps = {}, []
    for root in sorted(roots):
        try:
            fragments = native.decode_ranges(image, {root})
        except ValueError as error:
            gaps.append(dict(root=hex(image.pe.base + root[0]), reason=str(error)))
            continue
        decoded[root] = {row['address']: row for f in fragments for row in f['instructions']}
    output = []
    for anchor in anchors:
        candidates, unresolved = {}, []
        for root, pairs in roots.items():
            for address, target in pairs:
                if anchor['id'] not in targets[target]: continue
                row = decoded.get(root, {}).get(address)
                entry = hex(image.pe.base + root[0])
                if row is None or target not in row['rip_references'] or row['mnemonic'] != 'lea':
                    unresolved.append(dict(root=entry, address=hex(address), reason='Instruction boundary not verified'))
                    continue
                candidates.setdefault(entry, []).append(dict(address=hex(address), target=hex(target), bytes=row['bytes']))
        output.append(dict(id=anchor['id'], literals=[hex(a) for a in literals[anchor['id']]],
            state='candidate' if len(candidates) == 1 and not unresolved else 'requires_review',
            candidates=[dict(root=entry, references=rows) for entry, rows in sorted(candidates.items())],
            unresolved=unresolved, required_checks=anchor['required_checks']))
    return output, gaps


def run(*, root, targets_path, source_sha):
    if not re.fullmatch('[0-9a-f]{64}', source_sha): raise ValueError('Full source SHA required')
    definition_bytes = targets_path.read_bytes()
    definition = json.loads(definition_bytes)
    anchors = definition['anchors']
    if definition['schema'] != 1 or not 1 <= len(anchors) <= 16:
        raise ValueError('Unsupported anchor definition')
    if len({a['id'] for a in anchors}) != len(anchors): raise ValueError('Duplicate target IDs')
    for anchor in anchors:
        if (anchor['encoding'] not in ('ascii', 'utf-16le') or not 4 <= len(anchor['text']) <= 1024
                or '\0' in anchor['text'] or not anchor['required_checks']):
            raise ValueError('Invalid reviewed anchor')
    native = load_native()
    sources, outputs, gaps = {}, {}, {}
    for label, sha in (('baseline', definition['baseline_sha256']), ('current', source_sha)):
        if not re.fullmatch('[0-9a-f]{64}', sha): raise ValueError('Invalid baseline SHA')
        source = root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
        raw = source.read_bytes()
        if hashlib.sha256(raw).hexdigest() != sha: raise ValueError('Source snapshot changed')
        sources[label] = dict(path=str(source), sha256=sha)
        outputs[label], gaps[label] = locate(raw, anchors, native)
    for anchor, found in zip(anchors, outputs['baseline']):
        observed_roots = {c['root'] for c in found['candidates']} | {c['root'] for c in found['unresolved']}
        if anchor['baseline_root'] not in observed_roots or anchor['baseline_literal'] not in found['literals']:
            raise ValueError('Reviewed baseline anchor not observed: ' + anchor['id'])
    report = dict(schema=1, sources=sources, targets=str(targets_path.resolve()),
        targets_sha256=hashlib.sha256(definition_bytes).hexdigest(),
        dependencies={name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in
            ('locate-release-update-targets.py', 'build-native-entry-code.py', 'extract-native-enums.py')},
        observations=outputs, gaps=gaps, compatibility='not_established',
        limits=['Only explicit exact literals and RIP LEA references; no call-tree expansion or whole EXE disassembly.',
                'A unique candidate is not a role or protocol proof. Export and port required checks for the new SHA.',
                'Missing/ambiguous/undecodable candidates remain queued. No auth, network, process memory or runtime profile changes.'])
    if targets_path.read_bytes() != definition_bytes: raise ValueError('Targets changed during search')
    for source in sources.values():
        with Path(source['path']).open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != source['sha256']:
                raise ValueError('Source snapshot changed during search')
    spec = importlib.util.spec_from_file_location('target_snapshot_audit', HERE / 'audit-client-release.py')
    audit = importlib.util.module_from_spec(spec); spec.loader.exec_module(audit)
    path = audit.save_snapshot(root / 'code-clues/update-targets', report)
    return dict(report=str(path), source_sha256=source_sha,
        candidates=[dict(id=r['id'], state=r['state'], roots=[c['root'] for c in r['candidates']]) for r in outputs['current']],
        compatibility='not_established')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--targets', type=Path, default=HERE / 'knowledge/release-update-targets.json')
    parser.add_argument('--source-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(run(root=args.root, targets_path=args.targets, source_sha=args.source_sha256)))
