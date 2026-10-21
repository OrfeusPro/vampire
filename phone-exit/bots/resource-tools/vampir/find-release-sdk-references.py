"""Validate native RIP candidates after the partial Ghidra database lacks xrefs."""
import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    args = parser.parse_args()
    audit = load('sdk_refs_audit', HERE / 'audit-client-release.py')
    native = load('sdk_refs_native', HERE / 'build-native-entry-code.py')
    evidence_sha = audit.sha256(args.evidence)
    evidence = json.loads(args.evidence.read_text('utf-8'))
    sha = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
    if evidence['new_source_sha256'] != sha:
        raise ValueError('Unreviewed SDK source')
    source = native.ROOT / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
    if audit.sha256(source) != sha:
        raise ValueError('SDK source changed')
    raw = source.read_bytes()
    image = native.Image(raw)
    targets = {}
    for item in evidence['literals']:
        address = int(item['address'], 16)
        data = bytes.fromhex(item['bytes'])
        off = image.offset(address - image.pe.base)
        if raw[off:off + len(data)] != data:
            raise ValueError('Ghidra literal bytes changed')
        targets[address] = item
    candidates = native.rip_candidates(image, targets)
    roots = {image.roots[image.containing(a)] for a, target in candidates if image.containing(a)}
    fragments = native.decode_ranges(image, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    references = []
    for address, target in candidates:
        row = rows.get(address)
        if row is None or row['mnemonic'] != 'lea' or row['rip_references'] != [target]:
            continue
        root = image.roots[image.containing(address)]
        references.append(dict(label=targets[target]['label'], literal=hex(target), instruction=hex(address),
            function=hex(image.pe.base + root[0]), bytes=row['bytes'], operands=row['operands']))
    report = dict(schema=1, source=str(source), source_sha256=sha,
        ghidra_evidence=str(args.evidence), ghidra_evidence_sha256=evidence_sha,
        tool_sha256=audit.sha256(Path(__file__)), scanner_sha256=audit.sha256(HERE / 'build-native-entry-code.py'),
        references=references, fragments=fragments, roles_transferred=False,
        limits=['LEA RIP candidates validated on whole unwind-root instruction boundaries.',
                'Ghidra database had no recorded literal references; this does not prove absence of native uses.',
                'No inferred function roles or runtime compatibility; next step is selected Ghidra inspection.'])
    target = audit.save_snapshot(args.evidence.parent.parent.parent / 'sdk-reference-candidates', report)
    print(json.dumps(dict(report=str(target), sha256=audit.sha256(target),
        references=len(references), functions=len({r['function'] for r in references})), indent=2))


if __name__ == '__main__':
    main()
