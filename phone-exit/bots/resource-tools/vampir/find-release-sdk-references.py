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
    parser.add_argument('--follow-client-id-globals', action='store_true', help='Find consumers of constructor destinations, without inferring their role')
    parser.add_argument('--global-address', action='append', default=[], help='Follow a global explicitly referenced in the supplied Ghidra instructions')
    parser.add_argument('--direct-target', action='append', default=[], help='Inspect an explicit CALL/JMP target from the supplied Ghidra instructions')
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
    for item in evidence.get('literals', []):
        address = int(item['address'], 16)
        data = bytes.fromhex(item['bytes'])
        off = image.offset(address - image.pe.base)
        if raw[off:off + len(data)] != data:
            raise ValueError('Ghidra literal bytes changed')
        targets[address] = item
    # Comparison exports contain both releases: follow only the reviewed new side.
    functions = list(evidence.get('functions', [])) + [pair['new'] for pair in evidence.get('pairs', [])]
    instructions = []
    for function in functions:
        for original in function.get('instructions', []):
            row = dict(original, references=original.get('references', original.get('flows', [])))
            data = bytes.fromhex(row['bytes'])
            off = image.offset(int(row['address'], 16) - image.pe.base)
            if raw[off:off + len(data)] != data:
                raise ValueError('Ghidra instruction bytes differ from current source')
            instructions.append(row)
    known_references = {int(ref, 16) for row in instructions for ref in row.get('references', [])}
    for value in args.global_address:
        address = int(value, 16)
        if address not in known_references:
            raise ValueError('Global absent from supplied Ghidra references')
        targets[address] = dict(label='GlobalAddress')
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
    direct_rows = []
    for value in args.direct_target:
        address = int(value, 16)
        callers = [row for row in instructions if row['text'].startswith(('CALL ', 'JMP '))
                   and address in [int(ref, 16) for ref in row.get('references', [])]]
        if not callers:
            raise ValueError('Target absent from supplied Ghidra CALL/JMP references')
        references.append(dict(label='GhidraDirectTarget', function=hex(address),
            callsites=[row['address'] for row in callers]))
        direct_rows.extend(callers)
    initializers = []
    if args.follow_client_id_globals:
        for reference in list(references):
            if reference['label'] != 'ClientId':
                continue
            start = int(reference['function'], 16)
            body = [r for f in fragments if f['root_begin_rva'] + image.pe.base == start for r in f['instructions']]
            if len(body) != 7 or body[1]['address'] != int(reference['instruction'], 16):
                continue
            destination = body[2]
            if destination['mnemonic'] != 'lea' or not destination['operands'].startswith('rcx,') or len(destination['rip_references']) != 1:
                continue
            initializers.append(dict(function=hex(start), global_address=hex(destination['rip_references'][0]),
                                     source_literal=reference['literal']))
        globals_set = {int(r['global_address'], 16) for r in initializers}
        uses = native.rip_candidates(image, globals_set)
        use_roots = {image.roots[image.containing(a)] for a, target in uses if image.containing(a)}
        extra = native.decode_ranges(image, use_roots - roots)
        fragments.extend(extra)
        rows.update({r['address']: r for f in extra for r in f['instructions']})
        for address, target in uses:
            row = rows.get(address)
            if row is None or row['mnemonic'] != 'lea' or row['rip_references'] != [target]:
                continue
            root = image.roots[image.containing(address)]
            references.append(dict(label='ClientIdGlobalUse', global_address=hex(target), instruction=hex(address),
                function=hex(image.pe.base + root[0]), bytes=row['bytes'], operands=row['operands']))
    report = dict(schema=1, source=str(source), source_sha256=sha,
        ghidra_evidence=str(args.evidence), ghidra_evidence_sha256=evidence_sha,
        tool_sha256=audit.sha256(Path(__file__)), scanner_sha256=audit.sha256(HERE / 'build-native-entry-code.py'),
        references=references, client_id_initializer_candidates=initializers, fragments=fragments,
        ghidra_direct_target_instructions=direct_rows, roles_transferred=False,
        limits=['LEA RIP candidates validated on whole unwind-root instruction boundaries.',
                'Ghidra database had no recorded literal references; this does not prove absence of native uses.',
                'No inferred function roles or runtime compatibility; next step is selected Ghidra inspection.'])
    target = audit.save_snapshot(args.evidence.parent.parent.parent / 'sdk-reference-candidates', report)
    print(json.dumps(dict(report=str(target), sha256=audit.sha256(target),
        references=len(references), functions=len({r['function'] for r in references})), indent=2))


if __name__ == '__main__':
    main()
