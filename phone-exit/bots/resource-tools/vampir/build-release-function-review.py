"""Turn Ghidra correlation candidates into an explicit review queue, never new roles."""
import argparse
from collections import Counter, defaultdict
import importlib.util
import json
from pathlib import Path


def review_functions(historical, correlation):
    if historical['source_sha256'] != correlation['old_source_sha256']:
        raise ValueError('Historical source mismatch')
    functions = {f['address'].lower(): f for f in historical['functions']}
    if len(functions) != len(historical['functions']):
        raise ValueError('Duplicate historical address')
    matches = defaultdict(lambda: defaultdict(set))
    unexpected = []
    for group in correlation['passes']:
        for match in group['matches']:
            old, new = match['old_address'].lower(), match['new_address'].lower()
            if old not in functions:
                unexpected.append(dict(old_address=old, new_address=new, correlator=group['correlator']))
                continue
            matches[old][new].add(group['correlator'])
    # Even different source functions can compete for a destination across passes.
    destinations = defaultdict(set)
    for old, candidates in matches.items():
        for new in candidates:
            destinations[new].add(old)
    rows = []
    for old, function in functions.items():
        candidates = matches[old]
        conflict = len(candidates) > 1 or any(len(destinations[new]) > 1 for new in candidates)
        status = ('not_matched' if not candidates else 'conflicting_candidates' if conflict
                  else 'candidate_requires_verification')
        rows.append(dict(old_address=old, old_analyst_name=function['name'], status=status,
                         candidates=[dict(new_address=new, correlators=sorted(kinds),
                                          competing_old_addresses=sorted(destinations[new] - {old}))
                                     for new, kinds in sorted(candidates.items())],
                         next_check=('Locate in new EXE using callers, literals and packet bindings'
                                     if not candidates else
                                     'Verify operands, call targets, data bindings and bounded behavior in new EXE')))
    return dict(old_source_sha256=correlation['old_source_sha256'],
                new_source_sha256=correlation['new_source_sha256'],
                analysis_timed_out=correlation['analysis_timed_out'],
                counts=dict(Counter(row['status'] for row in rows)), functions=rows,
                matches_outside_historical_export=unexpected,
                compatibility='not_established', roles_transferred=False,
                limits=['A unique correlator candidate is not a verified semantic relationship.',
                        'A missing match is not proof of function removal.',
                        'An analysis timeout and incomplete function discovery limit matching coverage.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('comparison_directory', type=Path)
    args = parser.parse_args()
    folder = args.comparison_directory
    spec = importlib.util.spec_from_file_location('review_audit', Path(__file__).with_name('audit-client-release.py'))
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    receipt_path = folder / 'provenance.json'
    receipt = json.loads(receipt_path.read_text('utf-8'))
    candidate_path = folder / 'candidates.json'
    if audit.sha256(candidate_path) != receipt['files']['candidates.json']:
        raise ValueError('Candidate report hash mismatch')
    historical_paths = [Path(p) for p in receipt['inputs'] if Path(p).name == 'functions.json']
    if len(historical_paths) != 1:
        raise ValueError('Ambiguous historical export')
    historical_path = historical_paths[0]
    if audit.sha256(historical_path) != receipt['inputs'][str(historical_path)]:
        raise ValueError('Historical export hash mismatch')
    correlation = json.loads(candidate_path.read_text('utf-8'))
    if (correlation['old_source_sha256'] != receipt['old_source_sha256'] or
            correlation['new_source_sha256'] != receipt['new_source_sha256']):
        raise ValueError('Receipt source mismatch')
    for prefix in ('old', 'new'):
        if audit.sha256(Path(receipt[prefix + '_source'])) != receipt[prefix + '_source_sha256']:
            raise ValueError('Saved EXE hash mismatch')
    result = dict(schema=1, tool_sha256=audit.sha256(Path(__file__)),
                  candidate_report_sha256=audit.sha256(candidate_path),
                  provenance_sha256=audit.sha256(receipt_path),
                  historical_export_sha256=audit.sha256(historical_path),
                  **review_functions(json.loads(historical_path.read_text('utf-8')), correlation))
    target = audit.save_snapshot(folder / 'function-review', result)
    print(json.dumps(dict(report=str(target), sha256=audit.sha256(target),
                          counts=result['counts'], analysis_timed_out=result['analysis_timed_out']), indent=2))


if __name__ == '__main__':
    main()
