"""Match historical saved blobs to fresh decoded records by SHA, never by offset.

Absence is inconclusive: records may be encrypted, oversized or undiscovered.
Observed path strings are references, not authenticated archive filenames.
"""
import argparse
from collections import defaultdict
import importlib.util
import json
from pathlib import Path


def match_blobs(previous, entries):
    by_hash = defaultdict(list)
    for row in entries:
        if row.get('decode_status') == 'decoded' and row.get('decoded_sha256'):
            by_hash[row['decoded_sha256']].append(row['entry'])
    return [dict(**blob, matching_new_entries=by_hash.get(blob['sha256'], []),
                 status='exact_content_match' if blob['sha256'] in by_hash else 'not_observed')
            for blob in previous]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record_index', type=Path)
    parser.add_argument('previous_entries', type=Path)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('asset_audit', Path(__file__).with_name('audit-client-release.py'))
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    if audit.sha256(args.record_index) != args.record_index.parent.name:
        raise ValueError('Record index digest mismatch')
    index = json.loads(args.record_index.read_text('utf-8'))
    if audit.sha256(Path(index['source']['path'])) != index['source']['sha256']:
        raise ValueError('Source archive changed')
    previous_bytes = args.previous_entries.read_bytes()
    previous = json.loads(previous_bytes)
    blobs = []
    for row in previous:
        if not row.get('saved'):
            continue
        path = Path(row['saved'])
        # A legacy index is data, not permission to hash arbitrary local files.
        if not path.resolve().is_relative_to(args.previous_entries.parent.resolve()):
            raise ValueError('Historical blob outside extraction directory')
        blobs.append(dict(previous_entry=row['entry'], file=str(path), sha256=audit.sha256(path),
                          observed_paths=row.get('paths', [])))
    rows = match_blobs(blobs, index['entries'])
    report = dict(schema=1, tool_sha256=audit.sha256(Path(__file__)), source=index['source'],
                  record_index=str(args.record_index), record_index_sha256=args.record_index.parent.name,
                  previous_entries=str(args.previous_entries), previous_entries_sha256=audit.sha256(args.previous_entries),
                  scope='Only historical saved blobs and fresh decoded record hashes; no resource identity inferred',
                  exact_content_matches=sum(row['status'] == 'exact_content_match' for row in rows),
                  not_observed=sum(row['status'] == 'not_observed' for row in rows), blobs=rows,
                  compatibility='not_established')
    target = audit.save_snapshot(args.record_index.parent / 'asset-comparisons', report)
    print(json.dumps(dict(report=str(target), sha256=audit.sha256(target),
                          saved_blobs=len(rows), exact_content_matches=report['exact_content_matches'],
                          not_observed=report['not_observed']), indent=2))


if __name__ == '__main__':
    main()
