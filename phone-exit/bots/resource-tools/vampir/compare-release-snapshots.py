"""Compare two immutable release audits without treating samples as full hashes."""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path, PureWindowsPath


def compare_file(before, after):
    if before is None:
        return 'added'
    if after is None:
        return 'removed'
    if before['size'] != after['size']:
        return 'content_changed'
    if before.get('sha256') and after.get('sha256'):
        return 'full_hash_equal' if before['sha256'] == after['sha256'] else 'content_changed'
    if before['sample_sha256'] != after['sample_sha256']:
        return 'content_changed'
    if before['modified_ns'] != after['modified_ns']:
        return 'metadata_changed_content_unverified'
    return 'sample_equal_content_unverified'


def compare(before, after):
    def inventory(report):
        result = {}
        for item in report['files']:
            key = str(PureWindowsPath(item['path'])).casefold()
            if key in result:
                raise ValueError('Duplicate archive path')
            result[key] = item
        return result
    old, new = inventory(before), inventory(after)
    rows = []
    for key in sorted(old.keys() | new.keys()):
        a, b = old.get(key), new.get(key)
        left, right = a.get('current') if a else None, b.get('current') if b else None
        if left is None and right is None:
            continue
        rows.append(dict(path=(b or a)['path'], status=compare_file(left, right),
                         before=left, after=right))
    return dict(files=rows, counts=dict(Counter(row['status'] for row in rows)),
                exe=dict(before=before['exe'], after=after['exe'],
                         full_hash_equal=before['exe']['sha256'] == after['exe']['sha256']),
                compatibility='not_established')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before', type=Path)
    parser.add_argument('after', type=Path)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('release_audit', Path(__file__).with_name('audit-client-release.py'))
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    reports = []
    for path in (args.before, args.after):
        if audit.sha256(path) != path.parent.name:
            raise ValueError('Release manifest digest mismatch')
        reports.append(json.loads(path.read_text('utf-8')))
    report = dict(schema=1, tool_sha256=audit.sha256(Path(__file__)),
                  before_manifest=str(args.before), before_manifest_sha256=args.before.parent.name,
                  after_manifest=str(args.after), after_manifest_sha256=args.after.parent.name,
                  **compare(*reports))
    target = audit.save_snapshot(args.after.parent / 'comparisons', report)
    print(json.dumps(dict(report=str(target), sha256=audit.sha256(target),
                          counts=report['counts'], exe_equal=report['exe']['full_hash_equal']), indent=2))


if __name__ == '__main__':
    main()
