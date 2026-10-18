"""Read public client archives; preserve immutable release audits outside Git.

Sample equality is NOT full content equality or protocol compatibility. Never
read account/preferences files or replace the existing extraction baseline.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

EXE_SHA256 = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'
EXTENSIONS = {'.pak', '.utoc', '.ucas'}


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def inspect_archive(path):
    before = path.stat()
    with path.open('rb') as stream:
        head = stream.read(65536)
        stream.seek(max(0, before.st_size - 65536))
        tail = stream.read()
    marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
    version = struct.unpack_from('<i', tail, marker + 4)[0] if 0 <= marker <= len(tail) - 8 else None
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise RuntimeError('Archive changed during sampling')
    return dict(path=str(path), size=before.st_size, modified_ns=before.st_mtime_ns,
                sample_sha256=hashlib.sha256(head + tail).hexdigest(), pak_version=version)


def classify(old, current):
    if old is None:
        return 'added'
    if current is None:
        return 'removed'
    if old['size'] != current['size'] or old['sample_sha256'] != current['sample_sha256']:
        return 'changed'
    if old['modified_ns'] != current['modified_ns']:
        return 'metadata_changed'
    return 'sample_matches_unverified'


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode('utf-8') + b'\n'


def save_snapshot(folder, report):
    payload = canonical(report)
    identity = hashlib.sha256(payload).hexdigest()
    target = folder / identity / 'manifest.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open('xb') as stream:
            stream.write(payload)
    except FileExistsError:
        if target.read_bytes() != payload:
            raise RuntimeError('Immutable snapshot collision') from None
    return target


def audit(install, resources):
    baseline_path = resources / 'pc-pak-inventory.json'
    baseline_bytes = baseline_path.read_bytes()
    baseline = json.loads(baseline_bytes)
    if Path(baseline['source']).resolve() != install.resolve():
        raise ValueError('Baseline belongs to another installation')
    previous = {}
    roots = {install / 'ProjectRED/Content/Paks',
             install / 'ProjectRED/Saved/PersistentDownloadDir/Patch/Install'}
    for row in baseline['files']:
        path = Path(row['path'])
        if not path.resolve().is_relative_to(install.resolve()) or path.suffix.lower() not in EXTENSIONS:
            raise ValueError('Baseline archive outside public installation scope')
        previous[str(path)] = row
        roots.add(path.parent)
    paths = {str(path): path for root in roots if root.is_dir()
             for path in root.rglob('*') if path.is_file() and path.suffix.lower() in EXTENSIONS}
    rows = []
    for name in sorted(previous.keys() | paths.keys()):
        path = paths.get(name)
        current = inspect_archive(path) if path else None
        old = previous.get(name)
        status = classify(old, current)
        item = dict(path=name, status=status, baseline=old, current=current)
        # Metadata-only changes also require review; head/tail can miss middle edits.
        if current and status != 'sample_matches_unverified':
            current['sha256'] = sha256(path)
            after = path.stat()
            if (after.st_size, after.st_mtime_ns) != (current['size'], current['modified_ns']):
                raise RuntimeError('Archive changed during full hashing')
        if old and old.get('pak_version') == 11:
            cache = resources / 'pak-extracted' / Path(name).stem
            stamp, entries = cache / 'source.json', cache / 'entries.json'
            cache_status = 'missing'
            if stamp.is_file() and entries.is_file():
                stamp_matches = json.loads(stamp.read_text('utf-8')) == old
                cache_status = ('sample_only_unverified' if stamp_matches and
                                status == 'sample_matches_unverified' else 'stale')
            item['cached_index'] = dict(
                path=str(entries),
                status=cache_status,
                stamp_sha256=sha256(stamp) if stamp.is_file() else None,
                entries_sha256=sha256(entries) if entries.is_file() else None)
        rows.append(item)
    exe = install / 'ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe'
    exe_before = exe.stat()
    exe_hash = sha256(exe)
    exe_after = exe.stat()
    if (exe_before.st_size, exe_before.st_mtime_ns) != (exe_after.st_size, exe_after.st_mtime_ns):
        raise RuntimeError('EXE changed during hashing')
    return dict(schema=1, tool_sha256=sha256(Path(__file__)), source=str(install),
                game_version=None, android_version=None,
                baseline_path=str(baseline_path),
                baseline_sha256=hashlib.sha256(baseline_bytes).hexdigest(),
                scope='baseline archive parents plus Content/Paks and Patch/Install; archive extensions only',
                sample_definition='SHA256(first 65536 bytes + last 65536 bytes), overlapping bytes repeated',
                full_archive_coverage=False, compatibility='not_established', network_ready=False,
                exe=dict(path=str(exe), sha256=exe_hash, expected_sha256=EXE_SHA256,
                         matches_research=exe_hash == EXE_SHA256),
                files=rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install', type=Path, default=Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR'))
    parser.add_argument('--resources', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    report = audit(args.install, args.resources)
    target = save_snapshot(args.resources / 'release-snapshots', report)
    counts = {status: sum(r['status'] == status for r in report['files'])
              for status in sorted({r['status'] for r in report['files']})}
    print(json.dumps(dict(manifest=str(target), sha256=sha256(target), counts=counts,
                          exe_matches=report['exe']['matches_research'], compatibility=report['compatibility']), indent=2))


if __name__ == '__main__':
    main()
