"""Fresh bounded record discovery in changed PAKs; never reuse old offsets.

This walks local record headers, not the encrypted PAK directory index. Paths
are observed strings, not authoritative archive filenames or resource bindings.
"""
import argparse
import hashlib
import importlib.util
import json
import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
DECODE_LIMIT = 2 * 1024 * 1024
NEEDLES = ('NMSDKSettings', 'SDKZone=', 'NetmarbleClientId=', 'NMSDKMarket-')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record_digest(stream, start, end):
    digest = hashlib.sha256()
    stream.seek(start)
    while start < end:
        block = stream.read(min(end - start, 1024 * 1024))
        if not block:
            raise ValueError('Truncated record')
        start += len(block)
        digest.update(block)
    return digest.hexdigest()


def discover(stream, size, reader):
    stream.seek(max(0, size - 512))
    tail = stream.read()
    marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
    if marker < 0 or marker + 24 > len(tail):
        raise ValueError('Missing PAK footer')
    version, limit, index_size = struct.unpack_from('<iqq', tail, marker + 4)
    footer_offset = max(0, size - 512) + marker
    if version != 11 or not 0 < limit <= footer_offset or not 0 <= index_size <= footer_offset - limit:
        raise ValueError('Unsupported PAK footer bounds')
    pos, rows, gaps = 0, [], []
    while pos < limit:
        header = reader.header(stream, pos, limit)
        if not header:
            for candidate in sorted({((pos + a - 1) // a) * a for a in (16, 128, 512, 2048, 4096, 65536)}):
                if pos < candidate < limit:
                    header = reader.header(stream, candidate, limit)
                    if header:
                        gaps.append(dict(start=pos, end=candidate))
                        pos = candidate
                        break
            if not header:
                break
        if not pos < header['end'] <= limit:
            raise ValueError('Invalid record bounds')
        row = dict(entry=len(rows), offset=pos, end=header['end'], bytes=header['size'],
                   uncompressed=header['usize'], encrypted=header['encrypted'], method=header['method'],
                   stored_record_sha256=record_digest(stream, pos, header['end']))
        if header['encrypted']:
            row['decode_status'] = 'encrypted_skipped'
        elif header['usize'] > DECODE_LIMIT or header['size'] > DECODE_LIMIT:
            row['decode_status'] = 'size_skipped'
        else:
            try:
                data = reader.decode(stream, header)
                if data is None or len(data) != header['usize']:
                    raise ValueError('Decoded size mismatch')
                row['decoded_sha256'] = hashlib.sha256(data).hexdigest()
                row['decode_status'] = 'decoded'
                row['uasset'] = data.startswith(b'\xc1\x83\x2a\x9e')
                if row['uasset']:
                    strings = re.findall(rb'[ -~]{4,}', data)
                    row['paths'] = sorted({s.decode('ascii') for s in strings if s.startswith((b'/Game/', b'/Engine/'))})
                matches = []
                for needle in NEEDLES:
                    for encoding in ('ascii', 'utf-16le'):
                        offset = data.find(needle.encode(encoding))
                        if offset >= 0:
                            matches.append(dict(needle=needle, encoding=encoding, decoded_offset=offset))
                if matches:
                    row['settings_markers'] = matches
            except (ValueError, OSError) as error:
                row['decode_status'] = 'error'
                row['error_type'] = type(error).__name__
        rows.append(row)
        pos = header['end']
    return dict(entries=rows, scan_end=pos, index_offset=limit, reached_index=pos == limit,
                gaps=gaps, directory_index_parsed=False, decode_limit=DECODE_LIMIT,
                decode_counts={status: sum(r['decode_status'] == status for r in rows)
                               for status in sorted({r['decode_status'] for r in rows})})


def compare_observed_paths(old, new):
    before = {p for r in old for p in r.get('paths', [])}
    after = {p for r in new for p in r.get('paths', [])}
    return dict(previous_observed=len(before), current_observed=len(after),
                newly_observed=sorted(after - before), no_longer_observed=sorted(before - after),
                authoritative_resource_diff=False,
                limitation='Different decode budgets; strings are not directory names or proven bindings')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--archive-sha256', help='Index only this exact archive digest from the release manifest')
    args = parser.parse_args()
    audit = load('vampir_audit_for_index', HERE / 'audit-client-release.py')
    manifest = json.loads(args.manifest.read_text('utf-8'))
    if audit.sha256(args.manifest) != args.manifest.parent.name:
        raise ValueError('Release manifest digest mismatch')
    if args.archive_sha256 and not any(
            (item.get('current') or {}).get('sha256') == args.archive_sha256
            and (item.get('current') or {}).get('pak_version') == 11
            for item in manifest['files']):
        raise ValueError('Requested PAK digest absent from release manifest')
    reader_path = HERE.parent / 'rfnext/scan-pak.py'
    reader = load('vampir_record_reader', reader_path)
    dependencies = dict(tool_sha256=audit.sha256(Path(__file__)),
                        reader_sha256=audit.sha256(reader_path),
                        oodle_sha256=audit.sha256(reader.ROOT / 'tools/oodle-data-shared.dll'))
    outputs = []
    for item in manifest['files']:
        source = item['current']
        if args.archive_sha256 and (source or {}).get('sha256') != args.archive_sha256:
            continue
        if not source or source.get('pak_version') != 11 or item['status'] == 'sample_matches_unverified':
            continue
        path = Path(item['path'])
        before = path.stat()
        if audit.sha256(path) != source['sha256']:
            raise ValueError('Archive no longer matches release manifest')
        cache_key = hashlib.sha256(audit.canonical(dict(source_sha256=source['sha256'], **dependencies))).hexdigest()
        cache_dir = args.manifest.parent / 'record-indexes' / cache_key
        existing = list(cache_dir.glob('*/manifest.json'))
        if len(existing) > 1:
            raise ValueError('Ambiguous index cache')
        if existing:
            target = existing[0]
            if audit.sha256(target) != target.parent.name:
                raise ValueError('Index snapshot digest mismatch')
            report = json.loads(target.read_text('utf-8'))
        else:
            with path.open('rb') as stream:
                result = discover(stream, before.st_size, reader)
            old = []
            cached = item.get('cached_index')
            if cached and cached.get('entries_sha256'):
                old_path = Path(cached['path'])
                if audit.sha256(old_path) != cached['entries_sha256']:
                    raise ValueError('Previous index digest mismatch')
                old = json.loads(old_path.read_text('utf-8'))
            report = dict(schema=1, source=source, release_manifest_sha256=args.manifest.parent.name,
                          dependencies=dependencies, **result,
                          observed_path_comparison=compare_observed_paths(old, result['entries']))
            after = path.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise RuntimeError('Source changed during discovery')
            target = audit.save_snapshot(cache_dir, report)
        summary = dict(archive=path.name, report=str(target), sha256=audit.sha256(target),
                       entries=len(report['entries']), reached_index=report['reached_index'],
                       decode_counts=report['decode_counts'], gaps=len(report['gaps']),
                       settings_marker_records=sum(bool(r.get('settings_markers')) for r in report['entries']))
        outputs.append(summary)
        print(json.dumps(summary), flush=True)
    summary = dict(schema=1, release_manifest_sha256=args.manifest.parent.name,
                   selected_archive_sha256=args.archive_sha256,
                   dependencies=dependencies, archives=outputs, compatibility='not_established')
    target = audit.save_snapshot(args.manifest.parent / 'index-summaries', summary)
    print('SUMMARY', target, flush=True)


if __name__ == '__main__':
    main()
