"""Extract current CSVs using a fresh SHA-bound record index, without old offsets."""
import argparse
import csv
import hashlib
import importlib.util
import io
import json
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIMIT = 16 * 1024 * 1024


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def compare_tables(previous, current):
    """Exact bytes prove equality; unique equal schemas only identify candidates."""
    hashes, old_schemas, new_schemas = defaultdict(list), defaultdict(list), defaultdict(list)
    for row in previous:
        hashes[row['sha256']].append(row['file'])
        old_schemas[tuple(row['header'])].append(row['file'])
    for row in current:
        new_schemas[tuple(row['header'])].append(row)
    for row in current:
        row['identical_previous_files'] = hashes.get(row['sha256'], [])
        candidates = old_schemas.get(tuple(row['header']), [])
        row['unique_schema_candidate'] = (candidates[0] if len(candidates) == 1 and
                                          len(new_schemas[tuple(row['header'])]) == 1 else None)
        row['identity_proven_by_schema'] = False
    return dict(exact_content_matches=sum(bool(r['identical_previous_files']) for r in current),
                without_exact_content_match=sum(not r['identical_previous_files'] for r in current),
                unique_schema_candidates=sum(bool(r['unique_schema_candidate']) for r in current),
                table_identity_by_entry_assumed=False)


def parse_csv(data):
    if not data.startswith(b'\xef\xbb\xbf'):
        return None
    rows = csv.reader(io.StringIO(data.decode('utf-8-sig')))
    header = next(rows, [])
    if len(header) < 2:
        return None
    count = sum(1 for _ in rows)
    return header, count


def compare_unique_rows(before_data, after_data):
    """Textual CSV differences, using an observed unique first column only."""
    before = list(csv.reader(io.StringIO(before_data.decode('utf-8-sig'))))
    after = list(csv.reader(io.StringIO(after_data.decode('utf-8-sig'))))
    if not before or not after or before[0] != after[0] or len(set(before[0])) != len(before[0]):
        return dict(status='unsupported_header')
    width = len(before[0])
    if any(len(row) != width or not row[0] for row in before[1:] + after[1:]):
        return dict(status='unsupported_row_shape')
    old = {row[0]: row for row in before[1:]}
    new = {row[0]: row for row in after[1:]}
    if len(old) != len(before) - 1 or len(new) != len(after) - 1:
        return dict(status='duplicate_first_column')
    changed = sorted(key for key in old.keys() & new.keys() if old[key] != new[key])
    fields = defaultdict(int)
    examples = []
    for key in changed:
        names = [before[0][i] for i in range(width) if old[key][i] != new[key][i]]
        for name in names:
            fields[name] += 1
        if len(examples) < 10:
            examples.append(dict(first_column=key, fields=names))
    return dict(status='compared', key_basis='unique first column text; game key semantics not inferred',
                added_rows=len(new.keys() - old.keys()), removed_rows=len(old.keys() - new.keys()),
                changed_rows=len(changed), changed_fields=dict(sorted(fields.items())), examples=examples)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record_index', type=Path)
    parser.add_argument('previous_table_index', type=Path)
    args = parser.parse_args()
    audit = load('vampir_table_audit', HERE / 'audit-client-release.py')
    if audit.sha256(args.record_index) != args.record_index.parent.name:
        raise ValueError('Record index digest mismatch')
    index = json.loads(args.record_index.read_text('utf-8'))
    reader_path = HERE.parent / 'rfnext/scan-pak.py'
    reader = load('vampir_table_reader', reader_path)
    if (audit.sha256(reader_path) != index['dependencies']['reader_sha256'] or
            audit.sha256(reader.ROOT / 'tools/oodle-data-shared.dll') != index['dependencies']['oodle_sha256']):
        raise ValueError('Record decoder dependencies changed')
    source = Path(index['source']['path'])
    before = source.stat()
    if audit.sha256(source) != index['source']['sha256']:
        raise ValueError('Source archive changed')
    previous_bytes = args.previous_table_index.read_bytes()
    previous = json.loads(previous_bytes)['tables']
    if any(Path(row['source']['path']).resolve() != source.resolve() for row in previous):
        raise ValueError('Previous table index belongs to another archive')
    dest = args.record_index.parent / 'csv-blobs'
    dest.mkdir(exist_ok=True)
    tables, errors, skipped = [], [], 0
    csv.field_size_limit(1024 * 1024)
    with source.open('rb') as stream:
        for entry in index['entries']:
            if entry['encrypted'] or not 0 < entry['uncompressed'] <= LIMIT or entry['bytes'] > LIMIT:
                skipped += 1
                continue
            header = reader.header(stream, entry['offset'], index['index_offset'])
            if not header or header['end'] != entry['end']:
                raise ValueError('Fresh record header mismatch')
            try:
                data = reader.decode(stream, header)
                if data is None or len(data) != entry['uncompressed']:
                    raise ValueError('Decoded size mismatch')
                parsed = parse_csv(data)
                if parsed is None:
                    continue
                digest = hashlib.sha256(data).hexdigest()
                if entry.get('decoded_sha256') and digest != entry['decoded_sha256']:
                    raise ValueError('Decoded hash mismatch')
                target = dest / (digest + '.csv')
                try:
                    with target.open('xb') as output:
                        output.write(data)
                except FileExistsError:
                    if audit.sha256(target) != digest:
                        raise ValueError('Existing CSV blob corrupt') from None
                tables.append(dict(file=str(target), entry=entry['entry'], offset=entry['offset'],
                                   sha256=digest, bytes=len(data), header=parsed[0], rows=parsed[1],
                                   internal_path=None))
            except (ValueError, UnicodeError, csv.Error) as error:
                errors.append(dict(entry=entry['entry'], error_type=type(error).__name__))
    after = source.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise RuntimeError('Source changed during extraction')
    comparison = compare_tables(previous, tables)
    previous_by_file = {row['file']: row for row in previous}
    for table in tables:
        candidate = table['unique_schema_candidate']
        if candidate and not table['identical_previous_files']:
            old_path = args.previous_table_index.parent / candidate
            old_bytes = old_path.read_bytes()
            if hashlib.sha256(old_bytes).hexdigest() != previous_by_file[candidate]['sha256']:
                raise ValueError('Historical CSV hash mismatch')
            table['candidate_row_diff'] = compare_unique_rows(old_bytes, Path(table['file']).read_bytes())
    report = dict(schema=1, source=index['source'], tool_sha256=audit.sha256(Path(__file__)),
                  record_index_sha256=args.record_index.parent.name,
                  previous_table_index_sha256=hashlib.sha256(previous_bytes).hexdigest(),
                  previous_table_index=str(args.previous_table_index),
                  scope='Plain UTF-8 BOM CSV, stored and decoded sizes <=16 MiB; no directory names',
                  dependencies=index['dependencies'], tables=tables, errors=errors, skipped=skipped,
                  comparison=comparison, compatibility='not_established')
    target = audit.save_snapshot(args.record_index.parent / 'table-snapshots', report)
    print(json.dumps(dict(report=str(target), sha256=audit.sha256(target), tables=len(tables),
                          errors=len(errors), skipped=skipped, comparison=report['comparison']), indent=2))


if __name__ == '__main__':
    main()
