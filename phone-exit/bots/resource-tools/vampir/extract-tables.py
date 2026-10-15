"""Index plain CSV records without interpreting cooked or encrypted data."""
import csv
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', default='ProjectRED-Windows')
    args = parser.parse_args()
    if not args.archive or Path(args.archive).name != args.archive or '/' in args.archive or '\\' in args.archive:
        raise ValueError('Archive must be an inventory folder name')
    spec = importlib.util.spec_from_file_location('pak_reader', HERE.parent / 'rfnext' / 'scan-pak.py')
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    dest = ROOT / 'table-study'
    dest.mkdir(exist_ok=True)
    tables, failures = [], []
    # ProjectRED contains the observed plain localization/configuration records.
    folder = ROOT / 'pak-extracted' / args.archive
    source = json.loads((folder / 'source.json').read_text(encoding='utf-8'))
    archive = Path(source['path'])
    stamp = archive.stat()
    with archive.open('rb') as check:
        head = check.read(65536)
        check.seek(max(0, stamp.st_size - 65536))
        fingerprint = hashlib.sha256(head + check.read()).hexdigest()
    if (stamp.st_size != source['size'] or stamp.st_mtime_ns != source['modified_ns']
            or fingerprint != source['sample_sha256']):
        raise ValueError('Archive changed; rerun scan-resources.py before extracting tables')
    records = json.loads((folder / 'entries.json').read_text(encoding='utf-8'))
    with archive.open('rb') as stream:
        for record in records[:-1]:
            if record.get('encrypted') or record.get('uasset') or record.get('pixel_formats'):
                continue
            if not 0 < record.get('uncompressed', 0) <= 16 * 1024 ** 2:
                continue
            try:
                data = reader.decode(stream, reader.header(stream, record['offset'], records[-1]['index_offset']))
                if not data or not data.startswith(b'\xef\xbb\xbf'):
                    continue
                content = data.decode('utf-8-sig')
                rows = list(csv.reader(io.StringIO(content)))
                if not rows or len(rows[0]) < 2:
                    continue
                name = args.archive + '-' + str(record['entry']) + '.csv'
                (dest / name).write_bytes(data)
                relevant = [row for row in rows[1:] if any(word in ','.join(row).lower() for word in ('quest', 'tutorial'))]
                tables.append(dict(file=name, source=source, entry=record['entry'], offset=record['offset'],
                                   size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                                   header=rows[0], rows=len(rows)-1, quest_tutorial_rows=len(relevant),
                                   examples=[row[:8] for row in relevant[:5]],
                                   internal_path=None))
            except Exception as exc:
                failures.append(dict(entry=record['entry'], error=str(exc)))
    result = dict(scope=args.archive + ' only; plain UTF-8 BOM CSV, <=16 MiB',
                  tables=tables, errors=failures)
    index = dest / ('index.json' if args.archive == 'ProjectRED-Windows' else 'index-' + args.archive + '.json')
    index.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(tables=len(tables), errors=len(failures), index=str(index))))


if __name__ == '__main__':
    main()
