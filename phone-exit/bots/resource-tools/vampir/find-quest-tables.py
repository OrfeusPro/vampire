"""Search explicit schema keys in unencrypted records of candidate data PAKs."""
import hashlib
import importlib.util
import json
import os
import argparse
from collections import Counter
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
HERE = Path(__file__).resolve().parent
KEYS = ('PreQuestId', 'QuestInitParam', 'QuestActionPosX', 'TargetSpotInfoId',
        'UIEnteredStartStep', 'ServerProcessRequest', 'SkipButtonMove', 'TutorialUI.csv', 'TutorialStep.csv')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--all', action='store_true', help='Search all inventoried game PAKs')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('pak_reader', HERE.parent / 'rfnext/scan-pak.py')
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    dest = ROOT / 'code-clues'
    dest.mkdir(exist_ok=True)
    report = []
    stems = sorted(p.name for p in (ROOT / 'pak-extracted').iterdir() if (p / 'source.json').is_file()) if args.all else ('ProjectRED-Windows', 'pakchunk0-Windows', 'pakchunk0_s1-Windows', 'pakchunk0_s2-Windows', 'pakchunk100-Windows')
    output = dest / ('quest-table-search-all.json' if args.all else 'quest-table-search.json')
    for stem in stems:
        folder = ROOT / 'pak-extracted' / stem
        source = json.loads((folder / 'source.json').read_text(encoding='utf-8'))
        path = Path(source['path'])
        stamp = path.stat()
        if stamp.st_size != source['size'] or stamp.st_mtime_ns != source['modified_ns']:
            raise ValueError('Changed archive: rerun inventory')
        rows = json.loads((folder / 'entries.json').read_text(encoding='utf-8'))
        hits, errors, scanned, skipped = [], [], 0, 0
        signatures = Counter()
        encrypted = []
        with path.open('rb') as stream:
            for row in rows[:-1]:
                if row.get('encrypted'):
                    encrypted.append(dict(entry=row['entry'], offset=row['offset'], size=row['uncompressed']))
                if row.get('encrypted') or row.get('uasset') or row.get('pixel_formats') or not 128 <= row.get('uncompressed', 0) <= 64 * 1024 ** 2:
                    skipped += 1
                    continue
                try:
                    data = reader.decode(stream, reader.header(stream, row['offset'], rows[-1]['index_offset']))
                    if not data:
                        continue
                    scanned += 1
                    signatures[data[:8].hex()] += 1
                    keys = [key for key in KEYS if key.encode() in data or key.encode('utf-16le') in data]
                    if keys:
                        name = stem + '-' + str(row['entry']) + '.bin'
                        (dest / name).write_bytes(data)
                        hits.append(dict(entry=row['entry'], offset=row['offset'], file=name,
                                         sha256=hashlib.sha256(data).hexdigest(), size=len(data), keys=keys))
                except Exception as error:
                    errors.append(dict(entry=row['entry'], error=str(error)))
        report.append(dict(source=source, scanned=scanned, skipped=skipped, errors=errors, hits=hits,
                           signatures=signatures.most_common(15), encrypted=encrypted))
        output.write_text(json.dumps(dict(keys=KEYS, complete=False, archives=report), indent=2), encoding='utf-8')
        print(json.dumps(dict(archive=stem, scanned=scanned, hits=len(hits), errors=len(errors))), flush=True)
    output.write_text(json.dumps(dict(keys=KEYS, complete=True, archives=report), indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
