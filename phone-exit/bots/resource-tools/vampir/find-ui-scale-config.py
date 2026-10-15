"""Search bounded unencrypted startup/config records for exact DPI configuration keys."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
KEYS = ('DPIScaleRule', 'UIScaleRule', 'UIScaleCurve', 'DPICurve', 'ApplicationScale',
        'DesignScreenSize', 'UserInterfaceSettings', 'DisplayUIScaleAOS')


def main():
    spec = importlib.util.spec_from_file_location('ui_config_pak', Path(__file__).resolve().parent.parent / 'rfnext/scan-pak.py')
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    dest = ROOT / 'code-clues/ui-scale-config'
    dest.mkdir(exist_ok=True)
    archives = []
    for stem in ('ProjectRED-Windows', 'pakchunk0-Windows', 'pakchunk0_s1-Windows', 'pakchunk0_s2-Windows', 'pakchunk100-Windows'):
        folder = ROOT / 'pak-extracted' / stem
        source = json.loads((folder / 'source.json').read_text(encoding='utf-8'))
        path = Path(source['path'])
        stat = path.stat()
        if stat.st_size != source['size'] or stat.st_mtime_ns != source['modified_ns']:
            raise ValueError('Archive changed; rebuild inventory: ' + stem)
        records = json.loads((folder / 'entries.json').read_text(encoding='utf-8'))
        hits, errors, scanned, encrypted = [], [], 0, 0
        with path.open('rb') as stream:
            for row in records[:-1]:
                if row.get('encrypted'):
                    encrypted += 1
                    continue
                if row.get('uasset') or row.get('pixel_formats') or not 32 <= row.get('uncompressed', 0) <= 4 * 1024 * 1024:
                    continue
                try:
                    data = reader.decode(stream, reader.header(stream, row['offset'], records[-1]['index_offset']))
                    scanned += 1
                    matches = []
                    for key in KEYS:
                        for encoding in ('ascii', 'utf-16le'):
                            needle = key.encode(encoding)
                            offset = data.find(needle)
                            if offset >= 0:
                                matches.append(dict(key=key, encoding=encoding, decoded_offset=offset))
                    if matches:
                        name = stem + '-' + str(row['entry']) + '.bin'
                        (dest / name).write_bytes(data)
                        hits.append(dict(entry=row['entry'], offset=row['offset'], size=len(data),
                                         file=name, sha256=hashlib.sha256(data).hexdigest(), matches=matches))
                except Exception as error:
                    errors.append(dict(entry=row['entry'], error=str(error)))
        archives.append(dict(source=source, scanned=scanned, encrypted_skipped=encrypted, hits=hits, errors=errors))
        print(json.dumps(dict(archive=stem, scanned=scanned, hits=len(hits), errors=len(errors))), flush=True)
    (dest / 'index.json').write_text(json.dumps(dict(keys=KEYS, archives=archives, complete=True,
        limitation='Only five startup/data archives, unencrypted non-texture records <=4MiB; no Android config or active preference inferred'), indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
