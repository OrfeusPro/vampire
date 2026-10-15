"""Export local VAMPIR UI/map textures with archive and pixel provenance."""
import importlib.util
import json
import os
import re
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
HERE = Path(__file__).resolve().parent


def main():
    spec = importlib.util.spec_from_file_location('vampir_texture_reader', HERE.parent / 'rfnext' / 'export-textures.py')
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    reader.ROOT = ROOT
    reader.export_all()
    records = json.loads((ROOT / 'archive-image-catalog.json').read_text('utf-8'))
    selected = {}
    for record in records:
        suffix = re.search(r'_s(\d+)-Windows', record['source'])
        record['patch'] = int(suffix[1]) if suffix else 0
        record['selection'] = 'largest_s_suffix; confirm against game patch manifest before navigation'
        previous = selected.get(record['asset_path'])
        if previous is None or record['patch'] > previous['patch']:
            selected[record['asset_path']] = record
    for filename, value in [('archive-image-catalog.json', records), ('archive-image-latest.json', list(selected.values()))]:
        (ROOT / filename).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    maps = [r for r in selected.values() if '/Texture/Map/' in r['asset_path']]
    (ROOT / 'map-image-catalog.json').write_text(json.dumps(maps, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Vampir map textures', len(maps), flush=True)


if __name__ == '__main__':
    main()
