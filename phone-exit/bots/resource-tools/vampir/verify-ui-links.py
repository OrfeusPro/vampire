"""Recheck native descriptor pointers and container/catalog links against source bytes."""
import hashlib
import csv
import importlib.util
import json
import os
import struct
from collections import defaultdict
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
spec = importlib.util.spec_from_file_location('verified_ui_pe', Path(__file__).with_name('extract-native-enums.py'))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def main():
    schema = json.loads((ROOT / 'code-clues/ui-properties.json').read_text(encoding='utf-8'))
    data = Path(schema['source']).read_bytes()
    require(hashlib.sha256(data).hexdigest() == schema['sha256'], 'Native executable changed')
    pe = native.PE(data)
    descriptors = 0
    for family in ('size_box', 'widget', 'widget_transform', 'scale_box'):
        for row in schema[family]['properties']:
            require(struct.unpack_from('<Q', data, row['pointer_offset'])[0] == pe.address(row['descriptor_offset']), 'Property array pointer changed')
            require(struct.unpack_from('<Q', data, row['descriptor_offset'])[0] == pe.address(row['name_offset']), 'Property name pointer changed')
            require(struct.unpack_from('<I', data, row['descriptor_offset'] + 24)[0] == row['gen_flags'], 'Native property flags changed')
            require(data[row['name_offset']:row['name_offset'] + len(row['name']) + 1] == row['name'].encode() + b'\0', 'Property name changed')
            descriptors += 1
    index = json.loads((ROOT / 'ui-catalog/index.json').read_text(encoding='utf-8'))
    by_source, cache = defaultdict(list), {}
    for row in index['windows']:
        by_source[row['source_file']].append(row['file'])
    summary = dict(native_descriptors=descriptors)
    for file, kind in (('size-boxes.json', 'SizeBox'), ('scale-boxes.json', 'ScaleBox')):
        report = json.loads((ROOT / 'ui-geometry' / file).read_text(encoding='utf-8'))
        require(not report['failures'], kind + ' has unresolved records; inspect failures')
        for box in report['boxes']:
            source = box['provenance']
            controls = []
            # Only index-listed variants are authoritative; old package files may remain.
            for variant in by_source[source['file']]:
                if variant not in cache:
                    cache[variant] = json.loads((ROOT / 'ui-catalog' / variant).read_text(encoding='utf-8'))
                controls.extend(c for c in cache[variant]['controls'] if c['export'] == source['export'])
            require(bool(controls), 'Container missing from catalog: ' + source['file'])
            require(all(c['type'] == kind and c.get('container_geometry', {}).get('provenance', {}).get('sha256') == source['sha256'] for c in controls), 'Container source link changed')
        summary[kind] = len(report['boxes'])
    scale_file = ROOT / 'ui-geometry/ui-scale-reference.json'
    if scale_file.exists():
        scale = json.loads(scale_file.read_text(encoding='utf-8'))
        require(scale['native_source']['sha256'] == schema['sha256'], 'Scale reference native source mismatch')
        tables = {}
        for entry, source in scale['sources'].items():
            path = ROOT / 'table-study' / source['file']
            require(hashlib.sha256(path.read_bytes()).hexdigest() == source['sha256'], 'Scale table changed')
            with path.open(encoding='utf-8-sig', newline='') as stream:
                tables[entry] = list(csv.DictReader(stream))
        referenced = [scale[k] for k in ('option', 'labels', 'group', 'subtab', 'main_tab')]
        referenced += [item['row'] for levels in scale['presets'].values() for item in levels.values()]
        for row in referenced:
            origin = row['source']
            actual = tables[str(origin['entry'])][origin['csv_record'] - 2]
            require({k: v for k, v in row.items() if k != 'source'} == actual, 'Scale row link changed')
        option = scale['option_enum']
        require(struct.unpack_from('<q', data, option['descriptor_offset'] + 8)[0] == option['value'], 'Native scale option value changed')
        require(data[option['name_offset']:option['name_offset'] + len(option['name']) + 1] == option['name'].encode() + b'\0', 'Native scale option name changed')
        summary['ui_scale_presets'] = sum(len(v) for v in scale['presets'].values())
        summary['ui_scale_source_rows'] = len(referenced)
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
