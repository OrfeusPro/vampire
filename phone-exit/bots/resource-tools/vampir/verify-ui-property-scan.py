"""Verify the complete decoded-catalog matrix and all property occurrence references."""
import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


def read(path):
    return json.loads(path.read_text('utf-8'))


def verify(root, folder):
    report = read(folder / 'index.json'); catalog = root / 'ui-catalog'
    assert hashlib.sha256((catalog / 'index.json').read_bytes()).hexdigest() == report['source_index_sha256']
    index = read(catalog / 'index.json')
    files = {r['file'] for r in index['windows']} | {v['file'] for rows in index['resource_variants'].values() for v in rows}
    dataset = report['datasets'][report['dataset_id']]
    assert files == dataset['variants'].keys()
    assert index['resource_variants'].keys() == dataset['resources'].keys()
    for path, rows in index['resource_variants'].items():
        assert {r['file'] for r in rows} == dataset['resources'][path]['variants'].keys()
    matrices, totals = {}, Counter()
    for file, entry in dataset['variants'].items():
        raw = (catalog / file).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == entry['source']['catalog_sha256']
        source = json.loads(raw); matrix = read(folder / entry['file']); matrices[file] = matrix
        assert matrix['source'] == entry['source']
        assert matrix['widgets'] == {str(c['export']): c for c in source['controls']}
        assert matrix['slots'] == {str(s['provenance']['slot_export']): s for s in source.get('decoded_slots', [])}
        assert matrix['excluded_slots'] == source.get('excluded_slots', [])
        totals.update(variants=1, widgets=len(matrix['widgets']), slots=len(matrix['slots']), excluded_slots=len(matrix['excluded_slots']))
    assert dict(totals) == report['statistics']
    observations = 0
    for pid, prop in report['properties'].items():
        assert prop['field'], 'Empty field is not a property'
        assert pid == 'UI-23.P-' + hashlib.sha256(prop['key'].encode()).hexdigest()[:12]
        refs = read(folder / prop['occurrences']); assert len(refs) == prop['observations']
        types = set()
        for ref in refs:
            assert ref['scope'] == prop['scope'] and ref['field'] == prop['field']
            matrix = matrices[ref['variant']]
            if ref['scope'] == 'slot':
                value = matrix['slots'][str(ref['export'])]['decoded']
                assert value.get('parent', {}).get('type', 'unknown') == prop['owner']
            else:
                value = matrix['widgets'][str(ref['export'])]; assert value['type'] == prop['owner']
                if ref['scope'] != 'catalog_control':
                    value = value['container_geometry']['decoded']
                    if ref['scope'] != 'container_relation':
                        value = value[ref['scope']]
            for part in ref['field'].split('.'):
                value = value[part]
            types.add('null' if value is None else type(value).__name__)
        assert sorted(types) == prop['types']
        observations += len(refs)
    reverse, local = defaultdict(list), set()
    for relation in read(folder / report['relations']):
        file = relation['variant']; matrix = matrices[file]
        if relation['kind'] == 'local_slot':
            key = file, str(relation['slot']); assert key not in local; local.add(key)
            slot = matrix['slots'][key[1]]
            assert relation['parent'] == slot['decoded']['parent_export'] and relation['content'] == slot['decoded']['content_export']
            assert relation['source_sha256'] == slot['provenance'].get('sha256')
        elif relation['kind'] == 'nested_class_candidates':
            assert matrix['widgets'][str(relation['control'])]['type'] == relation['target_class']
            expected = sorted(f for f, entry in dataset['variants'].items() if entry['name'] + '_C' == relation['target_class'])
            assert relation['candidates'] == expected
            for candidate in expected:
                reverse[candidate].append(dict(variant=file, control=relation['control']))
        elif relation['kind'] == 'container_slot_order':
            assert relation['slots'] == matrix['widgets'][str(relation['control'])]['container_geometry']['decoded']['slots']
        else:
            raise AssertionError('Unknown relation type')
    assert len(local) == totals['slots']
    assert dict(reverse) == read(folder / 'reverse-components.json')
    return dict(state='passed', dataset=report['dataset_id'], properties=len(report['properties']),
        observations=observations, **dict(totals),
        limits='Decoded-catalog roundtrip and reference verification; not completeness of native UProperties or runtime behavior.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = verify(args.root, args.folder)
    if args.output:
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(result, ensure_ascii=False))
