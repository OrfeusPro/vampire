"""Audit cooked *Slot export candidates without guessing their property schema or role."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('slot_source_exports', HERE / 'inspect-ui.py')
source_reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source_reader)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def coverage(exports, catalog):
    slots = {e['index']: e for e in exports if e['type'].endswith('Slot')}
    if len(slots) != sum(e['type'].endswith('Slot') for e in exports):
        raise ValueError('Duplicate source slot')
    accounted, rows = set(), []
    for field, state in [('decoded_slots', 'decoded'), ('excluded_slots', 'rejected')]:
        for row in catalog[field]:
            proof = row['provenance']; key = proof['slot_export']
            if key not in slots or key in accounted:
                raise ValueError('Unknown or duplicate catalog slot')
            raw = slots[key]
            if (proof.get('slot_type', 'CanvasPanelSlot'), proof['sha256'], proof['offset']) != (raw['type'], raw['sha256'], raw['offset']):
                raise ValueError('Catalog slot source mismatch')
            accounted.add(key)
            rows.append(dict(export=key, kind=raw['type'], status=state, sha256=raw['sha256']))
    for key in sorted(slots.keys() - accounted):
        raw = slots[key]
        rows.append(dict(export=key, name=raw['name'], kind=raw['type'], status='unaccounted',
                         offset=raw['offset'], size=raw['size'], sha256=raw['sha256']))
    return sorted(rows, key=lambda row: row['export'])


def audit(root):
    index_bytes = (root / 'ui-catalog/index.json').read_bytes()
    records, totals, missing_types = [], Counter(), Counter()
    for entry in json.loads(index_bytes)['windows']:
        file = entry['file']
        catalog_bytes = (root / 'ui-catalog' / file).read_bytes()
        catalog = json.loads(catalog_bytes)
        source_file = entry.get('source_file', file)
        base = root / 'ui-layout-study' / source_file.removesuffix('.json')
        asset, body = base.with_suffix('.uasset').read_bytes(), base.with_suffix('.uexp').read_bytes()
        if sha(asset) != catalog['asset_sha256'] or sha(body) != catalog['body_sha256']:
            raise ValueError('Changed cooked source: ' + file)
        decoded = source_reader.exports(asset, body)
        rows = coverage(decoded['exports'], catalog)
        counts = Counter(row['status'] for row in rows)
        totals.update(counts); totals['variants'] += 1
        missing = [row for row in rows if row['status'] == 'unaccounted']
        missing_types.update(row['kind'] for row in missing)
        records.append(dict(file=file, source_file=source_file, resource=catalog['name'], catalog_sha256=sha(catalog_bytes),
                            asset_sha256=sha(asset), body_sha256=sha(body), counts=dict(counts),
                            unaccounted=missing))
    return dict(schema=1, kind='cooked_slot_coverage', index_sha256=sha(index_bytes),
                tool_sha256=sha(Path(__file__).read_bytes()), reader_sha256=sha((HERE/'inspect-ui.py').read_bytes()),
                totals=dict(totals), unaccounted_types=dict(missing_types), variants=records,
                limits=['Historical cooked source accounting only; no current client compatibility established.',
                        'Suffix candidates include NamedSlot widgets; totals are not a count of proven layout slots.',
                        'Each catalog variant is counted separately, including multiple roots from one package.',
                        'Decoded does not prove schema semantics, sibling order, DPI, visibility or runtime placement.',
                        'Unaccounted slots remain unknown; no guessed row/column or inherited fields applied.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.root)
    with args.output.open('x', encoding='utf8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
    print(json.dumps(dict(output=str(args.output), totals=result['totals'], unaccounted_types=result['unaccounted_types'])))
