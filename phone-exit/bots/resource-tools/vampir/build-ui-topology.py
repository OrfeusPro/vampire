"""Recover sibling order from a uniquely matching serialized slot array.

Does not invent panel geometry, visibility or an active switcher child.
"""
import hashlib
import json
import os
import struct
from collections import defaultdict
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))


def slot_array(data, expected):
    if not expected or len(expected) != len(set(expected)):
        raise ValueError('Expected unique nonempty slot references')
    hits = []
    count = len(expected)
    for offset in range(max(0, len(data) - 3)):
        size = struct.unpack_from('<i', data, offset)[0]
        if size != count or offset + 4 + count * 4 > len(data):
            continue
        values = list(struct.unpack_from('<' + 'i' * count, data, offset + 4))
        if len(set(values)) == count and set(values) == set(expected):
            hits.append(dict(offset=offset, ordered_slots=values))
    return hits


def main():
    geometry = ROOT / 'ui-geometry'
    records = []
    for name in ('canvas-slots.json', 'panel-slots.json'):
        records += json.loads((geometry / name).read_text(encoding='utf-8'))['slots']
    groups = defaultdict(list)
    for record in records:
        groups[(record['provenance']['file'], record['decoded']['parent_export'])].append(record)
    packages, resolved, unresolved = {}, [], []
    for (filename, parent_id), slots in groups.items():
        if filename not in packages:
            report = json.loads((ROOT / 'ui-layout-study' / filename).read_text(encoding='utf-8'))
            body = (ROOT / 'ui-layout-study' / filename.replace('.json', '.uexp')).read_bytes()
            header_size = (ROOT / 'ui-layout-study' / filename.replace('.json', '.uasset')).stat().st_size
            if hashlib.sha256(body).hexdigest() != report['body_sha256']:
                raise ValueError('Changed widget body: ' + filename)
            packages[filename] = (report, body, header_size)
        report, body, header_size = packages[filename]
        export = next(e for e in report['exports'] if e['index'] == parent_id)
        start = export['offset'] - header_size
        raw = body[start:start + export['size']]
        if hashlib.sha256(raw).hexdigest() != export['sha256']:
            raise ValueError('Changed parent export')
        by_id = {s['provenance']['slot_export']: s for s in slots}
        candidates = slot_array(raw, list(by_id))
        provenance = dict(file=filename, parent_export=parent_id, export_offset=export['offset'],
                          export_sha256=export['sha256'], source=report['source'], entry=report['entry'])
        if len(candidates) != 1:
            unresolved.append(dict(provenance=provenance, matches=len(candidates), slots=list(by_id)))
            continue
        match = candidates[0]
        resolved.append(dict(provenance=provenance, parent=dict(index=parent_id, name=export['name'], type=export['type']),
                             array_relative_offset=match['offset'],
                             children=[dict(slot=slot, content=by_id[slot]['decoded']['content'],
                                            slot_geometry=by_id[slot]['decoded']) for slot in match['ordered_slots']]))
    result = dict(parents=resolved, unresolved=unresolved, absolute_geometry_verified=False,
                  limitations=['Order proved by unique count-and-reference array match',
                               'Only decoded slot classes included; missing links are explicit',
                               'No runtime visibility, desired sizes, DPI or animation resolved'])
    (geometry / 'topology.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(parents=len(resolved), unresolved=len(unresolved), children=sum(len(r['children']) for r in resolved))))


if __name__ == '__main__':
    main()
