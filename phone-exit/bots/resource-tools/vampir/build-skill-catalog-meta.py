"""Compact skill presentation from exact CSV fields and verified book targets."""
import csv
import hashlib
import json
from pathlib import Path


def main(root=Path('F:/PhoneExit Resources/Vampir')):
    sources = {}

    def read(file, expected=None):
        raw = (root / file).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if expected and digest != expected:
            raise ValueError('Changed source: ' + file)
        sources[file] = digest
        return json.loads(raw.decode('utf-8-sig'))

    metadata = read('table-study/index-pakchunk1-Windows.json')
    spec = next(t for t in metadata['tables'] if t['entry'] == 1505)
    path = 'table-study/' + spec['file']
    raw = (root / path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != spec['sha256']:
        raise ValueError('Changed Skill CSV')
    sources[path] = spec['sha256']
    with (root / path).open(encoding='utf-8-sig', newline='') as stream:
        skills = {row['Id']: dict(category=row['Category'], type_raw=row['Type'],
            rarity_raw=row['Rarity'], class_raw=row['ClassType'],
            provenance=dict(entry=1505, csv_record=line), kind='unknown', kind_evidence=[])
            for line, row in enumerate(csv.DictReader(stream), 2)}
    loot = read('maps/loot/index.json')
    items = read('maps/loot/' + loot['files']['items']['file'], loot['files']['items']['sha256'])
    details = read('maps/loot/' + loot['files']['item-details']['file'], loot['files']['item-details']['sha256'])
    for item_id, book in details['skill_books'].items():
        if not book.get('relation_verified') or book.get('skill_id') not in skills:
            continue
        skill = skills[book['skill_id']]
        for name in items[item_id].get('names_en', []):
            for marker, kind in [('[Active]', 'active'), ('[Passive]', 'passive')]:
                if marker in name.get('Desc', ''):
                    skill['kind_evidence'].append(dict(item_id=item_id, marker=marker,
                        name_provenance=name.get('provenance'), item_provenance=items[item_id]['data']['provenance']))
    for skill in skills.values():
        kinds = {e['marker'] for e in skill['kind_evidence']}
        skill['kind'] = ('active' if kinds == {'[Active]'} else
                         'passive' if kinds == {'[Passive]'} else 'unknown')
    result = dict(skills=skills, sources=sources,
        limitations=['Kind comes only from explicit book description markers through verified book targets.',
                     'Skill.Type is preserved raw; no enum binding is inferred from matching numeric values.',
                     'Class and rarity are template fields, not account progress or runtime eligibility.'])
    path = root / 'maps/skill-catalog-meta.json'
    path.write_text(json.dumps(result, ensure_ascii=False, separators=(',', ':')), 'utf-8')
    manifest = dict(file=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    (path.parent / 'skill-catalog-meta-manifest.json').write_text(json.dumps(manifest), 'utf-8')
    print('Skill presentation:', len(skills), 'rows')
    return result


if __name__ == '__main__':
    main()
