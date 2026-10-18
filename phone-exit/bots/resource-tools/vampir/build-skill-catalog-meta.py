"""Compact skill presentation from exact CSV fields and verified book targets."""
import csv
import hashlib
import importlib.util
import json
from pathlib import Path


def book_presentations(book_rows, skill_rows, skill_meta, resolved):
    """Expose only verified targets; matching candidate IDs are not enough."""
    result = {}
    for item_id, book in book_rows.items():
        sid = book.get('skill_id')
        row = skill_rows.get(sid)
        linked = book.get('relation_verified') is True and row is not None
        target = None
        if linked:
            target = dict(id=sid,
                display_names=[dict(text=n['Name'], provenance=n.get('provenance'))
                    for n in book.get('skill_names_en', []) if n.get('Id') == sid and n.get('Name')],
                images={field: resolved.get(row[field], dict(key='', status='not_declared', images=[]))
                    for field in ('Img', 'ImgBg')},
                provenance=skill_meta[sid]['provenance'])
        result[item_id] = dict(relation_verified=linked, target=target,
            kind=skill_meta[sid]['kind'] if linked else 'unknown',
            kind_evidence=skill_meta[sid]['kind_evidence'] if linked else [],
            item_provenance=book.get('record', {}).get('provenance'),
            acquisition_verified=False)
    return result


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
        skill_rows = list(csv.DictReader(stream))
        skills = {row['Id']: dict(category=row['Category'], type_raw=row['Type'],
            rarity_raw=row['Rarity'], class_raw=row['ClassType'],
            provenance=dict(entry=1505, csv_record=line), kind='unknown', kind_evidence=[])
            for line, row in enumerate(skill_rows, 2)}
    skill_rows = {row['Id']: row for row in skill_rows}
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
    keys = {skill_rows[b['skill_id']][field]
        for b in details['skill_books'].values()
        if b.get('relation_verified') is True and b.get('skill_id') in skill_rows
        for field in ('Img', 'ImgBg') if skill_rows[b['skill_id']][field]}
    image_rows = read('archive-image-latest.json')
    by_name = {key: [] for key in keys}
    for image in image_rows:
        key = image['asset_path'].rsplit('/', 1)[-1]
        if key in by_name:
            by_name[key].append(image)
    resolver_path = Path(__file__).with_name('build-npc-loot.py')
    resolver_spec = importlib.util.spec_from_file_location('book_skill_icon_resolver', resolver_path)
    resolver = importlib.util.module_from_spec(resolver_spec)
    resolver_spec.loader.exec_module(resolver)
    resolved = {key: resolver.resolve_icon(key, images) for key, images in by_name.items()}
    checked = set()
    for value in resolved.values():
        for image in value['images']:
            if image['file'] not in checked:
                if hashlib.sha256((root / image['file']).read_bytes()).hexdigest() != image['sha256']:
                    raise ValueError('Changed book skill image: ' + image['file'])
                checked.add(image['file'])
    books = book_presentations(details['skill_books'], skill_rows, skills, resolved)
    result = dict(skills=skills, books=books, sources=sources,
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
