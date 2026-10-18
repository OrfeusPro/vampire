"""Class filters from explicit client fields; not a runtime eligibility check."""
import csv
import hashlib
import json
from pathlib import Path
from collections import Counter


def skill_classes(raw, known):
    tokens = [v.strip() for v in (raw or '').split(',') if v.strip()]
    if tokens == ['All']:
        return {'status': 'all', 'keys': [], 'raw': raw}
    if tokens and all(v in known for v in tokens):
        return {'status': 'specified', 'keys': sorted(set(tokens)), 'raw': raw}
    return {'status': 'unknown', 'keys': [], 'raw': raw or ''}


def book_classes(item_raw, skill, by_id):
    if item_raw and item_raw != '0':
        key = by_id.get(item_raw)
        if not key:
            return {'status': 'unknown', 'keys': []}
        if skill['status'] == 'specified' and key not in skill['keys']:
            return {'status': 'conflict', 'keys': []}
        return {'status': 'specified', 'keys': [key]}
    return {k: skill[k] for k in ('status', 'keys')}


def main(root=Path('F:/PhoneExit Resources/Vampir')):
    sources = {}

    def read(relative):
        data = (root / relative).read_bytes()
        sources[relative] = hashlib.sha256(data).hexdigest()
        return json.loads(data.decode('utf-8-sig'))

    metadata = {t['entry']: t for t in read('table-study/index-pakchunk1-Windows.json')['tables']}
    def rows(entry):
        meta = metadata[entry]
        path = root / 'table-study' / meta['file']
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != meta['sha256']:
            raise ValueError(f'Changed class CSV: {entry}')
        sources['table-study/' + meta['file']] = digest
        with path.open(encoding='utf-8-sig', newline='') as stream:
            return list(csv.DictReader(stream))

    native = read('code-clues/native-enums.json')
    enums = {str(v['value']): v['name'].split('::')[-1] for v in native['enums']['EClassType']}
    name_rows = rows(401)
    names = {r['Id']: r['Name'] for r in name_rows}
    name_lines = {r['Id']: line for line, r in enumerate(name_rows, 2)}
    classes, by_id = [], {}
    for line, row in enumerate(rows(36), 2):
        key = enums.get(row['Type'])
        if not key or key != row['Resource'] or row['Id'] in by_id:
            raise ValueError('Class.Type/Resource is not unambiguous')
        by_id[row['Id']] = key
        classes.append(dict(key=key, class_info_id=row['Id'], label=names.get(row['Id'], key),
                            raw_type=row['Type'], provenance=dict(entry=36, csv_record=line),
                            name_provenance=dict(entry=401, csv_record=name_lines.get(row['Id']))))
    known = {c['key'] for c in classes}
    skills = {r['Id']: dict(skill_classes(r['ClassType'], known), provenance=dict(entry=1505, csv_record=line))
              for line, r in enumerate(rows(1505), 2)}
    loot = read('maps/loot/index.json')
    items = read('maps/loot/' + loot['files']['items']['file'])
    details = read('maps/loot/' + loot['files']['item-details']['file'])
    for key in ('items', 'item-details'):
        if sources['maps/loot/' + loot['files'][key]['file']] != loot['files'][key]['sha256']:
            raise ValueError(f'Changed catalogue input: {key}')
    books = {}
    for item_id, book in details['skill_books'].items():
        raw = items[item_id]['data']['ClassInfoId']
        target = skills.get(book.get('skill_id')) if book.get('relation_verified') else None
        target = target or skill_classes('', known)
        books[item_id] = dict(book_classes(raw, target, by_id), item_class_info_id=raw,
                              skill_id=book.get('skill_id'), skill_class=target,
                              provenance=items[item_id]['data']['provenance'])
    result = dict(classes=classes, skills=skills, books=books, sources=sources,
                  client_exe_sha256=native['sha256'], runtime_eligibility_verified=False,
                  classification='Explicit Item.ClassInfoId, Class.Id/Type and Skill.ClassType field joins. Class names via ClassName-en Id; not a newly recovered native eligibility predicate.',
                  summary=dict(books=dict(Counter(b['status'] for b in books.values())),
                               skills=dict(Counter(s['status'] for s in skills.values()))))
    path = root / 'maps/catalog-classes.json'
    path.write_text(json.dumps(result, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
    (root / 'maps/catalog-classes-manifest.json').write_text(json.dumps(dict(file=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest())), encoding='utf-8')
    print(json.dumps(result['summary'], ensure_ascii=False))
    return result


if __name__ == '__main__':
    main()
