"""Inventory existing client categories; no runtime availability or new joins inferred."""
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path('F:/PhoneExit Resources/Vampir')


def main(root=ROOT):
    sources = {}

    def read(relative):
        path = root / relative
        raw = path.read_bytes()
        sources[relative] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw.decode('utf-8-sig'))

    metadata = read('table-study/index-pakchunk1-Windows.json')
    tables = {t['entry']: t for t in metadata['tables']}
    native = read('code-clues/native-enums.json')
    dependencies = read('code-clues/table-dependencies.json')
    items = read('maps/loot/items.json')

    def rows(entry):
        table = tables[entry]
        path = root / 'table-study' / table['file']
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != table['sha256']:
            raise ValueError(f'CSV hash changed: {entry}')
        sources['table-study/' + table['file']] = digest
        with path.open(encoding='utf-8-sig', newline='') as stream:
            return list(csv.DictReader(stream))

    original = rows(194)
    if Counter(r['Type'] for r in original) != Counter(i['data']['Type'] for i in items.values()):
        raise ValueError('Item type counts differ from source CSV')

    def counts(records, field, enum):
        names = {str(v['value']): v['name'] for v in native['enums'].get(enum, [])}
        return [{'value': value, 'name': names.get(value), 'count': count}
                for value, count in Counter(r.get(field, '') for r in records).most_common()]

    selected = [18, 36, 51, 53, 73, 86, 87, 141, 144, 180, 200, 202, 205, 206, 1448, 1499, 1505]
    candidate_tables = []
    for entry in selected:
        records = rows(entry)
        candidate_tables.append({'entry': entry, 'file': tables[entry]['file'],
                                 'sha256': tables[entry]['sha256'], 'record_count': len(records),
                                 'header': tables[entry]['header'],
                                 'note': 'Header evidence; a semantic table name is not inferred here.'})
    reference_sheets = {}
    prefixes = ('Achievement', 'Artifact', 'Collection', 'CharacterCollection', 'Costume',
                'Dungeon', 'Elite', 'EventBoss', 'Follower', 'ItemCraft', 'LifeTree',
                'NpcFollower', 'Pet', 'Sephira', 'Shop', 'TileCollection', 'Tomb', 'Vehicle')
    for ref in dependencies['references']:
        for side in ('source', 'target'):
            table = ref.get(side, {})
            name = table.get('sheet', '')
            if name.startswith(prefixes):
                key = (table['workbook'], name)
                reference_sheets.setdefault(key, []).append(ref['offset'])

    report = {'sources': sources, 'client_exe_sha256': native['sha256'],
              'item_count': len(original),
              'item_types': counts(original, 'Type', 'EItemType'),
              'equipment_slots': counts([r for r in original if r['Type'] == '1'], 'EquipmentType', 'EEquipmentType'),
              'inventory_categories': counts(original, 'InventoryCategory', 'EInventoryCategory'),
              'skill_categories': counts(rows(1505), 'Category', 'ESkillCategory'),
              'quest_types': counts(rows(1448), 'Type', 'EQuestType'),
              'candidate_tables': candidate_tables,
              'named_reference_sheets': [{'workbook': book, 'sheet': sheet,
                                          'diagnostic_offsets': sorted(set(offsets))}
                                         for (book, sheet), offsets in sorted(reference_sheets.items())],
              'limitations': ['Counts are client records, not obtainable entities.',
                              'Item types are not full system definitions.',
                              'CSV header candidates are not newly verified native table bindings.',
                              'Rates, server schedules, shop availability and activation rules are not verified.']}
    out = root / 'maps' / 'catalog-category-study.json'
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'items': len(original), 'types': len(report['item_types']),
                      'tables_checked': len(selected), 'report': str(out)}, ensure_ascii=False))
    return report


if __name__ == '__main__':
    main()
