"""Build the collection catalogue from SHA-checked client CSV and native diagnostics."""
import csv
import hashlib
import io
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path('F:/PhoneExit Resources/Vampir')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unique(rows, key):
    result = {}
    for row in rows:
        if row[key] in result:
            raise ValueError('Duplicate '+key+': '+row[key])
        result[row[key]] = row
    return result


def display_name(template, row):
    for index in (1, 2):
        template = template.replace('{ReplaceString'+str(index)+'}', row['ReplaceString'+str(index)])
    return template.strip()


def main(root=ROOT):
    sources = {}

    def read(relative):
        path = root/relative
        sources[relative] = sha(path)
        return json.loads(path.read_text('utf-8-sig'))

    metadata = {t['entry']: t for t in read('table-study/index-pakchunk1-Windows.json')['tables']}

    def table(entry):
        meta = metadata[entry]
        relative = 'table-study/'+meta['file']
        path = root/relative
        if sha(path) != meta['sha256']:
            raise ValueError('Changed CSV '+str(entry))
        reader = csv.DictReader(io.StringIO(path.read_text('utf-8-sig')))
        if reader.fieldnames != meta['header']:
            raise ValueError('Changed CSV header '+str(entry))
        rows = [dict(row, provenance={'entry': entry, 'csv_record': i+2}) for i, row in enumerate(reader)]
        if len(rows) != meta['rows']:
            raise ValueError('Changed CSV count '+str(entry))
        sources[relative] = meta['sha256']
        return rows

    native = read('code-clues/native-enums.json')
    dependencies = read('code-clues/table-dependencies.json')
    executable = Path(native['source'])
    if sha(executable) != native['sha256'] or dependencies['sha256'] != native['sha256']:
        raise ValueError('Changed client EXE')
    raw = executable.read_bytes()
    diagnostics = []
    for sheet, field, target in [('Collection', 'GroupId', 'CollectionGroup'),
                                 ('CollectionGroup', 'OperationGroupId', 'StaticOperation'),
                                 ('CollectionGroup', 'DateTimeSetting', 'DateTimeSetting'),
                                 ('CollectionGroup', 'FixedTermId', 'FixedTermId')]:
        ref = next(r for r in dependencies['references'] if r['source']['sheet'] == sheet
                   and r['field'] == field and r['target']['sheet'] == target)
        encoded = ref['text'].encode('utf-16le')
        if raw[ref['offset']:ref['offset']+len(encoded)] != encoded:
            raise ValueError('Changed native diagnostic')
        diagnostics.append(ref)

    groups = unique(table(53), 'Id')
    requirements = table(51)
    tabs = unique(table(54), 'CollectionTabId')
    titles = unique(table(397), 'Id')
    names = unique(table(406), 'Id')
    operation_names = unique(table(486), 'OperationType')
    operation_display = unique(table(1427), 'OperationType')
    enums = {str(x['value']): x for x in native['enums']['EOperationType']}
    collection_types = {str(x['value']): x for x in native['enums']['ECollectionType']}
    item_type = next(k for k, v in collection_types.items() if v['name'] == 'ECollectionType::Item')
    operations = defaultdict(list)
    for row in table(1521):
        enum = enums.get(row['Type'])
        key = enum['name'].split('::')[-1] if enum else ''
        operations[row['GroupId']].append(dict(row=row, enum=enum,
            name=operation_names.get(key), display=operation_display.get(row['Type'])))
    items = read('maps/loot/items.json')
    members = defaultdict(list)
    used_items = {}
    for row in requirements:
        if row['GroupId'] not in groups:
            raise ValueError('Orphan Collection.GroupId '+row['GroupId'])
        item = items.get(row['CollectParam']) if row['CollectType'] == item_type else None
        members[row['GroupId']].append(dict(row=row, item_id=row['CollectParam'] if item else None,
                                          collect_type=collection_types.get(row['CollectType'])))
        if item:
            used_items[row['CollectParam']] = dict(id=row['CollectParam'],
                name=' / '.join(dict.fromkeys(n['Name'] for n in item['names_en'] if n['Name'])) or row['CollectParam'],
                rarity=item.get('rarity'), icon=item.get('icon'), provenance=item['data']['provenance'])
    rarities = {str(i['rarity']['id']): i['rarity'] for i in items.values() if i.get('rarity')}
    entries = []
    for gid, row in groups.items():
        entries.append(dict(id=gid, name=display_name(names[gid]['Name'], row) if gid in names else 'Коллекция '+gid,
            name_source=names.get(gid), row=row, rarity=rarities.get(row['Rarity']),
            requirements=members[gid], bonuses=operations[row['OperationGroupId']]))
    payload = dict(schema=1, entries=entries, items=used_items,
        tabs=[dict(id=k, name=titles.get(k, {}).get('CollectionTitle', 'Категория '+k), row=v,
                   name_source=titles.get(k)) for k, v in tabs.items()],
        statistics=dict(collections=len(entries), requirements=len(requirements), items=len(used_items),
            unresolved_items=sum(m['item_id'] is None for row in entries for m in row['requirements']),
            missing_bonuses=sum(not row['bonuses'] for row in entries),
            tabs=dict(Counter(r['CollectionTabId'] for r in groups.values()))))
    out = root/'maps/collections'
    out.mkdir(parents=True, exist_ok=True)
    data = out/'collections.json'
    data.write_text(json.dumps(payload, ensure_ascii=False, separators=(',', ':')), 'utf-8')
    manifest = dict(file='collections.json', sha256=sha(data), statistics=payload['statistics'],
        sources=sources, client_exe={'path': str(executable), 'sha256': native['sha256']}, diagnostics=diagnostics,
        joins=['CSV51.GroupId = CSV53.Id', 'CSV53.CollectionTabId = CSV54.CollectionTabId = CSV397.Id',
               'CSV53.Id = CSV406.Id', 'CSV51.CollectType = ECollectionType::Item (1) → CollectParam = Item.Id',
               'CSV53.OperationGroupId = StaticOperation.GroupId', 'StaticOperation.Type = EOperationType.value',
               'EOperationType.name suffix = CSV486.OperationType; StaticOperation.Type = CSV1427.OperationType'],
        limitations=['CSV roles are supported by unique schemas, exact joins and saved native diagnostics; not a new binary parser binding.',
                    'CollectParam polymorphic Item branch is resolved by enum and exact IDs; native dispatch not replayed.',
                    'Names replace only literal ReplaceString1/2 with same-row values; no runtime localization formatter replay.',
                    'Bonus values are raw client Min/Max; percentage scaling is not established.',
                    'DateTimeSetting, FixedTermId and service flags are retained, not evaluated as current availability.',
                    'Account completion, registration/consumption rules and live server availability are not read.'])
    (out/'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(payload['statistics'], ensure_ascii=False))
    return manifest


if __name__ == '__main__':
    main()
