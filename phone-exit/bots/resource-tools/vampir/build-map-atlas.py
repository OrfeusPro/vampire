"""Build a source-linked geographical atlas. Does not issue game commands.

Raw client values are preserved. Reviewed optional projection, no walk edges.
"""
import argparse
import csv
import hashlib
import io
import json
import os
from collections import defaultdict
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
SPECS = {
    'World': (1568, ['Id', 'MapId', 'LevelPath', 'StartSpotInfoId']),
    'Map': (1394, ['Id', 'MapResource', 'GroundDistance', 'CenterX', 'CenterY']),
    'WorldSpot': (1573, ['Id', 'WorldInfoId', 'PosX', 'PosY', 'PosZ']),
    'Area': (9, ['Id', 'WorldInfoId', 'Waypoint', 'TeleportSpot']),
    'AreaBox': (10, ['Id', 'WorldInfoId', 'AreaId', 'AreaBoxMinPos', 'AreaBoxMaxPos']),
    'Waypoint': (1566, ['Id', 'GadgetSpawnInfoId', 'TeleportSpot', 'CostValue']),
    'NpcSpawn': (1546, ['Id', 'WorldInfoId', 'NpcInfoId', 'PositionGroupId', 'PosX', 'PosY']),
    'Npc': (1544, ['Id', 'NameEN', 'Level', 'Type']),
    'GadgetSpawn': (1542, ['Id', 'WorldInfoId', 'GadgetInfoId', 'BasePosX', 'BasePosY']),
    'Gadget': (1541, ['Id', 'Type', 'UseableContentsLock']),
    'QuestTask': (1454, ['Id', 'QuestInfoId', 'TargetSpotInfoId', 'AreaInfoId']),
    'QuestName_en': (498, ['Id', 'Name', 'DescObjective']),
    'QuestTaskName_en': (502, ['Id', 'TaskName']),
    'WorldType': (1574, ['Type', 'LockOpenMap', 'PossibleMoveTown']),
    'MapIcon': (1570, ['Id', 'Img', 'LayerGroupId']),
    'MapIconLayer': (1571, ['Id', 'GroupId', 'ZoomLevel', 'Show']),
    'NavigationTestCase': (1576, ['caseKey', 'worldInfoId', 'navFileName', 'sx', 'sy', 'ex', 'ey']),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load_table(root, meta, required, name):
    data = (root / 'table-study' / meta['file']).read_bytes()
    if sha(data) != meta['sha256']:
        raise ValueError('Changed CSV: ' + meta['file'])
    reader = csv.DictReader(io.StringIO(data.decode('utf-8-sig'), newline=''))
    if reader.fieldnames != meta['header'] or not set(required) <= set(reader.fieldnames):
        raise ValueError('Changed schema: ' + name)
    rows = list(reader)
    if len(rows) != meta['rows'] or any(None in r or None in r.values() for r in rows):
        raise ValueError('Changed row structure: ' + name)
    key = 'caseKey' if name == 'NavigationTestCase' else 'Type' if name == 'WorldType' else 'Id'
    if not name.endswith('_en') and len({r[key] for r in rows}) != len(rows):
        raise ValueError('Duplicate key: ' + name)
    return [dict(r, provenance=dict(table=name, entry=meta['entry'], csv_record=i + 2))
            for i, r in enumerate(rows)]


def image_group(row):
    prefix = '/Game/RED/UI/Resource/Texture/Map/'
    path = row['asset_path']
    if not path.startswith(prefix):
        raise ValueError('Unexpected map image path: ' + path)
    parts = path[len(prefix):].split('/')
    return parts[0], '/'.join(parts[1:-1])


def group(rows, field):
    result = defaultdict(list)
    for row in rows:
        result[row[field]].append(row)
    return result


def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')


def build(root):
    index_path = root / 'table-study/index-pakchunk1-Windows.json'
    metadata = {t['entry']: t for t in json.loads(index_path.read_text('utf-8'))['tables']}
    tables, sources = {}, {}
    for name, (entry, fields) in SPECS.items():
        tables[name] = load_table(root, metadata[entry], fields, name)
        sources[name] = metadata[entry]
    catalog_path = root / 'map-image-catalog.json'
    images = json.loads(catalog_path.read_text('utf-8'))
    assembly = json.loads((root / 'maps/nocturne-world.json').read_text('utf-8'))
    if file_sha(root / 'maps' / assembly['image']) != assembly['sha256']:
        raise ValueError('Changed assembled Nocturne PNG')
    selected = {r['asset_path']: r for r in images}
    for tile in assembly['sources']:
        if selected.get(tile['asset_path'], {}).get('sha256') != tile['sha256']:
            raise ValueError('Nocturne assembly uses outdated tiles')
    image_groups = defaultdict(list)
    for row in images:
        if sha((root / row['file']).read_bytes()) != row['sha256']:
            raise ValueError('Changed map PNG: ' + row['file'])
        kind, resource = image_group(row)
        image_groups[resource].append(dict(row, kind=kind))

    maps = {r['Id']: r for r in tables['Map']}
    spots = {r['Id']: r for r in tables['WorldSpot']}
    areas = {r['Id']: r for r in tables['Area']}
    waypoints = {r['Id']: r for r in tables['Waypoint']}
    npcs = {r['Id']: r for r in tables['Npc']}
    gadgets = {r['Id']: r for r in tables['Gadget']}
    # Localization has repeated IDs in the client snapshot. Preserve all variants.
    quests = group(tables['QuestName_en'], 'Id')
    tasknames = group(tables['QuestTaskName_en'], 'Id')
    rules = {r['Type']: r for r in tables['WorldType']}
    worlds = {r['Id']: r for r in tables['World']}
    issues = []

    def resolve(row, field, target, target_name):
        value = row[field]
        if value in ('', '0'):
            return None
        result = target.get(value)
        if result is None:
            issues.append(dict(source=row['provenance'], field=field, value=value,
                               target=target_name, status='missing_reference'))
        return result

    sections = {}
    for name in ['WorldSpot', 'Area', 'AreaBox', 'NpcSpawn', 'GadgetSpawn', 'NavigationTestCase']:
        field = 'worldInfoId' if name == 'NavigationTestCase' else 'WorldInfoId'
        sections[name] = group(tables[name], field)
        for row in tables[name]:
            resolve(row, field, worlds, 'World')

    tasks_by_world = defaultdict(list)
    for task in tables['QuestTask']:
        spot = resolve(task, 'TargetSpotInfoId', spots, 'WorldSpot')
        area = resolve(task, 'AreaInfoId', areas, 'Area')
        for wid in sorted({r['WorldInfoId'] for r in [spot, area] if r}):
            tasks_by_world[wid].append(dict(task, target_spot=spot, target_area=area,
                quest_names_en=quests.get(task['QuestInfoId'], []), task_names_en=tasknames.get(task['Id'], [])))

    out = root / 'maps/atlas'
    (out / 'worlds').mkdir(parents=True, exist_ok=True)
    map_entries = []
    for mid, row in maps.items():
        resource = row['MapResource']
        exact = image_groups.get(resource, [])
        candidates = sorted(k for k in image_groups if k != resource and k.casefold() == resource.casefold())
        map_entries.append(dict(data=row, images=exact, case_only_candidates=candidates,
                                pixel_projection=None, android_verified=False))
        if not exact:
            issues.append(dict(source=row['provenance'], field='MapResource', value=resource,
                               status='missing_exact_image_group', case_only_candidates=candidates))
    summaries = []
    for wid, world in worlds.items():
        maprow = resolve(world, 'MapId', maps, 'Map')
        data = dict(world=world, map=maprow, world_type=rules.get(world['Type']),
                    start_spot=resolve(world, 'StartSpotInfoId', spots, 'WorldSpot'),
                    **{name: items.get(wid, []) for name, items in sections.items()},
                    QuestTask=tasks_by_world.get(wid, []))
        for area in data['Area']:
            resolve(area, 'TeleportSpot', spots, 'WorldSpot')
            resolve(area, 'Waypoint', waypoints, 'Waypoint')
        for spawn in data['NpcSpawn']:
            resolve(spawn, 'NpcInfoId', npcs, 'Npc')
        for spawn in data['GadgetSpawn']:
            resolve(spawn, 'GadgetInfoId', gadgets, 'Gadget')
        wp_ids = {r['Waypoint'] for r in data['Area']}
        spawn_ids = {r['Id'] for r in data['GadgetSpawn']}
        data['Waypoint'] = [dict(r, destination=resolve(r, 'TeleportSpot', spots, 'WorldSpot'))
                            for r in tables['Waypoint'] if r['Id'] in wp_ids or r['GadgetSpawnInfoId'] in spawn_ids]
        data['Npc'] = {r['NpcInfoId']: npcs[r['NpcInfoId']] for r in data['NpcSpawn'] if r['NpcInfoId'] in npcs}
        data['Gadget'] = {r['GadgetInfoId']: gadgets[r['GadgetInfoId']] for r in data['GadgetSpawn'] if r['GadgetInfoId'] in gadgets}
        file = 'worlds/' + wid + '.json'
        dump(out / file, data)
        summaries.append(dict(id=wid, level_path=world['LevelPath'], map_id=world['MapId'],
            resource=maprow['MapResource'] if maprow else None, type=world['Type'], test=world['IsTestWorld'],
            file=file, sha256=sha((out / file).read_bytes()),
            counts={name: len(data[name]) for name in [*sections, 'Waypoint', 'QuestTask']}))
    # Keep raw tables, including records which have no resolved world association.
    dump(out / 'tables.json', tables)
    deps_path = root / 'code-clues/table-dependencies.json'
    deps = json.loads(deps_path.read_text('utf-8'))
    if file_sha(Path(deps['source'])) != deps['sha256']:
        raise ValueError('Changed EXE for native table declarations')
    relevant = set(SPECS)
    declarations = [r for r in deps['references'] if r['source']['sheet'] in relevant and r['target']['sheet'] in relevant]
    report = dict(schema_version=1, sources=sources, table_index_sha256=sha(index_path.read_bytes()),
        tables_sha256=sha((out / 'tables.json').read_bytes()),
        assembled_images=[dict(assembly, file='maps/' + assembly['image'], kind='Атлас',
                               resource='Field/Nocturne', asset_path='Nocturne · собранная карта (25 плиток)',
                               width=assembly['size'][0], height=assembly['size'][1],
                               source='maps/nocturne-world.json')],
        image_catalog_sha256=sha(catalog_path.read_bytes()),
        native_declarations=dict(source=deps['source'], sha256=deps['sha256'], references=declarations),
        maps=map_entries, worlds=summaries, issues=issues,
        counts={name: len(rows) for name, rows in tables.items()}, image_count=len(images),
        unassigned_images=[r for r in images if image_group(r)[1] not in {m['MapResource'] for m in maps.values()}],
        navigation_ready=False, pixel_projection=None,
        limitations=[
            'Windows cooked client snapshot; Android equivalence unverified.',
            'Exact MapId/Id and resource parent-path joins are structural data links; map loader not recovered.',
            'World XYZ preserved. GroundDistance/Center do not prove world-to-pixel projection.',
            'NpcSpawn rows can use PositionGroupId; base position is not guaranteed to be actual spawn position.',
            'Server/quest/visibility/activation/cost fields preserved, not evaluated.',
            'NavigationTestCase contains inputs, not successful paths or walkable edges.',
            'World/ParentWorldId, start spots and waypoints do not establish a walk graph.',
        ])
    projection_path = out / 'projection.json'
    if projection_path.is_file():
        projection = json.loads(projection_path.read_text('utf-8'))
        if (projection['atlas_sha256'] != assembly['sha256']
                or projection['tables_sha256'] != report['tables_sha256']
                or projection['map_csv_sha256'] != sources['Map']['sha256']):
            raise ValueError('Projection sources changed: rebuild map projection')
        evidence = out / projection['native_evidence']['file']
        if file_sha(evidence) != projection['native_evidence']['sha256']:
            raise ValueError('Projection native evidence changed')
        if json.loads(evidence.read_text('utf-8'))['sha256'] != deps['sha256']:
            raise ValueError('Projection and atlas use different client executables')
        if file_sha(out / 'screenshot-study/index.json') != projection['screenshot_check']['registration_sha256']:
            raise ValueError('Projection screenshot registration changed: rebuild map projection')
        report['pixel_projection'] = dict(file='projection.json', sha256=file_sha(projection_path),
                                          map_ids=projection['map_ids'])
        for entry in map_entries:
            if entry['data']['Id'] in projection['map_ids']:
                if entry['data'] not in projection['map_records']:
                    raise ValueError('Projection Map record changed')
                entry['pixel_projection'] = report['pixel_projection']
        report['limitations'][1:3] = [
            'Nocturne Map10/11 static map math recovered and checked against seven icon regions in one historical frame; fresh Android and other maps unverified.'
        ]
    dump(out / 'index.json', report)
    viewer = Path(__file__).with_name('map-atlas.html').read_text('utf-8')
    study_path = out / 'screenshot-study/index.json'
    if study_path.is_file():
        from PIL import Image
        study = json.loads(study_path.read_text('utf-8'))
        if study['atlas_sha256'] != assembly['sha256']:
            raise ValueError('Screenshot registration references an old atlas')
        views = [('screenshot-study/coverage.jpg', 'Покрытие карты по скринам')]
        for frame in study['frames']:
            views += [('screenshot-study/' + frame['patch'], 'Совмещённый фрагмент скрина'),
                      ('screenshot-study/' + frame['comparison'], 'Сравнение скрина с большой картой')]
        for relative, label in views:
            with Image.open(out / relative) as preview:
                width, height = preview.size
            report['assembled_images'].append(dict(file='maps/atlas/' + relative,
                resource='Field/Nocturne', asset_path=label, kind='Скриншоты', width=width, height=height,
                sha256=file_sha(out / relative), source='maps/atlas/screenshot-study/index.json'))
        report['screenshot_registration'] = dict(file='screenshot-study/index.json',
            sha256=file_sha(study_path), frames=len(study['frames']), world_xy_verified=False)
    dump(out / 'index.json', report)
    (out / 'index.html').write_text(viewer, encoding='utf-8')
    # A verified Nocturne scene is the main view; retain this per-world viewer as world.html.
    scene_builder = Path(__file__).with_name('build-world-map.py')
    if projection_path.is_file() and scene_builder.is_file() and Path(__file__).with_name('world-map.js').is_file():
        import importlib.util
        spec = importlib.util.spec_from_file_location('world_map_builder', scene_builder)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.main(root)
    print(json.dumps(dict(counts=report['counts'], images=len(images), worlds=len(summaries),
                          issues=len(issues), index=str(out / 'index.json')), ensure_ascii=False))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    build(parser.parse_args().root)
