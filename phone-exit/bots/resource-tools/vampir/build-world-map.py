"""Build one source-linked Nocturne scene, without merging worlds or inventing paths."""
import csv
import hashlib
import io
import importlib.util
import json
import math
import os
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
HERE = Path(__file__).resolve().parent
_area_spec=importlib.util.spec_from_file_location('world_area_math',HERE/'area-transform-math.py')
area_math=importlib.util.module_from_spec(_area_spec);_area_spec.loader.exec_module(area_math)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verified(path, expected):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Changed input: ' + str(path))
    return json.loads(raw)


def names(rows, column):
    result = defaultdict(list)
    for row in rows:
        if row[column] and row[column] not in result[row['Id']]:
            result[row['Id']].append(row[column])
    return dict(result)


def xy(row, x, y):
    try:
        result = [float(row[x]), float(row[y])]
        return result if all(math.isfinite(v) for v in result) else None
    except (KeyError, ValueError, TypeError):
        return None


def raw_box(row):
    """Read raw XY extents only. Do not guess a pivot for nonzero Yaw."""
    def pos(text):
        return area_math.vector(text)
    low, high = pos(row['AreaBoxMinPos']), pos(row['AreaBoxMaxPos'])
    if low is None or high is None or low[0] > high[0] or low[1] > high[1]:
        return None
    return [low, [high[0], low[1]], high, [low[0], high[1]]]


def scene(tables, scope, area_names, npc_names, npc_loot, loot_npcs,rotation_verified=False):
    world_ids = {w['id'] for w in scope}
    worlds = {w['Id']: w for w in tables['World'] if w['Id'] in world_ids}
    areas = {a['Id']: a for a in tables['Area'] if a['WorldInfoId'] in world_ids}
    spawns = [s for s in tables['NpcSpawn'] if s['WorldInfoId'] in world_ids]
    gadgets = {g['Id']: g for g in tables['GadgetSpawn'] if g['WorldInfoId'] in world_ids}
    definitions = {g['Id']: g for g in tables['Gadget']}
    npc_definitions = {n['Id']: n for n in tables['Npc']}
    spots = {s['Id']: s for s in tables['WorldSpot'] if s['WorldInfoId'] in world_ids}
    waypoints = {w['Id']: w for w in tables['Waypoint'] if w['GadgetSpawnInfoId'] in gadgets}
    by_gadget = defaultdict(list)
    for wp in waypoints.values():
        by_gadget[wp['GadgetSpawnInfoId']].append(wp['Id'])
    points, polygons, unplaced = [], [], []

    def add(kind, row, coordinate, label, **extra):
        key = kind + ':' + row['Id']
        item = dict(key=key, type=kind, id=row['Id'], world_id=row['WorldInfoId'],
                    label=label, provenance=row['provenance'], **extra)
        if coordinate is None:
            unplaced.append(dict(item, reason='No verified coordinate anchor'))
        else:
            item.update(x=coordinate[0], y=coordinate[1])
            points.append(item)
        return item

    world_data = []
    for w in scope:
        raw = worlds[w['id']]
        localized = [n for a in areas.values() if a['WorldInfoId'] == w['id']
                     for n in area_names.get(a['Id'], [])]
        label = ' / '.join(dict.fromkeys(localized)) or 'World ' + w['id']
        wd = dict(w, label=label, parent_world_id=raw['ParentWorldId'])
        if raw['WorldBoxQuadPosList']:
            vertices = json.loads(raw['WorldBoxQuadPosList'])['PosList']
            vertices = [xy(v, 'x', 'y') for v in vertices]
            if len(vertices) < 3 or any(v is None for v in vertices):
                raise ValueError('Invalid World polygon: ' + w['id'])
            polygons.append(dict(key='World:' + w['id'], type='World', id=w['id'],
                world_id=w['id'], vertices=vertices, label=label, provenance=raw['provenance']))
        world_data.append(wd)
    boxes_by_area = defaultdict(list)
    rotated, invalid_boxes = [], []
    for box in tables['AreaBox']:
        if box['WorldInfoId'] not in world_ids:
            continue
        vertices = raw_box(box)
        try:yaw=float(box['Yaw'] or '0')
        except ValueError:yaw=float('nan')
        if not math.isfinite(yaw):vertices=None
        if vertices is None:
            invalid_boxes.append(dict(record=box, reason='Invalid or inverted raw Min/Max; not silently reordered'))
            continue
        if yaw!=0:
            if not rotation_verified:
                rotated.append(box)
                continue
            vertices=area_math.vertices(vertices[0],vertices[2],yaw)
        boxes_by_area[box['AreaId']].append(vertices)
        polygons.append(dict(key='AreaBox:' + box['Id'], type='AreaBox', id=box['Id'],
            world_id=box['WorldInfoId'], area_id=box['AreaId'], vertices=vertices,
            label=' / '.join(area_names.get(box['AreaId'], [])), provenance=box['provenance'],
            yaw=yaw,rotation_verified=rotation_verified if yaw else True))
    for area in areas.values():
        coordinate = xy(area, 'MapIconX', 'MapIconY')
        anchor = 'MapIconXY'
        wp = waypoints.get(area['Waypoint'])
        if coordinate is None and wp:
            coordinate = xy(gadgets[wp['GadgetSpawnInfoId']], 'BasePosX', 'BasePosY')
            anchor = 'Waypoint→GadgetSpawn'
        if coordinate is None and boxes_by_area.get(area['Id']):
            vertices = [p for box in boxes_by_area[area['Id']] for p in box]
            coordinate = [(min(p[0] for p in vertices) + max(p[0] for p in vertices)) / 2,
                          (min(p[1] for p in vertices) + max(p[1] for p in vertices)) / 2]
            anchor = 'Label center of verified AreaBox geometry; not a destination'
        add('Area', area, coordinate, ' / '.join(area_names.get(area['Id'], [])) or 'Area ' + area['Id'],
            icon_id=area['MapIconId'], anchor=anchor, waypoint_id=area['Waypoint'])
    for spot in spots.values():
        add('WorldSpot', spot, xy(spot, 'PosX', 'PosY'), 'Spot ' + spot['Id'], icon_id=spot['MapIconId'])
    npcs = {}
    for row in spawns:
        nid = row['NpcInfoId']
        definition = npc_definitions.get(nid, {})
        labels = npc_names.get(nid, [])
        label = ' / '.join(labels) or definition.get('NameEN') or 'NPC ' + nid
        npcs[nid] = dict(id=nid, label=label, labels=labels, level=definition.get('Level'),
            icon_id=definition.get('MapIconId'), image_key=definition.get('Img'),
            loot=npc_loot.get(nid, []), reward=loot_npcs.get(nid),
            provenance=definition.get('provenance'))
        add('NpcSpawn', row, xy(row, 'PosX', 'PosY'), label, npc_id=nid,
            level=definition.get('Level'), icon_id=row['MapIconId'] or definition.get('MapIconId'),
            area_id=row['AreaInfoId'], radius=row['Radius'], loot_count=len(npc_loot.get(nid, [])))
    portal_links = []
    for g in gadgets.values():
        definition = definitions.get(g['GadgetInfoId'], {})
        wp_ids = by_gadget[g['Id']]
        kind = 'Waypoint' if wp_ids else 'GadgetSpawn'
        label = ('Портал · ' if wp_ids else '') + (definition.get('BPName') or 'Gadget ' + g['GadgetInfoId'])
        add(kind, g, xy(g, 'BasePosX', 'BasePosY'), label,
            gadget_id=g['GadgetInfoId'], icon_id=g['MapIconId'] or definition.get('MapIconId'),
            waypoint_ids=wp_ids, gadget_type=definition.get('Type'))
        for wid in wp_ids:
            wp = waypoints[wid]
            destination = next((s for s in tables['WorldSpot'] if s['Id'] == wp['TeleportSpot']), None)
            portal_links.append(dict(id=wid, source_key=kind + ':' + g['Id'],
                source_world_id=g['WorldInfoId'], destination=destination, record=wp,
                destination_on_atlas=bool(destination and destination['WorldInfoId'] in world_ids),
                relation='Waypoint.GadgetSpawnInfoId → GadgetSpawn.Id; Waypoint.TeleportSpot → WorldSpot.Id',
                walkable_path=False))
    quest_links = []
    task_names = names(tables['QuestTaskName_en'], 'TaskName')
    quest_names = names(tables['QuestName_en'], 'Name')
    for task in tables['QuestTask']:
        spot, area = spots.get(task['TargetSpotInfoId']), areas.get(task['AreaInfoId'])
        if not spot and not area:
            continue
        linked_worlds = sorted({r['WorldInfoId'] for r in [spot, area] if r})
        label = ' / '.join(quest_names.get(task['QuestInfoId'], [])) or 'Quest ' + task['QuestInfoId']
        relation = dict(id=task['Id'], quest_id=task['QuestInfoId'], label=label,
            task_label=' / '.join(task_names.get(task['Id'], [])), world_ids=linked_worlds,
            target_spot_id=task['TargetSpotInfoId'], target_area_id=task['AreaInfoId'],
            provenance=task['provenance'])
        quest_links.append(relation)
        if spot:
            add('QuestTask', dict(task, WorldInfoId=spot['WorldInfoId']), xy(spot, 'PosX', 'PosY'), label,
                quest_id=task['QuestInfoId'], target_spot_id=spot['Id'], task_label=relation['task_label'],
                area_id=task['AreaInfoId'], anchor='TargetSpotInfoId→WorldSpot')
        else:
            unplaced.append(dict(key='QuestTask:' + task['Id'], type='QuestTask', id=task['Id'],
                world_id=area['WorldInfoId'], label=label, provenance=task['provenance'],
                reason='Area relation exists; no exact target WorldSpot'))
    return dict(worlds=world_data, points=points, polygons=polygons, npcs=npcs,
        portal_links=portal_links, quest_links=quest_links, unplaced=unplaced,
        rotated_area_boxes=rotated, invalid_area_boxes=invalid_boxes)


def main(root=ROOT):
    out = root / 'maps/atlas'
    index = json.loads((out / 'index.json').read_text('utf-8'))
    spec = index['pixel_projection']
    if not spec:
        raise ValueError('Build and verify Nocturne projection first')
    projection = verified(out / spec['file'], spec['sha256'])
    tables = verified(out / 'tables.json', index['tables_sha256'])
    metadata = {t['entry']: t for t in json.loads((root / 'table-study/index-pakchunk1-Windows.json').read_text('utf-8'))['tables']}
    sources = {}
    def table(entry, required):
        meta = metadata[entry]
        raw = (root / 'table-study' / meta['file']).read_bytes()
        if hashlib.sha256(raw).hexdigest() != meta['sha256']:
            raise ValueError('Changed localization CSV')
        reader = csv.DictReader(io.StringIO(raw.decode('utf-8-sig'), newline=''))
        if reader.fieldnames != meta['header'] or not set(required) <= set(reader.fieldnames):
            raise ValueError('Changed localization schema')
        rows = list(reader)
        if len(rows) != meta['rows'] or any(None in r or None in r.values() for r in rows):
            raise ValueError('Changed localization records')
        sources[str(entry)] = meta
        return [dict(row, provenance=dict(entry=entry, csv_record=n + 2)) for n, row in enumerate(rows)]
    area_rows = table(385, ['Id', 'PlaceName'])
    npc_rows = table(481, ['Id', 'Name'])
    area_names = names(area_rows, 'PlaceName')
    npc_names = names(npc_rows, 'Name')
    loot_path = root / 'maps/loot'
    loot_index = json.loads((loot_path / 'index.json').read_text('utf-8'))
    origins = verified(loot_path / loot_index['files']['item-origins']['file'], loot_index['files']['item-origins']['sha256'])
    items = verified(loot_path / loot_index['files']['items']['file'], loot_index['files']['items']['sha256'])
    npc_loot = defaultdict(list)
    for item_id, chains in origins.items():
        for nid, count in Counter(c['npc_id'] for c in chains).items():
            npc_loot[nid].append(dict(item_id=item_id, chains=count))
    scope = [w for w in index['worlds'] if w['map_id'] in projection['map_ids']]
    # The scene references per-world records for on-demand detail display.
    for w in scope:
        verified(out / w['file'], w['sha256'])
    transform=area_math.validated_evidence(root,index['tables_sha256'])
    result = scene(tables, scope, area_names, npc_names, npc_loot, {n['id']: n for n in loot_index['npcs']},rotation_verified=transform is not None)
    if transform:result['area_transform_source']=transform
    area_ids = {r['Id'] for r in tables['Area'] if r['WorldInfoId'] in {w['id'] for w in scope}}
    result['localizations'] = dict(areas={iid: [r for r in area_rows if r['Id'] == iid] for iid in sorted(area_ids)},
        npcs={iid: [r for r in npc_rows if r['Id'] == iid] for iid in result['npcs']})
    images_path = root / 'archive-image-latest.json'
    images = json.loads(images_path.read_text('utf-8'))
    icon_keys = {r['Img'] for r in tables['MapIcon'] if r['Img']}
    selected_images = defaultdict(list)
    for image in images:
        key = image['asset_path'].rsplit('/', 1)[-1]
        if key in icon_keys:
            if sha(root / image['file']) != image['sha256']:
                raise ValueError('Changed map icon image')
            selected_images[key].append(image)
    result['icons'] = {r['Id']: dict(record=r, images=selected_images.get(r['Img'], [])) for r in tables['MapIcon']}
    result['items'] = {iid: dict(label=' / '.join(dict.fromkeys(n['Name'] for n in item['names_en'] if n['Name'])) or 'Предмет ' + iid,
        icon=item['icon'], rarity=item.get('rarity'), in_npc_reward=item['in_npc_reward'], provenance=item['data']['provenance'])
        for iid, item in items.items()}
    # Keep ambiguous paths visible. Never choose an unrelated basename candidate.
    result['item_npcs'] = {iid: sorted({c['npc_id'] for c in chains}) for iid, chains in origins.items()}
    result['projection'] = projection
    assembly = json.loads((root / 'maps/nocturne-world.json').read_text('utf-8'))
    if assembly['sha256'] != projection['atlas_sha256'] or sha(root / projection['atlas_image']) != assembly['sha256']:
        raise ValueError('Changed assembled map')
    result['background'] = dict(preview='maps/nocturne-preview.jpg',
        preview_sha256=sha(root / 'maps/nocturne-preview.jpg'), tiles=assembly['sources'])
    result['sources'] = dict(atlas_index_sha256=sha(out / 'index.json'), atlas_tables_sha256=index['tables_sha256'],
        projection_sha256=spec['sha256'], map_sources=index['sources'], localization=sources,
        loot_index_sha256=sha(loot_path / 'index.json'), loot_files=loot_index['files'],
        image_catalog_sha256=sha(images_path))
    result['stats'] = dict(worlds=len(scope), points=len(result['points']),
        point_types=dict(Counter(p['type'] for p in result['points'])),
        polygons=dict(Counter(p['type'] for p in result['polygons'])),
        npc_ids=len(result['npcs']), portal_relations=len(result['portal_links']),
        quest_relations=len(result['quest_links']), unplaced=len(result['unplaced']),
        rotated_area_boxes_source_only=len(result['rotated_area_boxes']),
        rotated_area_boxes_verified=sum(p['type']=='AreaBox' and bool(p.get('yaw')) and p.get('rotation_verified') for p in result['polygons']),
        invalid_area_boxes_source_only=len(result['invalid_area_boxes']),
        named_areas=sum(bool(area_names.get(a['Id'])) for a in tables['Area'] if a['WorldInfoId'] in {w['id'] for w in scope}))
    keys = [p['key'] for p in result['points']]
    if len(keys) != len(set(keys)):
        raise ValueError('Duplicate scene point keys')
    result.update(schema_version=1, navigation_ready=False, fresh_android_verified=False,
        limitations=['All36 source worlds are separate contexts; overlapping records are not simultaneous runtime spawns.',
            'Only Map10/11 share the proven Nocturne projection.',
            'AreaBox outlines use native-proven XY geometry only when matching transform evidence is available; outlines are not walkability.',
            'Quest area-only relations have no invented exact target point.',
            'Portal links show table destinations, not a walkable route or an evaluated activation condition.',
            'Raw rates remain raw; drop percentages unknown.'])
    import importlib.util
    readiness_spec=importlib.util.spec_from_file_location('map_readiness',HERE/'map-readiness.py')
    readiness=importlib.util.module_from_spec(readiness_spec);readiness_spec.loader.exec_module(readiness)
    result['geometry_audit']=readiness.main(root)
    lift_spec=importlib.util.spec_from_file_location('lift_map_preview',HERE/'build-lift-map-preview.py')
    lift_module=importlib.util.module_from_spec(lift_spec);lift_spec.loader.exec_module(lift_module)
    if (root/'maps/navigation-study/lift-blueprints/rotation-evidence.json').is_file():
        result['lift_preview']=lift_module.main(root)
    data_path = out / 'nocturne.json'
    if (root/'code-clues/recast-coordinate-evidence.json').is_file() and (root/'maps/navigation-study/geometry-hypothesis-97/grid-inventory.json').is_file():
        overlay_spec=importlib.util.spec_from_file_location('nav_map_overlay',HERE/'build-recast-map-overlay.py')
        overlay_module=importlib.util.module_from_spec(overlay_spec);overlay_spec.loader.exec_module(overlay_module)
        result['navigation_overlay']=overlay_module.main(root)
    data_path.write_text(json.dumps(result, ensure_ascii=False, separators=(',', ':')), 'utf-8')
    manifest = dict(file='nocturne.json', sha256=sha(data_path), stats=result['stats'], sources=result['sources'])
    (out / 'nocturne-manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), 'utf-8')
    # Preserve the previous per-world viewer, with all the existing links intact.
    (out / 'world.html').write_text((HERE / 'map-atlas.html').read_text('utf-8'), 'utf-8')
    for source, target in [('world-map.html', 'index.html'), ('world-map.js', 'world-map.js'), ('world-map-model.js', 'world-map-model.js'),('nav-overlay-model.js','nav-overlay-model.js')]:
        path = HERE / source
        if path.is_file():
            (out / target).write_text(path.read_text('utf-8'), 'utf-8')
    detail_builder = HERE / 'build-monster-details.py'
    if detail_builder.is_file():
        import importlib.util
        spec = importlib.util.spec_from_file_location('monster_detail_builder', detail_builder)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.main(root)
    import runpy
    runpy.run_path(str(HERE/'build-catalog-pages.py'))['main'](root)
    print(json.dumps(dict(stats=result['stats'], scene_bytes=data_path.stat().st_size, output=str(data_path)), ensure_ascii=False))
    return result


if __name__ == '__main__':
    main()
