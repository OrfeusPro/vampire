"""Index existing quest/NPC data and table schemas for UI analysis, without executing actions."""
import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def quest_graph(data):
    nodes, edges = {}, []
    def node(kind, row, key='Id', omit=()):
        identity = kind + ':' + str(row[key])
        value = dict(kind=kind, id=str(row[key]), fields={k: v for k, v in row.items() if k not in omit})
        if identity in nodes and nodes[identity] != value:
            raise ValueError('Конфликт ID в одном наборе: ' + identity)
        nodes[identity] = value; return identity
    def edge(source, target, field, status='static_table_reference_not_runtime'):
        edges.append(dict(source=source, target=target, field=field, status=status))
    quest_ids = {str(q['Id']) for q in data['quests']}
    for q in data['quests']:
        qid = node('Quest', q, omit=('tasks',))
        for token in q.get('previous_id_tokens', []):
            edge(qid, 'Quest:' + str(token), 'PreQuestId', 'token_only_branch_semantics_unknown' if str(token) in quest_ids else 'unresolved_previous_token')
        for task in q['tasks']:
            if str(task['QuestInfoId']) != str(q['Id']):
                raise ValueError('QuestTask принадлежит другому QuestInfoId')
            tid = node('QuestTask', task, omit=('actions', 'world_spot', 'tutorial'))
            edge(tid, qid, 'QuestInfoId')
            spot = task.get('world_spot')
            if spot:
                if str(spot['Id']) != str(task['TargetSpotInfoId']):
                    raise ValueError('WorldSpot не соответствует TargetSpotInfoId')
                edge(tid, node('WorldSpot', spot), 'TargetSpotInfoId')
            for action in task['actions']:
                if str(action['TaskId']) != str(task['Id']):
                    raise ValueError('QuestTaskAction принадлежит другому TaskId')
                edge(node('QuestTaskAction', action), tid, 'TaskId')
    for tutorial in data.get('tutorials', []):
        parent = node('Tutorial', tutorial, omit=('steps',))
        for step in tutorial['steps']:
            if str(step['TutorialId']) != str(tutorial['Id']):
                raise ValueError('TutorialStep принадлежит другому TutorialId')
            sid = node('TutorialStep', step, omit=('ui',)); edge(sid, parent, 'TutorialId')
            if step.get('ui'):
                edge(sid, node('TutorialUI', step['ui'], 'Key'), 'ui', 'prior_catalog_link_not_current_ui_action')
    for control in data.get('controls', []):
        node('TutorialUI', control, 'Key')
    return nodes, edges


def npc_graph(npc_id, detail):
    npc = detail['npc']
    if str(detail['npc_id']) != str(npc_id) or str(npc['Id']) != str(npc_id):
        raise ValueError('Детальная запись относится к другому NPC')
    nodes = {'Npc:' + str(npc_id): dict(kind='Npc', id=str(npc_id), fields=npc)}
    edges = []
    for row in detail['battle']:
        if str(row['GroupId']) != str(npc['BattleGroupId']):
            raise ValueError('Battle.GroupId не соответствует Npc.BattleGroupId')
        origin = row['provenance']
        bid = 'Battle:' + str(row['GroupId']) + ':record:' + str(origin['csv_record'])
        nodes[bid] = dict(kind='Battle', id=str(row['GroupId']), fields=row)
        edges.append(dict(source='Npc:' + str(npc_id), target=bid, field='BattleGroupId',
            status='prior_catalog_static_join_not_current_behavior'))
    return nodes, edges


def map_registry(root, read, tracked):
    """Reference existing spatial evidence without flattening it into walkable routes."""
    atlas = root / 'maps/atlas'
    registry = {}
    for name in ('index.json', 'projection.json', 'lift-preview.json',
                 'navigation-overlay-manifest.json', 'geometry-readiness.json'):
        relative = 'maps/atlas/' + name
        data = read(relative)
        dependencies = []
        refs = list(data.get('sources', {}).values()) if name == 'lift-preview.json' else []
        if name == 'navigation-overlay-manifest.json':
            refs.append(dict(file=data['file'], sha256=data['sha256']))
        if name == 'projection.json':
            refs.append(data['native_evidence'])
        for ref in refs:
            target = (atlas / ref['file']).resolve()
            if not target.is_relative_to(root.resolve()):
                raise ValueError('Источник карты выходит за корень ресурсов')
            path = target.relative_to(root.resolve()).as_posix()
            tracked(path, ref['sha256'])
            dependencies.append(dict(file=path, sha256=ref['sha256']))
        registry[name] = dict(file=relative, sha256=sha(root / relative),
            sections=list(data), dependencies=dependencies,
            status='existing_spatial_evidence_not_current_route_or_activation')
    return registry


SPATIAL_TABLES = ('World', 'Map', 'WorldSpot', 'Area', 'AreaBox', 'Waypoint',
                  'NpcSpawn', 'GadgetSpawn', 'Gadget', 'MapIcon', 'MapIconLayer')


def spatial_graph(tables, existing):
    """Reuse explicit joins from the atlas builder; keep missing targets visible."""
    nodes = {}
    for kind in SPATIAL_TABLES:
        for row in tables[kind]:
            key = kind + ':' + str(row['Id'])
            value = dict(kind=kind, id=str(row['Id']), fields=row)
            if key in nodes:
                raise ValueError('Повторный ID пространственной таблицы: ' + key)
            if key in existing and existing[key] != value:
                raise ValueError('Несогласованные источники пространственного объекта: ' + key)
            nodes[key] = value
    # These exact field mappings are already used by build-map-atlas/build-world-map.
    joins = {
        'World': {'MapId': 'Map', 'StartSpotInfoId': 'WorldSpot'},
        'WorldSpot': {'WorldInfoId': 'World'},
        'Area': {'WorldInfoId': 'World', 'TeleportSpot': 'WorldSpot'},
        'AreaBox': {'WorldInfoId': 'World', 'AreaId': 'Area'},
        'Waypoint': {'GadgetSpawnInfoId': 'GadgetSpawn', 'TeleportSpot': 'WorldSpot'},
        'NpcSpawn': {'WorldInfoId': 'World', 'NpcInfoId': 'Npc'},
        'GadgetSpawn': {'WorldInfoId': 'World', 'GadgetInfoId': 'Gadget'},
    }
    edges = []
    for key, node in nodes.items():
        for field, target_kind in joins.get(node['kind'], {}).items():
            value = node['fields'].get(field)
            if value in (None, '', '0'):
                continue
            target = target_kind + ':' + str(value)
            present = target in nodes or target in existing
            edges.append(dict(source=key, target=target, field=field,
                status='prior_atlas_static_join_not_runtime' if present else 'unresolved_static_table_reference'))
    return nodes, edges


def overlay_inventory(overlay, lifts):
    """Audit source addresses and topology bounds, never invent runtime connectivity."""
    import math
    def vector(value, size):
        return isinstance(value, list) and len(value) == size and all(
            type(x) in (int, float) and math.isfinite(x) for x in value)
    groups = {'NavTile': overlay['tiles'], 'SpecialLink': overlay['special_links'],
              'Lift': lifts['lifts'], 'NavigationFilter': overlay['navigation_filter_presets']}
    properties = defaultdict(Counter); objects = {}; polygon_count = 0
    def fields(kind, value, prefix=''):
        if isinstance(value, dict):
            for field, item in value.items():
                fields(kind, item, prefix + '.' + field if prefix else field)
        elif isinstance(value, list) and value and isinstance(value[0], dict):
            for item in value:
                fields(kind, item, prefix + '[]')
        else:
            properties[kind][prefix] += 1
    for kind, rows in groups.items():
        for index, row in enumerate(rows):
            local_id = str(row['path'] if kind == 'NavigationFilter' else row['id'])
            key = kind + ':' + local_id
            if key in objects:
                raise ValueError('Повторный пространственный объект: ' + key)
            objects[key] = dict(kind=kind, local_id=local_id,
                source='lift-preview.json' if kind == 'Lift' else 'navigation-overlay.json',
                pointer='/' + {'NavTile': 'tiles', 'SpecialLink': 'special_links',
                    'Lift': 'lifts', 'NavigationFilter': 'navigation_filter_presets'}[kind] + '/' + str(index),
                status='source_record_not_current_world_identity')
            fields(kind, row)
            if kind == 'NavTile':
                vertices = row['vertices']
                if not all(vector(v, 2) for v in vertices) or not vector(row['bounds'], 4) or not vector(row['height_range'], 2):
                    raise ValueError('Некорректная геометрия ячейки')
                if row['height_range'][0] > row['height_range'][1]:
                    raise ValueError('Перевёрнутый диапазон высот')
                for polygon in row['polygons']:
                    if not 1 <= len(polygon) <= 6 or any(type(i) is not int or not 0 <= i < len(vertices) for i in polygon):
                        raise ValueError('Некорректный индекс полигона')
                polygon_count += len(row['polygons'])
            elif kind == 'SpecialLink':
                if not vector(row['start'], 3) or not vector(row['end'], 3):
                    raise ValueError('Некорректные точки специального перехода')
    if polygon_count != overlay['stats']['surface_polygons'] or len(overlay['tiles']) != overlay['stats']['tiles']:
        raise ValueError('Сводка полигонов не соответствует данным')
    return dict(objects=objects, properties={k: dict(v) for k, v in properties.items()},
        surface_polygons=polygon_count, source_navigation_ready=overlay['navigation_ready'],
        source_coordinate_space=overlay['coordinate_space'],
        limits=['Tile ID локален для отчёта; world / level / активный mesh не назначаются по близости.',
            'Индекс поверхности после исключения special polygons не является native polygon index.',
            'Соседство, этаж, направление и доступность не выводятся из совпадения XY или высоты.',
            'Векторы, flags, missing, условия и исходные утверждения сохраняются по JSON pointers; наследование не угадывается.'])


def spatial_properties(tables, inventory):
    properties = []
    counts = {kind: dict(Counter(key for row in tables[kind] for key in row if key != 'provenance'))
              for kind in SPATIAL_TABLES}
    counts.update(inventory['properties'])
    for kind, fields in counts.items():
        for field, observations in sorted(fields.items()):
            identity = hashlib.sha256((kind + '.' + field).encode()).hexdigest()[:12]
            properties.append(dict(id='UI-23.S-' + identity, owner=kind, field=field,
                observations=observations, status='not_reviewed',
                source='atlas_table_csv' if kind in SPATIAL_TABLES else 'spatial_report_json_pointer'))
    return properties


def spatial_checklist(report):
    lines = ['# Пространственные характеристики: проверка', '',
        'Набор: `' + report['dataset_id'] + '`.', '',
        '[Источники и ограничения](UI-GAME-DATA.md). Наличие поля не закрывает проверку.',
        'Для каждого поля проверить чтение, единицы, координатную систему, наследование, связи, применение и результат.',
        'Локальные ID overlay и его индексы не являются native ID или подтверждёнными этажами.', '']
    for prop in report['spatial_properties']:
        lines.append('- [ ] ' + prop['id'] + '. `' + prop['owner'] + '.' + prop['field'] +
                     '` · наблюдений: ' + str(prop['observations']))
    return '\n'.join(lines) + '\n'


def skill_graph(tables, existing):
    """Static explicit joins; Effect parameter matching stays a candidate."""
    nodes, edges = {}, []
    for kind in ('Skill', 'SkillOperation', 'Effect', 'EffectOperation'):
        for row in tables[kind]:
            key = kind + ':' + row['Id']
            if key in nodes or key in existing:
                raise ValueError('Повторная запись навыка / эффекта: ' + key)
            nodes[key] = dict(kind=kind, id=row['Id'], fields=row)
    def link(source, kind, value, field, candidate=False):
        target = kind + ':' + value
        present = target in nodes or target in existing
        status = ('candidate_param1_id_match_only' if present else 'candidate_definition_missing') if candidate else (
            'prior_catalog_static_join_not_current_behavior' if present else 'unresolved_static_table_reference')
        edges.append(dict(source=source, target=target, field=field, status=status))
    for key, node in nodes.items():
        row = node['fields']
        if node['kind'] == 'SkillOperation':
            link(key, 'Skill', row['SkillId'], 'SkillId')
            if row['OperationType'] == '2001' and row['OperationParam1'] not in ('', '0'):
                link(key, 'Effect', row['OperationParam1'], 'OperationParam1', candidate=True)
        elif node['kind'] == 'EffectOperation':
            link(key, 'Effect', row['EffectInfoId'], 'EffectInfoId')
    for key, node in existing.items():
        if node['kind'] == 'Battle':
            # Preserve repeated skill tokens and their source order.
            for index, token in enumerate(node['fields'].get('SkillIdList', '').split(',')):
                if token.strip():
                    link(key, 'Skill', token.strip(), 'SkillIdList[' + str(index) + ']')
    return nodes, edges


def scan(root, output):
    if any(output.resolve().is_relative_to((root / area).resolve()) for area in ('table-study', 'quest-graph', 'maps/atlas')):
        raise ValueError('Результат должен быть вне исходных каталогов')
    inputs = {}
    def tracked(relative, expected=None):
        path = (root / relative).resolve()
        if not path.is_relative_to(root.resolve()):
            raise ValueError('Источник выходит за корень ресурсов')
        digest = sha(path)
        if expected and digest != expected:
            raise ValueError('Изменился источник: ' + relative)
        inputs[relative] = digest; return path
    def read(relative, expected=None):
        return json.loads(tracked(relative, expected).read_text('utf-8'))
    tables = read('table-study/index-pakchunk1-Windows.json')
    table_registry = {}
    for table in tables['tables']:
        file = 'table-study/' + table['file']; tracked(file, table['sha256'])
        table_registry[str(table['entry'])] = dict(file=file, sha256=table['sha256'], columns=table['header'],
            rows=table['rows'], source=table['source'], status='schema_only_foreign_keys_not_inferred')
    if len(table_registry) != len(tables['tables']):
        raise ValueError('Повторный table entry')
    quests = read('quest-graph/index.json')
    for source in quests['sources'].values():
        tracked('table-study/' + source['file'], source['sha256'])
    nodes, edges = quest_graph(quests)
    atlas = 'maps/atlas/'
    manifest = read(atlas + 'monster-manifest.json')
    catalog = read(atlas + manifest['npc_catalog']['file'], manifest['npc_catalog']['sha256'])
    npc_refs = {}
    for nid, spec in manifest['files'].items():
        relative = atlas + spec['file']; detail = read(relative, spec['sha256'])
        group, links = npc_graph(nid, detail)
        for key, value in group.items():
            if key in nodes and nodes[key] != value:
                raise ValueError('Конфликт игрового объекта: ' + key)
            nodes[key] = value
        edges.extend(links)
        npc_refs[nid] = dict(file=relative, sha256=spec['sha256'], sections=list(detail),
            status='additional_fields_preserved_in_original_detail_not_fully_linked')
    if set(npc_refs) != set(catalog['npcs']):
        raise ValueError('Каталог NPC и подробные записи неполны')
    spatial_refs = map_registry(root, read, tracked)
    skill_sources = dict(manifest['sources']['skills'])
    skill_sources.update(manifest['sources']['effects']['sources'])
    skill_tables = {}
    for kind in ('Skill', 'SkillOperation', 'Effect', 'EffectOperation'):
        source = skill_sources[kind]
        path = tracked('table-study/' + source['file'], source['sha256'])
        with path.open(encoding='utf-8-sig', newline='') as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames != source['header']:
                raise ValueError('Изменилась схема навыков / эффектов')
            skill_tables[kind] = [dict(row, provenance=dict(table=kind, entry=source['entry'], csv_record=i + 2))
                                  for i, row in enumerate(reader)]
        if len(skill_tables[kind]) != source['rows']:
            raise ValueError('Изменилось число записей навыков / эффектов')
    group, links = skill_graph(skill_tables, nodes)
    nodes.update(group); edges.extend(links)
    skill_index = read(atlas + manifest['skill_index']['file'], manifest['skill_index']['sha256'])
    skill_refs = {}
    for sid, entry in skill_index['skills'].items():
        detail = entry['detail']; path = tracked(atlas + detail['file'], detail['sha256'])
        skill_refs[sid] = dict(file=atlas + detail['file'], sha256=detail['sha256'],
            has_static_definition='Skill:' + sid in nodes,
            status='prior_catalog_annotations_not_current_bindings_or_active_buffs')
    atlas_index = read(atlas + 'index.json')
    spatial_tables = read(atlas + 'tables.json', atlas_index['tables_sha256'])
    for kind in SPATIAL_TABLES:
        source = atlas_index['sources'][kind]
        tracked('table-study/' + source['file'], source['sha256'])
    group, links = spatial_graph(spatial_tables, nodes)
    nodes.update(group); edges.extend(links)
    overlay = read(atlas + 'navigation-overlay.json')
    lift_data = read(atlas + 'lift-preview.json')
    spatial_inventory = overlay_inventory(overlay, lift_data)
    tracked('maps/navigation-study/geometry-hypothesis-97/grid-inventory.json', overlay['source_grid_sha256'])
    tracked('code-clues/recast-coordinate-evidence.json', overlay['coordinate_proof_sha256'])
    for field in ('special_source', 'special_direction_evidence', 'special_nearest_evidence',
                  'special_attachment_evidence', 'area_priority_evidence',
                  'navigation_filter_evidence', 'navigation_filter_application_evidence'):
        ref = overlay[field]
        target = ((root / atlas) / ref['file']).resolve()
        if not target.is_relative_to(root.resolve()):
            raise ValueError('Источник навигации выходит за корень ресурсов')
        tracked(target.relative_to(root.resolve()).as_posix(), ref['sha256'])
    # Namespaced IDs prevent unrelated Quest/Npc/Item integer IDs from being joined.
    reverse = defaultdict(list)
    for edge in edges:
        if edge['target'] not in nodes and edge['status'] not in ('unresolved_previous_token', 'unresolved_static_table_reference', 'candidate_definition_missing'):
            raise ValueError('Неожиданная отсутствующая цель связи')
        reverse[edge['target']].append(edge)
    identity = hashlib.sha256(json.dumps(dict(inputs=inputs, scanner=sha(Path(__file__))), sort_keys=True).encode()).hexdigest()
    result = dict(schema=1, dataset_id=identity, inputs=inputs, table_schemas=table_registry,
        nodes=nodes, relations=edges, reverse=dict(reverse), npc_detail_refs=npc_refs,
        map_evidence_refs=spatial_refs,
        skill_detail_refs=skill_refs,
        spatial_inventory=spatial_inventory,
        spatial_properties=spatial_properties(spatial_tables, spatial_inventory),
        native_enum_source=quests.get('native_enum_source'),
        source_diagnostics={k: quests.get(k) for k in ('unknown_native_types', 'json_parse_errors', 'unresolved_previous_ids', 'limitations')},
        table_extraction_errors=tables.get('errors', []),
        statistics=dict(node_types=dict(Counter(n['kind'] for n in nodes.values())), relations=len(edges), tables=len(table_registry)),
        limits=['Найденные цепочки частичные; текущие состояния персонажей и серверные условия не прочитаны.',
            'PreQuestId tokens не задают AND / OR, порядок ветвлений или допустимый следующий квест.',
            'Все NPC не объявляются монстрами: Type / native enum и контекст требуют проверки.',
            'Навыки, добыча, награды, позиции и прочие блоки сохранены ссылками на исходные NPC details; не все связи восстановлены.',
            'Колонки остальных таблиц проиндексированы, но совпадение числовых ID не создаёт foreign key.',
            'Полигоны, лифты и проекция включены ссылками на пространственные отчёты; направление, активация и проходимость не выводятся из наличия геометрии.',
            'Версии данных не подтверждены для установленного клиента; действий игры и генерации UI нет.'])
    destination = output / identity; destination.mkdir(parents=True, exist_ok=True)
    for relative, digest in inputs.items():
        if sha(root / relative) != digest:
            raise ValueError('Источники изменились во время сканирования')
    (destination / 'index.json').write_text(json.dumps(result, ensure_ascii=False, separators=(',', ':')), 'utf-8')
    return destination, result


def verify_rows(root, report):
    """Recheck each normalized record against its exact logical CSV row."""
    cached = {}; checked = 0
    for node in report['nodes'].values():
        row = node['fields']; origin = row['provenance']; table = report['table_schemas'][str(origin['entry'])]
        if table['file'] not in cached:
            path = root / table['file']
            if sha(path) != table['sha256']:
                raise ValueError('Изменилась исходная таблица')
            with path.open(encoding='utf-8-sig', newline='') as stream:
                cached[table['file']] = list(csv.DictReader(stream))
        number = origin['csv_record']
        if type(number) is not int or not 2 <= number < len(cached[table['file']]) + 2:
            raise ValueError('Недопустимый номер логической CSV записи')
        original = cached[table['file']][number - 2]
        if not all(key in row and row[key] == value for key, value in original.items()):
            raise ValueError('Запись не соответствует исходной CSV строке: ' + node['kind'] + ':' + node['id'])
        checked += 1
    for relative, digest in report['inputs'].items():
        if sha(root / relative) != digest:
            raise ValueError('Изменился вход набора данных')
    return dict(state='passed', dataset=report['dataset_id'], records=checked,
        source_files=len(report['inputs']), scope='static_source_records_not_runtime_or_all_relations')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--spatial-tasks', type=Path)
    args = parser.parse_args()
    if args.spatial_tasks and args.spatial_tasks.exists():
        parser.error('Существующий чеклист не перезаписывается: результаты проверки нужно сохранить')
    folder, report = scan(args.root, args.output or args.root / 'ui-game-data-scans')
    if args.verify:
        checked = verify_rows(args.root, report)
        (folder / 'verification.json').write_text(json.dumps(checked, ensure_ascii=False, indent=2), 'utf-8')
        print(json.dumps(checked, ensure_ascii=False))
    if args.spatial_tasks:
        args.spatial_tasks.write_text(spatial_checklist(report), 'utf-8')
    print(json.dumps(dict(output=str(folder), **report['statistics']), ensure_ascii=False))
