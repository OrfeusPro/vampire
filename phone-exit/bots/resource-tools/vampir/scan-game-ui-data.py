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
    # Namespaced IDs prevent unrelated Quest/Npc/Item integer IDs from being joined.
    reverse = defaultdict(list)
    for edge in edges:
        if edge['target'] not in nodes and edge['status'] != 'unresolved_previous_token':
            raise ValueError('Неожиданная отсутствующая цель связи')
        reverse[edge['target']].append(edge)
    identity = hashlib.sha256(json.dumps(dict(inputs=inputs, scanner=sha(Path(__file__))), sort_keys=True).encode()).hexdigest()
    result = dict(schema=1, dataset_id=identity, inputs=inputs, table_schemas=table_registry,
        nodes=nodes, relations=edges, reverse=dict(reverse), npc_detail_refs=npc_refs,
        map_evidence_refs=spatial_refs,
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
    args = parser.parse_args()
    folder, report = scan(args.root, args.output or args.root / 'ui-game-data-scans')
    if args.verify:
        checked = verify_rows(args.root, report)
        (folder / 'verification.json').write_text(json.dumps(checked, ensure_ascii=False, indent=2), 'utf-8')
        print(json.dumps(checked, ensure_ascii=False))
    print(json.dumps(dict(output=str(folder), **report['statistics']), ensure_ascii=False))
