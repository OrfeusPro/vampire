"""Verify saved analysis against source records and spatial evidence, without generation."""
import argparse
from collections import Counter, defaultdict
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('game_data_scan', HERE / 'scan-game-ui-data.py')
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


def verify_spatial(root, report):
    def read(relative):
        path = (root / relative).resolve()
        if not path.is_relative_to(root.resolve()):
            raise ValueError('Источник вне корня ресурсов')
        if relative not in report['inputs'] or scanner.sha(path) != report['inputs'][relative]:
            raise ValueError('Изменился пространственный источник: ' + relative)
        return json.loads(path.read_text('utf-8'))
    tables = read('maps/atlas/tables.json')
    overlay = read('maps/atlas/navigation-overlay.json')
    lifts = read('maps/atlas/lift-preview.json')
    inventory = scanner.overlay_inventory(overlay, lifts)
    if inventory != report['spatial_inventory']:
        raise ValueError('Пространственные записи / указатели не совпадают с источниками')
    if scanner.spatial_properties(tables, inventory) != report['spatial_properties']:
        raise ValueError('Перечень пространственных характеристик изменён')
    nodes, expected = scanner.spatial_graph(tables, report['nodes'])
    if any(report['nodes'].get(key) != value for key, value in nodes.items()):
        raise ValueError('Пространственные узлы неполны')
    actual = [e for e in report['relations'] if e['source'] in nodes]
    encode = lambda e: json.dumps(e, sort_keys=True)
    if Counter(map(encode, actual)) != Counter(map(encode, expected)):
        raise ValueError('Пространственные связи неполны или подменены')
    reverse = defaultdict(list)
    for edge in report['relations']:
        if edge['source'] not in report['nodes']:
            raise ValueError('Источник связи отсутствует')
        if edge['target'] not in report['nodes'] and edge['status'] not in (
                'unresolved_previous_token', 'unresolved_static_table_reference', 'candidate_definition_missing'):
            raise ValueError('Неподтверждённая цель скрыта как готовая связь')
        reverse[edge['target']].append(edge)
    if dict(reverse) != report['reverse']:
        raise ValueError('Обратный индекс не соответствует прямым связям')
    # Resolve every pointer rather than relying only on counts.
    sources = {'navigation-overlay.json': overlay, 'lift-preview.json': lifts}
    for obj in inventory['objects'].values():
        value = sources[obj['source']]
        for token in obj['pointer'].split('/')[1:]:
            value = value[int(token)] if isinstance(value, list) else value[token]
        if str(value['path'] if obj['kind'] == 'NavigationFilter' else value['id']) != obj['local_id']:
            raise ValueError('Указатель относится к другому объекту')
    return dict(spatial_objects=len(inventory['objects']), spatial_properties=len(report['spatial_properties']),
        spatial_relations=len(expected), unresolved_spatial_relations=sum(
            e['status'] == 'unresolved_static_table_reference' for e in expected))


def verify_skills(report, tables=None):
    kinds = ('Skill', 'SkillOperation', 'Effect', 'EffectOperation')
    if tables is None:
        tables = {kind: [n['fields'] for n in report['nodes'].values() if n['kind'] == kind] for kind in kinds}
    existing = {k: n for k, n in report['nodes'].items() if n['kind'] not in kinds}
    nodes, expected = scanner.skill_graph(tables, existing)
    if {k: n for k, n in report['nodes'].items() if n['kind'] in kinds} != nodes:
        raise ValueError('Некорректные ключи навыков / эффектов')
    actual = [e for e in report['relations'] if e['source'] in nodes or
              (e['source'] in existing and existing[e['source']]['kind'] == 'Battle' and e['field'].startswith('SkillIdList['))]
    encode = lambda e: json.dumps(e, sort_keys=True)
    if Counter(map(encode, actual)) != Counter(map(encode, expected)):
        raise ValueError('Повреждены связи навыков / эффектов или статус кандидата')
    return dict(skill_effect_records=len(nodes), skill_effect_relations=len(expected),
                effect_candidates=sum(e['status'].startswith('candidate_') for e in expected))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.output and args.output.exists():
        parser.error('Результаты прежней проверки не перезаписываются')
    report = json.loads((args.folder / 'index.json').read_text('utf-8'))
    result = scanner.verify_rows(args.root, report)
    result.update(verify_spatial(args.root, report))
    import csv
    manifest = json.loads((args.root / 'maps/atlas/monster-manifest.json').read_text('utf-8'))
    sources = dict(manifest['sources']['skills']); sources.update(manifest['sources']['effects']['sources'])
    tables = {}
    for kind in ('Skill', 'SkillOperation', 'Effect', 'EffectOperation'):
        source = sources[kind]; relative = 'table-study/' + source['file']
        if report['inputs'].get(relative) != source['sha256']:
            raise ValueError('Источник навыков не входит в набор')
        with (args.root / relative).open(encoding='utf-8-sig', newline='') as stream:
            tables[kind] = [dict(row, provenance=dict(table=kind, entry=source['entry'], csv_record=i + 2))
                            for i, row in enumerate(csv.DictReader(stream))]
    result.update(verify_skills(report, tables))
    result['scope'] = 'static_csv_spatial_skill_effect_records_relations_and_reverse_index_not_runtime'
    if args.output:
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(result, ensure_ascii=False))
