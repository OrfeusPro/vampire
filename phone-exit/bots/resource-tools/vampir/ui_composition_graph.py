"""Compile structural dependency evidence. No active variant or behavior is inferred.

Reusable build step; reads published catalogs only, never starts or controls the game.
"""
import argparse
import json
from collections import Counter, defaultdict, deque
from pathlib import Path


def compile_graph(records):
    nodes, classes = {}, defaultdict(list)
    for record in sorted(records, key=lambda r: r['path']):
        for variant in sorted(record['variants'], key=lambda v: v['file']):
            key = record['path'] + '|' + variant['file']
            if key in nodes:
                raise ValueError('Повторный вариант: ' + key)
            nodes[key] = dict(resource_id=record['id'], resource_path=record['path'],
                name=record['name'], file=variant['file'], sha256=variant['sha256'],
                asset_sha256=variant.get('asset_sha256'), body_sha256=variant.get('body_sha256'),
                root=variant.get('root'), controls=len(variant['controls']),
                control_types=dict(sorted(Counter(c['type'] for c in variant['controls']).items())),
                decoded_slots=len(variant.get('slots', [])), dependencies=[])
            classes[record['name'] + '_C'].append(key)
    for record in records:
        for variant in record['variants']:
            node = nodes[record['path'] + '|' + variant['file']]
            for control in variant['controls']:
                kind = control['type'] or ''
                if not kind.endswith('_C'):
                    continue
                candidates = sorted(classes.get(kind, []))
                node['dependencies'].append(dict(control={k: control[k] for k in ('name', 'type', 'export', 'sha256')},
                    candidates=candidates,
                    status='class_match_requires_variant_selection' if candidates else 'unresolved_class'))
            node['dependencies'].sort(key=lambda d: (d['control']['export'], d['control']['name']))
    return dict(schema=1, kind='structural_candidate_graph', nodes=nodes,
        statistics=dict(variants=len(nodes), nested_controls=sum(len(n['dependencies']) for n in nodes.values()),
            unresolved_classes=sum(not d['candidates'] for n in nodes.values() for d in n['dependencies']),
            ambiguous_classes=sum(len(d['candidates']) > 1 for n in nodes.values() for d in n['dependencies'])),
        limits=['Класс контрола подтверждён каталогом; кандидаты не выбирают активный вариант клиента.',
            'Граф не подтверждает runtime DPI, Brush, delegates, серверное состояние или готовность окна.',
            'Неизвестные классы сохраняются; исторические варианты не объединяются с текущей сборкой.'])


def affected(graph, changed):
    """Conservative reverse closure, including unresolved variant alternatives and cycles."""
    reverse = defaultdict(set)
    for key, node in graph['nodes'].items():
        for edge in node['dependencies']:
            for target in edge['candidates']:
                reverse[target].add(key)
    seen, queue = set(changed), deque(changed)
    while queue:
        for parent in sorted(reverse.get(queue.popleft(), [])):
            if parent not in seen:
                seen.add(parent)
                queue.append(parent)
    return sorted(seen)


def compare(previous, current):
    left, right = previous['nodes'], current['nodes']
    added, removed = sorted(right.keys() - left.keys()), sorted(left.keys() - right.keys())
    # Compare complete nodes too: candidate sets can change without changing a consumer package.
    changed = sorted(k for k in left.keys() & right.keys() if left[k] != right[k])
    seeds = added + removed + changed
    return dict(added=added, removed=removed, changed=changed,
        recheck=sorted(set(affected(previous, seeds)) | set(affected(current, seeds))),
        status='candidate_impact_requires_review_not_runtime_compatibility')


def from_snapshot(snapshot):
    read = lambda p: json.loads(p.read_text('utf-8'))
    manifest = read(snapshot / 'manifest.json')
    records = []
    for row in read(snapshot / 'registry-index.json'):
        record = read(snapshot / 'windows' / (row['id'] + '.json'))
        for variant in record['variants']:
            if manifest['resources'][record['path'] + '|' + variant['file']] != variant['sha256']:
                raise ValueError('Источник не соответствует manifest')
        records.append(record)
    return compile_graph(records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    # Standalone reports must not mutate immutable snapshots.
    output = args.output.resolve()
    for source in [args.snapshot, args.baseline]:
        if source and output.is_relative_to(source.resolve()):
            parser.error('Отчёт нужно сохранять вне snapshot')
    graph = from_snapshot(args.snapshot)
    result = dict(graph=graph)
    if args.baseline:
        result['impact'] = compare(from_snapshot(args.baseline), graph)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(output=str(output), **graph['statistics']), ensure_ascii=False))


if __name__ == '__main__':
    main()
