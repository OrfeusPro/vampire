"""Conservative static impact queue; does not select active variants or close UI tasks."""
from collections import defaultdict, deque
import ui_composition_graph as composition

CRITERIA = ['01', '02', '03', '04', '05', '06']


def rules(readiness):
    result = {}
    for row in readiness['rules']:
        if type(row.get('version')) is not int or row['version'] < 1:
            raise ValueError('Invalid rule version')
        if not isinstance(row.get('dependencies'), list) or any(not isinstance(v, str) for v in row['dependencies']):
            raise ValueError('Invalid rule dependencies')
        for field in ('criteria', 'widget_types'):
            if field in row and (not isinstance(row[field], list) or any(not isinstance(v, str) or not v for v in row[field])):
                raise ValueError('Invalid rule scope: ' + field)
        if any(c not in CRITERIA for c in row.get('criteria', [])):
            raise ValueError('Unknown UI criterion')
        if row['id'] in result:
            raise ValueError('Duplicate rule: ' + row['id'])
        provider = readiness['providers'].get(row['provider'])
        if not isinstance(provider, str) or len(provider) != 64 or any(c not in '0123456789abcdef' for c in provider):
            raise ValueError('Missing full provider SHA: ' + row['id'])
        result[row['id']] = dict(definition=row, provider_sha256=provider)
    for name, item in result.items():
        if any(dep not in result for dep in item['definition']['dependencies']):
            raise ValueError('Unknown rule dependency: ' + name)
    return result


def rule_closure(previous, current, seeds):
    reverse = defaultdict(set)
    for registry in (previous, current):
        for name, item in registry.items():
            for dependency in item['definition']['dependencies']:
                reverse[dependency].add(name)
    seen = set(seeds)
    queue = deque(sorted(seen))
    while queue:
        for name in sorted(reverse[queue.popleft()]):
            if name not in seen:
                seen.add(name)
                queue.append(name)
    return sorted(seen)


def targets(graph, rule):
    kinds = rule.get('widget_types')
    # Missing scope is conservative, not a guess that no windows are affected.
    if not kinds or '*' in kinds:
        return sorted(graph['nodes'])
    return sorted(key for key, node in graph['nodes'].items()
                  if node['name'] + '_C' in kinds or set(node['control_types']).intersection(kinds))


def priority_coverage(graph, kinds):
    result = {}
    for kind in sorted(kinds):
        seeds = targets(graph, dict(widget_types=[kind]))
        affected = composition.affected(graph, seeds)
        result[kind] = dict(source_variants=sum(n['name'] + '_C' == kind for n in graph['nodes'].values()),
            variants=len(affected), resources=len({graph['nodes'][key]['resource_id'] for key in affected}),
            runtime_binding_verified=False)
    return result


def compile_impact(previous_graph, current_graph, previous_ready, current_ready):
    before, after = rules(previous_ready), rules(current_ready)
    changed_rules = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
    affected_rules = rule_closure(before, after, changed_rules)
    graph_delta = composition.compare(previous_graph, current_graph)
    queue = {}
    def add(keys, criteria, reason):
        if not criteria or any(c not in CRITERIA for c in criteria):
            raise ValueError('Unknown UI criterion')
        for key in keys:
            old, new = previous_graph['nodes'].get(key), current_graph['nodes'].get(key)
            node = new or old
            task = 'UI-' + node['resource_id']
            row = queue.setdefault(task, dict(task_id=task, resource_path=node['resource_path'],
                variants={}, criteria=set(), reasons=set(), status='requires_recheck'))
            row['variants'][key] = dict(previous_sha256=old['sha256'] if old else None,
                                       current_sha256=new['sha256'] if new else None,
                                       removed=new is None)
            row['criteria'].update(criteria)
            row['reasons'].add(reason)
    add(graph_delta['recheck'], CRITERIA, 'source_or_dependency_changed')
    scope_unknowns = []
    for name in affected_rules:
        seed = set()
        criteria = set()
        for graph, registry in [(previous_graph, before), (current_graph, after)]:
            if name not in registry:
                continue
            rule = registry[name]['definition']
            if not rule.get('widget_types') or not rule.get('criteria'):
                scope_unknowns.append(name)
            seed.update(targets(graph, rule))
            criteria.update(rule.get('criteria') or CRITERIA)
        affected = set(composition.affected(previous_graph, seed)) | set(composition.affected(current_graph, seed))
        add(sorted(affected), sorted(criteria), 'rule_changed:' + name)
    for row in queue.values():
        row['criteria'] = sorted(row['criteria'])
        row['reasons'] = sorted(row['reasons'])
        row['variants'] = dict(sorted(row['variants'].items()))
    return dict(schema=1, kind='ui_static_rule_impact', source_delta=graph_delta,
        changed_rules=changed_rules, affected_rules=affected_rules,
        rule_scope_unknowns=sorted(set(scope_unknowns)), queue=dict(sorted(queue.items())),
        statistics=dict(resources=len(queue), variants=sum(len(v['variants']) for v in queue.values()),
                        criteria=sum(len(v['criteria']) for v in queue.values())),
        runtime_compatibility_verified=False, tasks_closed=False,
        limits=['Очередь консервативна: class candidates включают исторические и неоднозначные варианты.',
                'Отсутствие изменений не доказывает выполнение прежних открытых критериев.',
                'Удалённые ресурсы сохраняются в очереди; статус основного плана автоматически не меняется.'])


def markdown(impact):
    lines = ['# Повторные проверки UI', '', 'Это очередь запуска проверок, не копия статусов основного плана.', '']
    for row in impact['queue'].values():
        lines.append('- [ ] ' + row['task_id'] + '. `' + row['resource_path'] + '`')
        lines.append('  Критерии: ' + ', '.join(row['task_id'] + '.' + c for c in row['criteria']) + '.')
        lines.append('  Причины: ' + ', '.join(row['reasons']) + '.')
    if not impact['queue']:
        lines.append('Новых проверок по сравнению с baseline нет; прежние открытые задачи сохраняются.')
    return '\n'.join(lines) + '\n'
