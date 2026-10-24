"""Scan extracted catalogs into versioned multidimensional analysis data, never UI output."""
import argparse
import copy
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path('F:/PhoneExit Resources/Vampir')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, separators=(',', ':')), 'utf-8')


def leaves(value, prefix=''):
    # Keep vectors, arrays and serialized_fields intact; array positions are not property IDs.
    if not prefix and isinstance(value, dict) and not value:
        return
    if isinstance(value, dict) and value:
        for key, child in sorted(value.items()):
            yield from leaves(child, prefix + ('.' if prefix else '') + key)
    else:
        yield prefix, value


def scan(root, output, requirements):
    requirements = copy.deepcopy(requirements)
    ids = [row['id'] for row in requirements['characteristics']]
    if len(ids) != len(set(ids)):
        raise ValueError('Повторные ID обязательных характеристик')
    catalog = root / 'ui-catalog'
    if output.resolve().is_relative_to(catalog.resolve()):
        raise ValueError('Результат анализа должен быть вне исходного каталога')
    index_sha = sha(catalog / 'index.json')
    index = json.loads((catalog / 'index.json').read_text('utf-8'))
    paths = defaultdict(set)
    for path, variants in index['resource_variants'].items():
        for variant in variants:
            paths[variant['file']].add(path)
    names = {row['file']: row['name'] for row in index['windows']}
    files = sorted(set(names) | set(paths))
    hashes = {file: sha(catalog / file) for file in files}
    identity = hashlib.sha256(json.dumps(dict(catalog=index_sha, files=hashes,
        requirements=requirements, scanner=sha(Path(__file__))), sort_keys=True).encode()).hexdigest()
    destination = output / identity
    properties, occurrences, kinds, relations = {}, defaultdict(list), defaultdict(list), []
    counts, variants, classes = Counter(), {}, defaultdict(list)
    for file in files:
        classes[names.get(file, '') + '_C'].append(file)

    def observe(owner, scope, export, value, file):
        for field, item in leaves(value):
            key = scope + '.' + owner + '.' + field
            pid = 'UI-23.P-' + hashlib.sha256(key.encode()).hexdigest()[:12]
            if pid not in properties:
                properties[pid] = dict(key=key, owner=owner, scope=scope, field=field,
                    types=[], observations=0, status='requires_review_not_runtime_verified')
            entry = properties[pid]
            if entry['key'] != key:
                raise ValueError('Property ID collision')
            kind = 'null' if item is None else type(item).__name__
            if kind not in entry['types']:
                entry['types'].append(kind); entry['types'].sort()
            entry['observations'] += 1
            occurrences[pid].append(dict(variant=file, scope=scope, export=export, field=field))

    for file in files:
        data = json.loads((catalog / file).read_text('utf-8'))
        # Preserve original values/fields. No engine-native property is inferred from a name.
        widgets = {str(c['export']): c for c in data['controls']}
        if len(widgets) != len(data['controls']):
            raise ValueError('Duplicate control exports: ' + file)
        slots = {str(s['provenance']['slot_export']): s for s in data.get('decoded_slots', [])}
        if len(slots) != len(data.get('decoded_slots', [])):
            raise ValueError('Duplicate slot exports: ' + file)
        source = dict(file=file, catalog_sha256=hashes[file], asset_sha256=data.get('asset_sha256'),
            body_sha256=data.get('body_sha256'), archive=data.get('source'), entry=data.get('entry'))
        variants[file] = dict(name=data['name'], paths=sorted(paths[file]), file='variants/' + file, source=source)
        for c in widgets.values():
            kinds[c['type']].append(dict(variant=file, export=c['export']))
            geometry = c.get('container_geometry') or {}
            native = geometry.get('decoded', {})
            for scope in ('explicit_properties', 'inherited_properties'):
                if native.get(scope):
                    observe(c['type'], scope, c['export'], native[scope], file)
            other = {k: v for k, v in native.items() if k not in ('explicit_properties', 'inherited_properties')}
            if other:
                observe(c['type'], 'container_relation', c['export'], other, file)
            if 'slots' in native:
                relations.append(dict(kind='container_slot_order', variant=file, control=c['export'],
                    slots=native['slots'], source=geometry.get('provenance'), status='decoded_catalog_requires_review'))
            metadata = {k: v for k, v in c.items() if k != 'container_geometry'}
            observe(c['type'], 'catalog_control', c['export'], metadata, file)
            if c['type'].endswith('_C'):
                relations.append(dict(kind='nested_class_candidates', variant=file, control=c['export'],
                    target_class=c['type'], candidates=classes.get(c['type'], []), status='variant_not_selected'))
        for s in slots.values():
            d = s['decoded']; owner = d.get('parent', {}).get('type', 'unknown')
            observe(owner, 'slot', s['provenance']['slot_export'],
                {k: v for k, v in d.items() if k not in ('parent', 'content', 'parent_export', 'content_export')}, file)
            relations.append(dict(kind='local_slot', variant=file, slot=s['provenance']['slot_export'],
                parent=d['parent_export'], content=d['content_export'], source_sha256=s['provenance'].get('sha256')))
        write(destination / 'variants' / file, dict(source=source, blueprint_root=data.get('root_export'),
            widgets=widgets, slots=slots, excluded_slots=data.get('excluded_slots', []), limitations=data.get('limitations', [])))
        counts.update(variants=1, widgets=len(widgets), slots=len(slots), excluded_slots=len(data.get('excluded_slots', [])))
    resources = {path: dict(variants={file: dict(ref='variants/' + file) for file in sorted(fileset)})
        for path, fileset in sorted(((p, {f for f in files if p in paths[f]}) for p in {p for v in paths.values() for p in v}))}
    for pid, entry in properties.items():
        entry['occurrences'] = 'properties/' + pid + '.json'
        entry['examples'] = occurrences[pid][:4]
        write(destination / entry['occurrences'], occurrences[pid])
    for row in requirements['characteristics']:
        row['candidate_properties'] = sorted(pid for pid, prop in properties.items()
            if prop['field'].rsplit('.', 1)[-1] in row.get('aliases', []))
        row['status'] = 'not_reviewed'  # Candidate name matches never close a requirement.
    report = dict(schema=1, dataset_id=identity, phase='property_inventory', statistics=dict(counts),
        source_index_sha256=index_sha, source_compatibility='not_established',
        datasets={identity: dict(resources=resources, variants=variants)},
        properties=dict(sorted(properties.items())), widget_types=dict(sorted(kinds.items())),
        required_characteristics=requirements['characteristics'], relations='relations.json',
        limits=['Сканируются все поля имеющегося каталога, не все ещё недекодированные UProperties клиента.',
            'catalog_control offset / size — метаданные экспорта, не экранная геометрия.',
            'Требуется проверка каждой характеристики; совпадение имени и наличие значения не подтверждают применение.',
            'Набор для анализа; генерация внешнего вида и команды игры не выполняются.'])
    write(destination / 'relations.json', relations)
    reverse = defaultdict(list)
    for relation in relations:
        for candidate in relation.get('candidates', []):
            reverse[candidate].append(dict(variant=relation['variant'], control=relation['control']))
    write(destination / 'reverse-components.json', dict(reverse))
    if hashes != {file: sha(catalog / file) for file in files} or sha(catalog / 'index.json') != index_sha:
        raise ValueError('Каталоги изменились во время сканирования')
    write(destination / 'index.json', report)
    return destination, report


def checklist(report):
    lines = ['# Характеристики и связи UI: проверка', '',
        'Набор: `' + report['dataset_id'] + '`.', '',
        'Пункты закрываются после проверки источника, наследования, применения и результата.',
        'Наличие поля у сканера не означает готовность. Список дополняется при расширении декодеров.', '',
        '## Обязательные характеристики', '']
    for row in report['required_characteristics']:
        lines.append('- [ ] ' + row['id'] + '. ' + row['name'] + ' · кандидатов: ' + str(len(row['candidate_properties'])))
    lines += ['', '## Автоматически найденные поля каталога', '']
    for pid, row in report['properties'].items():
        lines.append('- [ ] ' + pid + '. `' + row['key'] + '` · ' + ', '.join(row['types']) + ' · наблюдений: ' + str(row['observations']))
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=ROOT)
    p.add_argument('--output', type=Path)
    p.add_argument('--requirements', type=Path, required=True)
    p.add_argument('--tasks', type=Path)
    args = p.parse_args()
    if args.tasks and args.tasks.exists():
        p.error('Не перезаписывать результаты проверки: задайте новый файл задач для нового набора.')
    folder, result = scan(args.root, args.output or args.root / 'ui-property-scans', json.loads(args.requirements.read_text('utf-8')))
    if args.tasks:
        args.tasks.write_text(checklist(result), 'utf-8')
    print(json.dumps(dict(output=str(folder), properties=len(result['properties']), **result['statistics']), ensure_ascii=False))
