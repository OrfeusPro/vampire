"""Inventory exact uppercase UI in terminal names; research output only, no UI completion claims."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('ui_name_inventory_builder', HERE / 'build-ui-prototype.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def classify(name, path):
    if not isinstance(name, str) or not name or not isinstance(path, str):
        raise ValueError('Invalid resource name/path')
    named = 'UI' in name
    return dict(name_contains_UI=named, name_ends_UI=name.endswith('UI'),
                path_only_UI='UI' in path and not named,
                unresolved=path.startswith('unresolved:'),
                case_insensitive_search_UI='ui' in name.lower() or 'ui' in path.lower())


def compile_inventory(index, registry):
    """Use the builder's grouping and stable path identity; reject a stale published cohort."""
    entries = builder.catalog_entries(index)
    by_path = {}
    for row in registry:
        if row['path'] in by_path:
            raise ValueError('Duplicate published resource path')
        by_path[row['path']] = row
    if set(entries) != set(by_path):
        raise ValueError('Published registry paths differ from source index')
    records, totals = [], Counter()
    cohorts = {key: [] for key in ('name_contains_UI', 'name_ends_UI', 'path_only_UI', 'case_insensitive_search_UI')}
    for path, variants in sorted(entries.items()):
        if not variants:
            raise ValueError('Empty source variant group')
        name = variants[0].get('unresolved_name', path.rsplit('/', 1)[-1])
        identity = digest(path.encode('utf8'))[:12]
        row = by_path[path]
        if row['id'] != 'W-' + identity or row['name'] != name or row['variants'] != len(variants):
            raise ValueError('Published registry identity/name/variant count differs from source')
        flags = classify(name, path)
        task_id = 'UI-W-' + identity
        value = dict(task_id=task_id, registry_id=row['id'], path=path, name=name,
                     name_basis='unresolved_class_name' if flags['unresolved'] else 'resource_terminal_name',
                     flags=flags, variant_count=len(variants),
                     source_variant_files=[v['file'] for v in variants], registry_status=row['status'],
                     review_state='not_reviewed')
        records.append(value)
        totals.update(resources=1, variants=len(variants), unresolved_resources=int(flags['unresolved']))
        for key in cohorts:
            if flags[key]:
                cohorts[key].append(task_id)
                totals[key + '_resources'] += 1
                totals[key + '_variants'] += len(variants)
        if flags['name_contains_UI'] and flags['unresolved']:
            totals['name_contains_UI_unresolved_resources'] += 1
            totals['name_contains_UI_unresolved_variants'] += len(variants)
    return dict(schema=1, kind='uppercase_UI_name_inventory',
                selection=dict(query='UI', case_sensitive=True, field='terminal_resource_or_unresolved_class_name',
                               path_directory_not_searched=True, rule='contains'),
                counts=dict(totals), cohorts=cohorts, records=records,
                limits=['Имя с UI — кандидат для обхода, а не доказательство отдельного игрового окна.',
                        'Исторические варианты и unresolved classes сохранены; активный вариант и совместимость не определены.',
                        'Все review_state = not_reviewed; список не отмечает реализацию или визуальные проверки выполненными.',
                        'Исследовательский отчёт не подключается к runtime и не загружается каждым из 50 окон.'])


def child(root, relative):
    candidate = (root / relative).resolve()
    if Path(relative).is_absolute() or not candidate.is_relative_to(root.resolve()):
        raise ValueError('Source path leaves the requested root')
    return candidate


def build(root, snapshot=None):
    root = root.resolve()
    index_path = root / 'ui-catalog/index.json'
    index_raw = index_path.read_bytes()
    index = json.loads(index_raw)
    pointer = None
    if snapshot is None:
        pointer_path = root / 'maps/ui-prototype/current.json'
        pointer_raw = pointer_path.read_bytes()
        pointer = dict(path=str(pointer_path), sha256=digest(pointer_raw))
        selected = json.loads(pointer_raw)
        snapshot = child(root / 'maps/ui-prototype', selected['snapshot'])
    else:
        snapshot = snapshot.resolve()
    manifest_raw = (snapshot / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_raw)
    registry_raw = (snapshot / 'registry-index.json').read_bytes()
    registry = json.loads(registry_raw)
    if manifest['inputs']['ui-catalog/index.json'] != digest(index_raw):
        raise ValueError('Published snapshot refers to another catalog index')
    result = compile_inventory(index, registry)
    if (manifest['registry_count'], manifest['variant_count']) != (result['counts']['resources'], result['counts']['variants']):
        raise ValueError('Published manifest totals differ from source cohort')
    file_sources = {}
    expected_resources = {}
    for path, variants in builder.catalog_entries(index).items():
        for variant in variants:
            file = variant['file']
            if file not in file_sources:
                raw = child(root / 'ui-catalog', file).read_bytes()
                value = json.loads(raw)
                file_sources[file] = dict(sha256=digest(raw), source_file=value.get('source_file', value['file']),
                                          asset_sha256=value['asset_sha256'], body_sha256=value['body_sha256'],
                                          entry=value['entry'])
            expected_resources[path + '|' + file] = file_sources[file]['sha256']
    if manifest['resources'] != expected_resources:
        raise ValueError('Published resource SHA map differs from actual catalog bytes')
    result['sources'] = dict(catalog_index=dict(path=str(index_path), sha256=digest(index_raw)),
                             published_snapshot=dict(id=manifest['id'], path=str(snapshot), manifest_sha256=digest(manifest_raw),
                                                     registry_sha256=digest(registry_raw), client=manifest['client']),
                             current_pointer=pointer, catalog_files=file_sources,
                             tools={p.name: digest(p.read_bytes()) for p in [Path(__file__), HERE / 'build-ui-prototype.py']})
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--snapshot', type=Path, help='Explicit existing published snapshot; defaults to current.json')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(HERE.parents[3]):
        parser.error('Большой отчёт хранится вне репозитория; укажите внешний --output')
    if args.output.exists():
        parser.error('Прежний отчёт не перезаписывается; укажите новый --output')
    value = build(args.root, args.snapshot)
    with args.output.open('x', encoding='utf8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
    print(json.dumps(dict(output=str(args.output), counts=value['counts']), ensure_ascii=False))
