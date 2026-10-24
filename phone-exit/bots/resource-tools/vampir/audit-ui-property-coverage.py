"""Audit recovered declarations vs decoded observations and bounded decoder fixtures.

No native addresses are applied to the installed executable and no UI is generated.
"""
import argparse
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


widget = load('coverage_widget', 'decode-widget-properties.py')
canvas = load('coverage_canvas', 'decode-canvas-slots.py')


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    return digest.hexdigest()


def probe(schema, field):
    index = field['schema_index']; name = field['name']; flags = field['gen_flags'] & 255
    if name == 'RenderTransform':
        parts = schema['widget_transform']['properties']
        values = {'Translation': [1.25, 2.5], 'Scale': [1.5, 1.5], 'Shear': [.25, .5], 'Angle': 12.5}
        raw = struct.pack('<H', 256 | len(parts) << 9)
        for part in parts:
            value = values[part['name']]
            raw += struct.pack('<f', value) if part['name'] == 'Angle' else struct.pack('<dd', *value)
    elif name == 'RenderTransformPivot':
        raw = struct.pack('<dd', .25, .75)
    elif flags in (12, 0, 30):
        raw = b'\x01'
    elif flags == 82:
        raw = struct.pack('<i', 42)
    elif name == 'RenderOpacity':
        raw = struct.pack('<f', .625)
    else:
        raw = struct.pack('<i', 1)  # Nonempty bindings/delegates must not be treated as empty.
    def attempt(zero, data):
        reader = canvas.Reader(data)
        try:
            actual_name, value = widget.property_value(reader, index, zero, schema)
            if actual_name != name or reader.pos != len(data):
                raise ValueError('Fixture not fully consumed')
            return dict(state='accepted_fixture', value=value)
        except (ValueError, KeyError) as error:
            return dict(state='unsupported_fixture', reason=str(error))
    result = dict(serialized_zero=attempt(True, b''), nonzero=attempt(False, raw),
        absent_default='unresolved_not_a_serialized_zero', scope='bounded_decoder_fixture_not_game_behavior')
    if name == 'NativeBindings':
        result['explicit_empty_array'] = attempt(False, struct.pack('<i', 0))
    return result


def declarations(schema):
    nested = set(schema['widget']['nested_descriptor_indices'])
    original = schema['widget']['properties']
    standalone = [row for row in original if row['index'] not in nested]
    serialized = schema['widget']['serialized_properties']
    if len(serialized) != len(standalone) or any(row['schema_index'] != i or
        any(row[k] != standalone[i][k] for k in standalone[i]) for i, row in enumerate(serialized)):
        raise ValueError('Некорректное исключение вложенных дескрипторов / schema_index')
    for family, owner in [('widget', 'Widget'), ('widget_transform', 'WidgetTransform'), ('size_box', 'SizeBox'), ('scale_box', 'ScaleBox')]:
        rows = serialized if family == 'widget' else schema[family]['properties']
        names = [row['name'] for row in rows]
        if len(names) != len(set(names)):
            raise ValueError('Повторные самостоятельные свойства')
        for row in rows:
            key = family + '.' + row['name']
            yield dict(id='UI-23.N-' + hashlib.sha256(key.encode()).hexdigest()[:12],
                family=family, owner=owner, name=row['name'], descriptor=row,
                native_array_offset=schema[family]['array_offset'])


def audit(root, folder):
    read = lambda p: json.loads(p.read_text('utf-8'))
    report = read(folder / 'index.json'); source_file = root / 'code-clues/ui-properties.json'
    schema = read(source_file)
    rows = list(declarations(schema))
    for row in rows:
        family, name = row['family'], row['name']
        def candidate(prop):
            if family == 'widget':
                return prop['scope'] == 'inherited_properties' and prop['field'].split('.')[0] == name
            if family == 'widget_transform':
                return prop['scope'] == 'inherited_properties' and prop['field'] == 'RenderTransform.explicit_properties.' + name
            return prop['scope'] == 'explicit_properties' and prop['owner'] == row['owner'] and prop['field'] == name
        matches = {key: prop for key, prop in report['properties'].items() if candidate(prop)}
        row['candidate_observation_fields'] = sorted(matches)
        row['observations'] = sum(p['observations'] for p in matches.values())
        row['decoded_owner_types'] = sorted({p['owner'] for p in matches.values()})
        row['status'] = 'historical_declaration_requires_review'
        row['default_and_application'] = 'unresolved'
        row['decoder_probe'] = probe(schema, row['descriptor']) if family == 'widget' else dict(state='container_decoder_not_probed_here')
    executable = Path(schema['source'])
    actual = sha(executable) if executable.is_file() else None
    fingerprints = dict(catalog_scan=sha(folder / 'index.json'), native_schema=sha(source_file),
        audit=sha(Path(__file__)), widget_decoder=sha(HERE / 'decode-widget-properties.py'),
        header_decoder=sha(HERE / 'decode-canvas-slots.py'), installed_exe=actual)
    identity = hashlib.sha256(json.dumps(fingerprints, sort_keys=True).encode()).hexdigest()
    return dict(schema=1, id=identity, dataset=report['dataset_id'], fingerprints=fingerprints,
        native_source=dict(file=str(source_file), declared_exe_sha256=schema['sha256'],
            path=schema['source'], installed_exe_sha256=actual, installed_matches=actual == schema['sha256'],
            status='saved_schema_not_reverified_descriptor_bytes'),
        statistics=dict(declarations=len(rows), widget_fields=len(schema['widget']['serialized_properties']),
            excluded_nested_descriptors=len(schema['widget']['nested_descriptor_indices']),
            declarations_without_observed_values=sum(not row['observations'] for row in rows)),
        declarations=rows, family_index={family: {r['name']: r['id'] for r in rows if r['family'] == family} for family in ('widget', 'widget_transform', 'size_box', 'scale_box')},
        limits=['Совпадения полей — кандидаты связей объявление / наблюдение, не перенос на все классы Widget.',
            'Схема относится к указанному историческому SHA; адреса не читаются по текущему EXE.',
            'Fixtures проверяют декодер, не native handler, defaults или runtime применение.',
            'Brush / Font / тексты / NkButton и остальные семейства ещё не покрыты этой схемой.'])


def tasks(report):
    lines = ['# Объявленные нативные свойства: аудит', '', 'Набор аудита: `' + report['id'] + '`.', '',
        'Историческая схема; совместимость с установленным клиентом и применение не подтверждены.',
        'Проверки fixtures и наличие наблюдений не закрывают чекбокс.', '']
    for row in report['declarations']:
        lines.append('- [ ] ' + row['id'] + '. `' + row['owner'] + '.' + row['name'] + '` · наблюдений: ' + str(row['observations']))
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('folder', type=Path)
    p.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--tasks', type=Path)
    args = p.parse_args()
    if args.output.exists():
        p.error('Сохранённый отчёт не перезаписывается: задайте новое имя')
    if args.tasks and args.tasks.exists():
        p.error('Существующие результаты проверки не перезаписываются')
    result = audit(args.root, args.folder)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    if args.tasks:
        args.tasks.write_text(tasks(result), 'utf-8')
    print(json.dumps(dict(output=str(args.output), id=result['id'], **result['statistics'], installed_matches=result['native_source']['installed_matches']), ensure_ascii=False))
