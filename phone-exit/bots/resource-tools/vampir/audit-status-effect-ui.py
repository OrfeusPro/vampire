"""Audit cooked status-effect UI records without assuming a dynamic entry binding."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('status_imports', HERE / 'build-navigation-filter-resources.py')
imports = importlib.util.module_from_spec(spec); spec.loader.exec_module(imports)
spec = importlib.util.spec_from_file_location('status_headers', HERE / 'decode-canvas-slots.py')
headers = importlib.util.module_from_spec(spec); spec.loader.exec_module(headers)

NAMES = ('WBP_PCStatusUI', 'WBP_OperationPanelIconT', 'ZBP_PCStatusUI_OperationPanelList',
         'ZBP_BossTargetUI_OperationPanelList', 'ZBP_MonsterTargetUI_OperationPanelList',
         'ZBP_PCTargetUI_OperationPanelList', 'WBP_SkillEffectInfoT')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def control_record(control, asset, body):
    start = control['offset'] - len(asset); end = start + control['size']
    if not 0 <= start <= end <= len(body):
        raise ValueError('Export выходит за границы body')
    raw = body[start:end]
    if digest(raw) != control['sha256']:
        raise ValueError('Изменился export контрола')
    reader = headers.Reader(raw)
    try:
        indices = reader.header()
        serialized = [dict(schema_index=index, serialized_zero=zero) for index, zero in indices]
        header = dict(fields=serialized, bytes=reader.pos, payload_bytes=len(raw) - reader.pos,
                      status='indices_only_property_names_types_and_bindings_unknown')
    except (ValueError, IndexError) as error:
        header = dict(status='unsupported_header', reason=str(error))
    return dict(export=control['export'], name=control['name'], type=control['type'],
        sha256=control['sha256'], offset=control['offset'], size=control['size'],
        parent_chain=control['parent_chain'], chain_termination=control['chain_termination'],
        unversioned_header=header,
        properties={k: control[k] for k in ('explicit_properties', 'inherited_properties') if k in control})


def audit(root):
    inputs = {}
    def read(relative):
        raw = (root / relative).read_bytes(); inputs[relative] = digest(raw); return raw
    index = json.loads(read('ui-catalog/index.json'))
    variants = {}
    for window in index['windows']:
        if window['name'] not in NAMES:
            continue
        file = window['file']; catalog = json.loads(read('ui-catalog/' + file))
        source = json.loads(read('ui-layout-study/' + file))
        asset = read('ui-layout-study/' + file.replace('.json', '.uasset'))
        body = read('ui-layout-study/' + file.replace('.json', '.uexp'))
        if digest(asset) != source['asset_sha256'] or digest(body) != source['body_sha256']:
            raise ValueError('Изменились cooked ресурсы')
        if (catalog['asset_sha256'], catalog['body_sha256']) != (source['asset_sha256'], source['body_sha256']):
            raise ValueError('Каталог и cooked пакет относятся к разным источникам')
        exported = {e['index']: e for e in source['exports']}
        for control in catalog['controls']:
            original = exported[control['export']]
            if any(original[k] != control[k] for k in ('name', 'type', 'offset', 'size', 'sha256')):
                raise ValueError('Метаданные контрола не соответствуют export')
        import_rows = imports.package_imports(asset, source['names'])
        variants[file] = dict(name=window['name'], resource_paths=catalog['resource_paths'],
            asset_sha256=source['asset_sha256'], body_sha256=source['body_sha256'],
            imports=import_rows, decoded_slots=catalog['decoded_slots'],
            controls=[control_record(c, asset, body) for c in catalog['controls']],
            package_names=source['names'], active_variant='unresolved')
    by_class = {}
    for file, variant in variants.items():
        by_class.setdefault(variant['name'] + '_C', []).append(file)
    edges = []
    for file, variant in variants.items():
        for control in variant['controls']:
            if control['type'] in by_class:
                edges.append(dict(source=file, export=control['export'], target_candidates=by_class[control['type']],
                    status='nested_class_candidates_active_variant_unknown'))
    if not variants:
        raise ValueError('Не найдены компоненты строки эффектов')
    if any(digest((root / p).read_bytes()) != sha for p, sha in inputs.items()):
        raise ValueError('Источники изменились во время аудита')
    fingerprints = dict(inputs=inputs, audit=digest(Path(__file__).read_bytes()),
        import_reader=digest((HERE / 'build-navigation-filter-resources.py').read_bytes()),
        header_reader=digest((HERE / 'decode-canvas-slots.py').read_bytes()))
    return dict(schema=1, id=digest(json.dumps(fingerprints, sort_keys=True).encode()),
        fingerprints=fingerprints, variants=variants, relations=edges,
        unresolved=['NkTileView entry class / factory binding', 'Effect instance → image Brush binding',
            'Effect stack / remaining time → runtime display', 'Buff panel click → handler / popup',
            'Active variants / source-version compatibility / DPI / dynamic state'],
        limits=['Импорты и names сохраняются как ссылки пакета, не как привязки конкретного свойства.',
            'Unversioned indices не получают имена / типы без проверенной схемы класса.',
            'NkTileView и sample ZBP не соединяются автоматически по имени.',
            'Наличие TextStackCount / ImageIcon / анимации не доказывает runtime updater или handler.',
            'Сохранены все варианты; генерации, команд игры и изменений профилей нет.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Сохранённый отчёт не перезаписывается')
    result = audit(args.root)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(id=result['id'], variants=len(result['variants']),
        controls=sum(len(v['controls']) for v in result['variants'].values()), relations=len(result['relations'])), ensure_ascii=False))
