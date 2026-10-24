"""Reuse historical extracted originals; never infer live brush bindings."""
import csv
import hashlib
import json
from collections import defaultdict


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def texture_candidates(images):
    result = defaultdict(list)
    for row in images:
        result[row['asset_path'].rsplit('/', 1)[-1]].append(row)
    return result


def button_families(names):
    # On is not assumed to be hover; only the explicit Press suffix is paired.
    return [dict(normal=n, pressed=n + '_Press' if n + '_Press' in names else None,
                 binding='name_candidate', hover=None, disabled=None)
            for n in sorted(names) if n.startswith('BTN_') and not n.endswith(('_Press', '_On'))]


def build(root, images):
    inputs = {}
    def load(relative):
        path = root / relative
        inputs[relative] = digest(path)
        return json.loads(path.read_text('utf-8'))
    enums = load('code-clues/native-enums.json')
    index = load('table-study/index.json')
    def table(filename):
        metadata = next(x for x in index['tables'] if x['file'] == filename)
        relative = 'table-study/' + filename
        path = root / relative
        inputs[relative] = digest(path)
        if inputs[relative] != metadata['sha256']:
            raise ValueError('Изменилась таблица: ' + relative)
        with path.open(encoding='utf-8-sig', newline='') as stream:
            return list(csv.DictReader(stream)), dict(file=relative, sha256=inputs[relative],
                entry=metadata['entry'], archive=metadata['source'], archive_full_sha256=None)
    definitions, definition_source = table('ProjectRED-Windows-6076.csv')
    labels, label_source = table('ProjectRED-Windows-6096.csv')
    by_value = {int(x['value']): x for x in enums['enums']['EAsset']}
    by_label = {x['AssetType']: (i, x) for i, x in enumerate(labels, 2)}
    candidates = texture_candidates(images)
    currencies = []
    for record, row in enumerate(definitions, 2):
        value = int(row['AssetType'])
        enum = by_value.get(value)
        symbol = enum['name'].split('::')[-1] if enum else None
        label = by_label.get(symbol)
        currencies.append(dict(id='asset:' + str(value), value=value, symbol=symbol,
            name_en=label[1]['Name'] if label else None, data=row,
            texture_candidates=[x['asset_path'] for x in candidates.get(row['Img'], [])],
            source=dict(definition=dict(definition_source, csv_record=record),
                enum=dict(file='code-clues/native-enums.json', executable_sha256=enums['sha256'], entry=enum),
                label=dict(label_source, csv_record=label[0]) if label else None)))
    currency_paths = {p for c in currencies for p in c['texture_candidates']}
    originals = [x for x in images if x['asset_path'] in currency_paths or x['asset_path'].rsplit('/', 1)[-1].startswith(
        ('BTN_', 'IMG_Asset_', 'IMG_Flat_', 'TEX_GradeBG', 'TEX_Inventory', 'PopUp_'))]
    textures = []
    for row in originals:
        if digest(root / row['file']) != row['sha256']:
            raise ValueError('Изменилась оригинальная текстура: ' + row['asset_path'])
        textures.append(dict(row, id='texture:' + row['asset_path'], status='historical_extraction'))
    return dict(schema=1, status='historical_not_current_verified', inputs=inputs,
        currencies=currencies, textures=textures,
        buttons=button_families({x['asset_path'].rsplit('/', 1)[-1] for x in originals}),
        unresolved_enum_values=[x for x in by_value.values() if int(x['value']) not in {c['value'] for c in currencies}],
        unknown=['OwnerType хранится как исходное число; область владения не доказана.',
                 'Русские подписи демо — перевод прототипа, не извлечённая локализация.',
                 'Имена текстур не доказывают brush binding и состояния конкретного контрола.',
                 'Архив таблиц имеет sample SHA; полный SHA архива неизвестен.',
                 'Рамки, слоты, вкладки и общие попапы требуют отдельных привязок.']), originals
