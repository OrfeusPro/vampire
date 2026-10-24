"""Repackage an already extracted historical collection catalog, without guessing rules."""
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(root):
    folder = root / 'maps/collections'
    manifest_path = folder / 'manifest.json'
    manifest = json.loads(manifest_path.read_text('utf-8'))
    if manifest['file'] != 'collections.json':
        raise ValueError('Неожиданный путь каталога коллекций')
    path = folder / manifest['file']
    actual = digest(path)
    if actual != manifest['sha256']:
        raise ValueError('Изменился каталог коллекций')
    data = json.loads(path.read_text('utf-8'))
    ids = [e['id'] for e in data['entries']]
    if len(ids) != len(set(ids)) or any(not x.isascii() or not x.isdecimal() for x in ids):
        raise ValueError('Повторный или некорректный ID коллекции')
    images = {}
    for item_id, item in data['items'].items():
        if item_id != item['id'] or not item_id.isascii() or not item_id.isdecimal():
            raise ValueError('Некорректный ID предмета коллекции')
        # Keep candidates and ambiguity. A unique historical texture is not a brush binding.
        for candidate in item.get('icon', {}).get('images', []):
            relative = Path(candidate['file'])
            if relative.is_absolute() or '..' in relative.parts or relative.parts[0] not in ('archive-images', 'item-icons-float'):
                raise ValueError('Небезопасный путь иконки коллекции')
            source = root / relative
            if digest(source) != candidate['sha256']:
                raise ValueError('Изменилась иконка предмета коллекции: ' + item_id)
            images[candidate['sha256']] = dict(candidate, url='collection-assets/' + candidate['sha256'] + '.png')
    for entry in data['entries']:
        requirement_ids = set()
        for requirement in entry['requirements']:
            row = requirement['row']
            if row['GroupId'] != entry['id'] or row['Id'] in requirement_ids or requirement['item_id'] not in data['items']:
                raise ValueError('Нарушены связи требований коллекции: ' + entry['id'])
            requirement_ids.add(row['Id'])
        if not entry['bonuses']:
            raise ValueError('Нет источника бонусов коллекции: ' + entry['id'])
    inputs = {p.relative_to(root).as_posix(): digest(p) for p in [manifest_path, path]}
    return dict(data=data, images=images, inputs=inputs, source=dict(
        file='maps/collections/collections.json', sha256=actual,
        manifest_sha256=inputs['maps/collections/manifest.json'],
        status='historical_not_current_verified', original_manifest=manifest,
        limits=['Серверные условия доступности, регистрация и область действия бонусов не проверены.',
                'Английские имена сохранены из исторических таблиц; русская локализация не установлена.',
                'Числа бонусов показаны как исходные Min / Max, без предположения о единицах.']))


def publish(prepared, destination, root):
    """Small index on demand; bounded chunks, images only when a detail is opened."""
    def write(relative, value):
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False, separators=(',', ':')), 'utf-8')
    data, chunks, entries, items = prepared['data'], {}, [], {}
    size = 64
    for offset in range(0, len(data['entries']), size):
        rows = data['entries'][offset:offset + size]
        file = 'collection-data/entries-' + str(offset // size) + '.json'
        write(file, {row['id']: row for row in rows})
        chunks[file] = digest(destination / file)
        for row in rows:
            entries.append(dict(id=row['id'], name=row['name'], tab=row['row']['CollectionTabId'],
                rarity=row['rarity']['label'], rarity_id=row['row']['Rarity'],
                order=row['row']['DisplayOrder'], requirements=len(row['requirements']), file=file))
    all_items = list(data['items'].values())
    for offset in range(0, len(all_items), size):
        rows = all_items[offset:offset + size]
        file = 'collection-data/items-' + str(offset // size) + '.json'
        write(file, {row['id']: dict(row, icon=dict(row.get('icon', {}), images=[dict(image,
            url=prepared['images'][image['sha256']]['url']) for image in row.get('icon', {}).get('images', [])])) for row in rows})
        chunks[file] = digest(destination / file)
        for row in rows:
            items[row['id']] = file
    write('collection-index.json', dict(schema=1, entries=entries, items=items, chunks=chunks,
        tabs=[dict(id=row['id'], name=row['name']) for row in data['tabs']], source=prepared['source'],
        statistics=data['statistics'], chunk_size=size))
    (destination / 'collection-assets').mkdir(exist_ok=True)
    for image in prepared['images'].values():
        # Content-addressed filenames keep older texture variants separate.
        content = (root / image['file']).read_bytes()
        if hashlib.sha256(content).hexdigest() != image['sha256']:
            raise ValueError('Иконка коллекции изменилась во время сборки')
        (destination / image['url']).write_bytes(content)
