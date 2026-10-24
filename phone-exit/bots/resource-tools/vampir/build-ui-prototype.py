"""Build isolated offline demo from existing extracted catalogs; never connect to game.

Catalog geometry and texture membership are evidence, not proved runtime bindings.
Snapshots are content addressed and previous builds remain available for comparison.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
import shared_ui_library
import ui_collection_catalog

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[1] / 'vampir' / 'ui-prototype'


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def read(path):
    return json.loads(path.read_text('utf-8'))


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), 'utf-8')


def catalog_entries(index):
    """Retain root classes with no resolved resource path as explicit unknowns."""
    entries = {path: list(variants) for path, variants in index['resource_variants'].items()}
    included = {row['file'] for variants in entries.values() for row in variants}
    for row in index['windows']:
        if row['file'] not in included:
            entries['unresolved:' + row['file']] = [dict(file=row['file'], unresolved_name=row['name'])]
    return entries


def compare(old, new):
    """Content changes only; paths and timestamps alone are not compatibility."""
    changes = {}
    for group in ('resources', 'images', 'inputs', 'implementation', 'client', 'tools'):
        left, right = old.get(group, {}), new.get(group, {})
        changes[group] = {
            'added': sorted(right.keys() - left.keys()),
            'removed': sorted(left.keys() - right.keys()),
            'changed': sorted(k for k in left.keys() & right.keys() if left[k] != right[k]),
        }
    return changes


def skill_sources(root):
    """Publish only the curated demo set; preserve historical source records."""
    inputs = {}
    def tracked(relative, expected=None):
        path = root / relative
        inputs[relative] = sha(path)
        if expected and inputs[relative] != expected:
            raise ValueError('Изменился источник навыков: ' + relative)
        return read(path)
    class_manifest = tracked('maps/catalog-classes-manifest.json')
    classes = tracked('maps/' + class_manifest['file'], class_manifest['sha256'])
    monster_manifest = tracked('maps/atlas/monster-manifest.json')
    index_spec = monster_manifest['skill_index']
    index = tracked('maps/atlas/' + index_spec['file'], index_spec['sha256'])['skills']
    declared = {}
    for class_id, group in re.findall(r'^\s+(\w+): \[(.+)\],?$', (SOURCE / 'skills.js').read_text('utf-8'), re.MULTILINE):
        for skill_id in re.findall(r"\['(\d+)',", group):
            if skill_id in declared:
                raise ValueError('Повторный навык в демокаталоге: ' + skill_id)
            declared[skill_id] = class_id
    if len(declared) != 15:
        raise ValueError('Демокаталог должен явно объявлять 15 навыков пяти классов')
    ids = sorted(declared)
    evidence, images = {}, []
    for skill_id in ids:
        spec = index[skill_id]['detail']
        relative = 'maps/atlas/' + spec['file']
        detail = tracked(relative, spec['sha256'])
        binding = classes['skills'][skill_id]
        if binding['keys'] != [declared[skill_id]] or detail['record']['ClassType'] != declared[skill_id]:
            raise ValueError('Неоднозначный класс навыка: ' + skill_id)
        candidates = detail['images']['Img']['images']
        if len(candidates) != 1:
            raise ValueError('Неоднозначная иконка навыка: ' + skill_id)
        images.extend(candidates)
        evidence[skill_id] = dict(detail=detail, class_binding=binding,
            source=dict(file=relative, sha256=inputs[relative], classes_sha256=inputs['maps/' + class_manifest['file']],
                        client_exe_sha256=classes['client_exe_sha256']),
            icon=candidates[0]['asset_path'], status='historical_not_current_verified',
            demo_rules='Русские названия, обучение, уровни, MP и перезарядка — правила демо из skills.js; серверное применение не проверено.')
    return evidence, images, inputs


def build(root, baseline=None):
    index_path = root / 'ui-catalog/index.json'
    index = read(index_path)
    image_path = root / 'archive-image-latest.json'
    images = read(image_path)
    shared, originals = shared_ui_library.build(root, images)
    skin_evidence, skin_images, skin_inputs = shared_ui_library.skin_roles(root, images, read(SOURCE / 'skin-roles.json'))
    known_shared = {row['asset_path'] for row in shared['textures']}
    for row in skin_images:
        if row['asset_path'] not in known_shared:
            shared['textures'].append(dict(row, id='texture:' + row['asset_path'], status='historical_extraction'))
            known_shared.add(row['asset_path'])
    skill_evidence, skill_images, skill_inputs = skill_sources(root)
    collection_catalog = ui_collection_catalog.prepare(root)
    # All texture membership is recorded as historical extraction, not active brushes.
    selected = {}
    exact = {'BG_Title', 'BG_PAC', 'BG_Portrait', 'BTN_ConfirmRed256',
             'BTN_ConfirmBlack256', 'PopUp_Default_Title_texture',
             'PopUp_DefaultBG_texture_01', 'IMG_Weapon_BloodSword_Rare_03',
             'IMG_Armor_Helmet_Common_01', 'IMG_Armor_Armor_Common_01',
             'IMG_Item_Subscription_01', 'IMG_MatrixEnchantMaterial_02'}
    prefixes = ('IMG_Flat_', 'IMG_Class_', 'IMG_Customize_',
                'IMG_Portrait_Abigail', 'IMG_Portrait_Damir')
    images_by_name = {x['asset_path'].rsplit('/', 1)[-1]: x for x in images}
    for row in images:
        name = row['asset_path'].rsplit('/', 1)[-1]
        if name in exact or name.startswith(prefixes):
            selected[name] = row
    # Short aliases are allowed only when unambiguous; full paths retain all originals.
    candidates = shared_ui_library.texture_candidates(images)
    for row in originals:
        selected[row['asset_path']] = row
        name = row['asset_path'].rsplit('/', 1)[-1]
        if len(candidates[name]) == 1:
            selected[name] = row
        else:
            selected.pop(name, None)
    for row in skill_images:
        selected[row['asset_path']] = row
    for row in skin_images:
        selected[row['asset_path']] = row
    # Item names/icons remain source data. Quantities, prices, balances are demo.
    items = read(root / 'maps/loot/items.json')
    demo_items = []
    for key, row in items.items():
        data = row.get('data', {})
        icon = str(data.get('Img', '')).rsplit('/', 1)[-1].split('.')[0]
        matches = [images_by_name[icon]] if icon in images_by_name else []
        if not matches and isinstance(row.get('icon'), dict):
            matches = row['icon'].get('images', [])[:1]
            if matches:
                icon = matches[0]['asset_path'].rsplit('/', 1)[-1]
        if not matches:
            continue
        selected[icon] = matches[0]
        demo_items.append(dict(id=key, name=row.get('name') or row.get('title') or row.get('names_en') or icon,
                               icon=icon, source=row.get('provenance'),
                               data={k: data.get(k) for k in ('Id', 'Type', 'EquipmentType', 'Rarity', 'Img')}))
        if len(demo_items) == 36:
            break
    records, resources = [], {}
    for path, variants in sorted(catalog_entries(index).items()):
        record = dict(id='W-' + hashlib.sha256(path.encode()).hexdigest()[:12],
                      path=path, name=variants[0].get('unresolved_name', path.rsplit('/', 1)[-1]), variants=[],
                      resource_path_resolved=not path.startswith('unresolved:'),
                      status='structure_only', unknown=['Поведение и активный вариант не подтверждены'])
        for variant in variants:
            file = root / 'ui-catalog' / variant['file']
            package = read(file)
            fingerprint = sha(file)
            resources[path + '|' + variant['file']] = fingerprint
            record['variants'].append(dict(file=variant['file'], sha256=fingerprint,
                source=package.get('source'), entry=package.get('entry'),
                asset_sha256=package.get('asset_sha256'), body_sha256=package.get('body_sha256'),
                root=package.get('root_export'), popup=package.get('popup', False),
                controls=[{k: c.get(k) for k in ('name', 'type', 'export', 'sha256', 'parent_chain',
                                               'local_slots', 'size_constraints', 'container_geometry')}
                          for c in package.get('controls', [])],
                slots=package.get('decoded_slots', [])))
        records.append(record)
    inputs = {str(p.relative_to(root)).replace('\\', '/'): sha(p) for p in
              (index_path, image_path, root / 'maps/loot/items.json', root / 'maps/atlas/index.json')}
    source_inputs = {p.name: sha(p) for p in sorted(SOURCE.iterdir()) if p.is_file()}
    inputs.update(shared['inputs'])
    inputs.update(skill_inputs)
    inputs.update(skin_inputs)
    inputs.update(collection_catalog['inputs'])
    for profile in read(SOURCE / 'window-layouts.json')['profiles'].values():
        reference = profile.get('reference_resource')
        if reference:
            path = root / reference['file']
            if sha(path) != reference['sha256']:
                raise ValueError('Изменился эталон окна: ' + reference['file'])
            inputs[reference['file']] = reference['sha256']
    source_inputs['shared_ui_library.py'] = sha(HERE / 'shared_ui_library.py')
    schema_match = re.search(r'\bconst SCHEMA = (\d+),', (SOURCE / 'model.js').read_text('utf-8'))
    if not schema_match:
        raise ValueError('Demo state schema is not declared')
    state_schema = int(schema_match.group(1))
    image_hashes = {}
    for name, row in selected.items():
        path = root / row['file']
        actual = sha(path)
        if actual != row['sha256']:
            raise ValueError('Изменилось изображение: ' + name)
        image_hashes[name] = actual
    exe = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
    client = dict(path=str(exe), sha256=sha(exe) if exe.exists() else None,
                  version='не определена автоматически', compatibility='not_established')
    data_id = hashlib.sha256(json.dumps(dict(resources=resources, images=image_hashes,
        inputs=inputs, schema=1), sort_keys=True).encode()).hexdigest()
    fingerprint = dict(resources=resources, images=image_hashes, inputs=inputs,
                       implementation=source_inputs, client=client, builder_sha256=sha(Path(__file__)),
                       tools={'inspect-ui.py': skin_evidence['decoder']['sha256'],
                              'ui_collection_catalog.py': sha(HERE / 'ui_collection_catalog.py')})
    identity = hashlib.sha256(json.dumps(fingerprint, sort_keys=True).encode()).hexdigest()
    out = root / 'maps/ui-prototype'
    snapshots = out / 'snapshots'
    snapshots.mkdir(parents=True, exist_ok=True)
    destination = snapshots / identity
    if not destination.exists():
        temporary = snapshots / (identity + '.building')
        temporary.mkdir(exist_ok=True)
        (temporary / 'assets').mkdir(exist_ok=True)
        texture_map = {}
        shutil.copyfile(HERE / "shared_ui_library.py", temporary / "shared_ui_library.py")
        for name, row in selected.items():
            filename = Path(row['file']).name
            shutil.copyfile(root / row['file'], temporary / 'assets' / filename)
            texture_map[name] = dict(url='assets/' + filename, sha256=row['sha256'],
                                     source=row['asset_path'], entry=row.get('entry'),
                                     archive=row.get('source'), status='historical_extraction')
        for path in SOURCE.iterdir():
            if path.is_file() and '.test.' not in path.name:
                shutil.copyfile(path, temporary / path.name)
        (temporary / 'windows').mkdir(exist_ok=True)
        for record in records:
            write(temporary / 'windows' / (record['id'] + '.json'), record)
        # Separate small index avoids loading all control geometry for normal screens.
        write(temporary / 'registry-index.json', [dict(id=x['id'], name=x['name'], path=x['path'],
            popup=any(v['popup'] for v in x['variants']), variants=len(x['variants']),
            controls=max(len(v['controls']) for v in x['variants']), status=x['status']) for x in records])
        manifest = dict(fingerprint, id=identity, data_id=data_id, state_schema=state_schema, built_at=datetime.now(timezone.utc).isoformat(),
            schema=1, registry_count=len(records), variant_count=sum(len(x['variants']) for x in records),
            limits=['Исторический каталог не подтверждает совместимость с установленным клиентом.',
                    'Размещение веб-интерфейса адаптировано; runtime DPI и brush bindings не подтверждены.',
                    'Цены, количества, персонажи, задания и действия — демонстрационные.',
                    'Каталог структуры не является реализацией всех игровых сценариев.'])
        write(temporary / 'manifest.json', manifest)
        write(temporary / 'textures.json', texture_map)
        for row in shared['textures']:
            row['url'] = texture_map[row['asset_path']]['url']
        write(temporary / 'shared-elements.json', shared)
        write(temporary / 'skin-evidence.json', skin_evidence)
        write(temporary / 'skin-tokens.json', {key: dict(url=texture_map[role['asset_path']]['url'],
            sha256=role['texture']['sha256'], asset_path=role['asset_path'],
            status=role['status'], runtime_brush_binding_verified=False) for key, role in skin_evidence['roles'].items()})
        write(temporary / 'skills-evidence.json', skill_evidence)
        write(temporary / 'skills-index.json', {key: dict(icon=row['icon'], class_id=row['detail']['record']['ClassType'], names=row['detail']['display_names']) for key, row in skill_evidence.items()})
        write(temporary / 'items.json', demo_items)
        ui_collection_catalog.publish(collection_catalog, temporary, root)
        layouts = read(SOURCE / 'window-layouts.json')
        for profile in layouts['profiles'].values():
            package = read(root / 'ui-catalog' / profile['catalog_file'])
            if package['name'] != profile['resource']:
                raise ValueError('Layout resource does not match catalog')
            profile['source'] = dict(catalog_sha256=sha(root / 'ui-catalog' / profile['catalog_file']),
                asset_sha256=package['asset_sha256'], body_sha256=package['body_sha256'],
                entry=package['entry'], archive=package['source'],
                slots=[s['provenance'] for s in package['decoded_slots']],
                size_constraints=[dict(name=c['name'], export=c['export'], values=c['size_constraints'])
                                  for c in package['controls'] if c.get('size_constraints')])
            reference = Path('C:/Users/754C~1/AppData/Local/Temp') / profile['reference'] if profile.get('reference') else None
            profile['reference_sha256'] = profile.get('reference_resource', {}).get('sha256') or (sha(reference) if reference and reference.exists() else None)
            profile['runtime_geometry_verified'] = False
        write(temporary / 'placement-evidence.json', layouts)
        button_layouts = read(SOURCE / 'button-layouts.json')
        for binding in button_layouts['bindings'].values():
            package_file = root / 'ui-catalog' / binding['catalog_file']
            package = read(package_file)
            if package['name'] != binding['resource']:
                raise ValueError('Button resource mismatch: ' + binding['control'])
            controls = package['controls']
            candidates = [c for c in controls if c['name'] == binding['control']]
            if len(candidates) != 1:
                raise ValueError('Ambiguous button: ' + binding['control'])
            control = candidates[0]
            if 'root_name' in binding:
                roots = [c for c in controls if c['name'] == binding['root_name']]
                if len(roots) != 1:
                    raise ValueError('Ambiguous geometry root')
                binding['root_export'] = roots[0]['export']
            slots = {s['provenance']['slot_export']: s for s in package['decoded_slots']}
            chain = []
            for part in control.get('parent_chain', []):
                if part['slot_export'] not in slots:
                    raise ValueError('Missing button slot')
                chain.append(slots[part['slot_export']])
                if part['parent_export'] == binding['root_export']:
                    break
            if not chain or chain[-1]['decoded']['parent_export'] != binding['root_export']:
                raise ValueError('Geometry root not reached')
            binding['chain'] = chain
            binding['source'] = dict(catalog_sha256=sha(package_file), asset_sha256=package['asset_sha256'],
                                     body_sha256=package['body_sha256'], control_export=control['export'],
                                     control_sha256=control['sha256'])
            binding['runtime_geometry_verified'] = False
        write(temporary / 'button-evidence.json', button_layouts)
        manifest['named_resource_count'] = sum(not r['path'].startswith('unresolved:') for r in records)
        manifest['unresolved_root_count'] = sum(r['path'].startswith('unresolved:') for r in records)
        # Existing atlas runs in an isolated frame, with session polling disabled.
        atlas = (root / 'maps/atlas/world-map.html')
        if not atlas.exists():
            atlas = HERE / 'world-map.html'
        template = atlas.read_text('utf-8')
        csp = ('<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; '
               'img-src \'self\' data:; style-src \'self\' \'unsafe-inline\'; '
               'script-src \'self\'; connect-src \'self\'; object-src \'none\'">')
        template = template.replace('<title>', csp + '<title>', 1)
        template = template.replace('<title>', '<base href="/maps/atlas/"><title>', 1)
        template += ('<link rel="stylesheet" href="/maps/ui-prototype/snapshots/' + identity + '/map.css">'
                     '<script src="/maps/ui-prototype/snapshots/' + identity + '/map-bridge.js"></script>')
        (temporary / 'map.html').write_text(template, 'utf-8')
        manifest['generated_files'] = {p.relative_to(temporary).as_posix(): sha(p)
            for p in temporary.rglob('*') if p.is_file() and p.name != 'manifest.json' and 'assets' not in p.parts}
        write(temporary / 'manifest.json', manifest)
        if any(sha((HERE if name == 'shared_ui_library.py' else SOURCE) / name) != digest for name, digest in source_inputs.items()):
            raise ValueError('Исходники изменились во время сборки. Повторите сборку.')
        temporary.rename(destination)
    current = dict(snapshot='snapshots/' + identity + '/', id=identity)
    write(out / 'current.json.tmp', current)
    os.replace(out / 'current.json.tmp', out / 'current.json')
    (out / 'index.html').write_text('<!doctype html><html lang="ru"><meta charset="utf-8">'
        '<title>Vampir · прототип</title><p id="status">Загрузка интерфейса…</p><script>'
        'fetch("current.json",{cache:"no-store"}).then(r=>{if(!r.ok)throw Error(r.status);return r.json()})'
        '.then(x=>location.replace(x.snapshot+"index.html"+location.search))'
        '.catch(e=>document.getElementById("status").textContent="Ошибка загрузки: "+e.message)'
        '</script></html>', 'utf-8')
    if baseline:
        old = read(baseline)
        changes = compare(old, read(destination / 'manifest.json'))
        write(destination.parent / (old['id'] + '-to-' + identity + '.json'), changes)
        lines = ['# Проверка обновления интерфейса', '', 'Baseline: ' + old['id'], '',
                 'Новый набор: ' + identity, '', 'Клиент SHA256: ' + str(client['sha256']), '',
                 '- [ ] Проверить knowledge-index.py update с явным baseline.',
                 '- [ ] Проверить изменённые окна, тексты, изображения и строки таблиц.',
                 '- [ ] Проверить переходы, геометрию и демосостояние.',
                 '- [ ] Подтвердить совместимость отдельно от результатов предыдущей версии.', '']
        for group, kinds in changes.items():
            for kind, keys in kinds.items():
                lines.extend('- [ ] ' + group + ' / ' + kind + ': `' + key + '`' for key in keys)
        (out / ('UPDATE-' + identity + '.md')).write_text('\n'.join(lines), 'utf-8')
    print(json.dumps(dict(output=str(out / 'index.html'), snapshot=identity,
                         resources=len(records), images=len(selected), items=len(demo_items)), ensure_ascii=False))
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir')))
    parser.add_argument('--baseline', type=Path)
    args = parser.parse_args()
    build(args.root, args.baseline)
