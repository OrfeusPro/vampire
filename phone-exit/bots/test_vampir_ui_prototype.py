"""Offline checks for complete catalog accounting and non-destructive update tasks."""
import importlib.util
import json
import tempfile
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).parent / 'resource-tools/vampir'
sys.path.insert(0, str(HERE))
import shared_ui_library as shared


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load('ui_prototype_builder', 'build-ui-prototype.py')
task_sync = load('ui_prototype_tasks', 'sync-ui-window-tasks.py')
verifier = load('ui_prototype_verifier', 'verify-ui-prototype.py')


class PrototypeTests(unittest.TestCase):
    def test_composition_graph_preserves_variants_unresolved_classes_and_source_controls(self):
        import ui_composition_graph as graph
        def record(path, name, files, controls):
            return dict(id=path, path=path, name=name, variants=[dict(file=f, sha256=f, controls=controls, slots=[]) for f in files])
        control = dict(name='Header', type='WBP_Header_C', export=7, sha256='control SHA')
        missing = dict(name='Unknown', type='WBP_Missing_C', export=8, sha256='unknown SHA')
        records = [record('/Game/Shop', 'WBP_Shop', ['shop'], [control, missing]), record('/Game/Header', 'WBP_Header', ['old', 'new'], [])]
        result = graph.compile_graph(records)
        edge, unknown = result['nodes']['/Game/Shop|shop']['dependencies']
        self.assertEqual(edge['control'], control)
        self.assertEqual(edge['candidates'], ['/Game/Header|new', '/Game/Header|old'])
        self.assertEqual(unknown['status'], 'unresolved_class')
        self.assertEqual(result['statistics']['ambiguous_classes'], 1)
        self.assertEqual(result, graph.compile_graph(list(reversed(records))))
        with self.assertRaisesRegex(ValueError, 'Повторный'):
            graph.compile_graph(records + [records[0]])

    def test_composition_impact_traverses_old_and_new_graphs_and_cycles(self):
        import copy
        import ui_composition_graph as graph
        node = lambda targets: dict(sha256='unchanged', dependencies=[dict(candidates=targets)])
        old = dict(nodes={'leaf': node([]), 'header': node(['leaf', 'screen']), 'screen': node(['header'])})
        new = copy.deepcopy(old)
        new['nodes']['leaf']['sha256'] = 'changed'
        self.assertEqual(graph.compare(old, new)['recheck'], ['header', 'leaf', 'screen'])
        del new['nodes']['leaf']
        new['nodes']['header']['dependencies'] = []
        self.assertEqual(graph.compare(old, new)['removed'], ['leaf'])
        self.assertEqual(graph.compare(old, new)['recheck'], ['header', 'leaf', 'screen'])
        self.assertEqual(graph.compare(old, old)['recheck'], [])

    def test_shared_components_check_nested_widget_classes_and_geometry_ownership(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root / 'ui-catalog').mkdir()
            control = lambda name, kind: dict(name=name, type=kind, export=1, sha256='control SHA')
            rows = [('player.json', 'WBP_Player', control('HP', 'ProgressBar')), ('title.json', 'WBP_Title', control('Player', 'WBP_Player_C')), ('shop.json', 'WBP_Shop', control('Title', 'WBP_Title_C'))]
            for file, name, c in rows:
                (root / 'ui-catalog' / file).write_text(json.dumps(dict(name=name, controls=[c], asset_sha256='asset SHA', body_sha256='body SHA', source='fixture archive', entry=1)), 'utf-8')
            records = [dict(name=name, path='/Game/Test/' + name, variants=[dict(file=file)]) for file, name, c in rows]
            definitions = dict(modules={'player': dict(resource='WBP_Player', catalog_file='player.json', members=['HP'], bindings={'hp': 'hp'}), 'title': dict(resource='WBP_Title', catalog_file='title.json', members=['Player'], dependencies=[dict(control='Player', module='player')])}, consumers=[dict(resource='WBP_Shop', catalog_file='shop.json', control='Title', module='title')], limits=['fixture only'])
            bindings = dict(bindings={'hp': dict(resource='WBP_Player', catalog_file='player.json')})
            result = builder.component_sources(root, definitions, records, bindings)
            self.assertEqual(result['consumers'][0]['control_source']['type'], 'WBP_Title_C')
            self.assertEqual(result['modules']['player']['source']['resource_path'], '/Game/Test/WBP_Player')
            bindings['bindings']['hp']['resource'] = 'WBP_Other'
            with self.assertRaisesRegex(ValueError, 'Геометрия'):
                builder.component_sources(root, definitions, records, bindings)
            bindings['bindings']['hp']['resource'] = 'WBP_Player'
            path = root / 'ui-catalog/title.json'; value = json.loads(path.read_text('utf-8')); value['controls'][0]['type'] = 'WBP_Unrelated_C'; path.write_text(json.dumps(value), 'utf-8')
            with self.assertRaisesRegex(ValueError, 'класс'):
                builder.component_sources(root, definitions, records, bindings)

    def test_desired_tree_retains_source_slots_and_rejects_missing_branches(self):
        import ui_desired_geometry as desired
        controls = [dict(export=1, name='Root', type='Overlay', sha256='root'), dict(export=2, name='Body', type='SizeBox', sha256='body', size_constraints={k: dict(status='explicitly_enabled', value=v) for k, v in [('WidthOverride', 1236), ('HeightOverride', 816)]}), dict(export=3, name='StepUp', type='CanvasPanel', sha256='extra')]
        slots = [dict(decoded=dict(parent_export=1, content_export=2, padding=dict(left=0, top=107, right=0, bottom=0)), provenance=dict(slot_export=10)), dict(decoded=dict(parent_export=1, content_export=3, padding=dict(left=20, top=20, right=20, bottom=20)), provenance=dict(slot_export=11))]
        package = dict(controls=controls, decoded_slots=slots)
        policy = dict(exclude={'StepUp': 'Not rendered in demo; native visibility unknown'})
        tree = desired.compile_tree(package, 'Root', policy)['1']
        self.assertEqual(tree['children'][0]['padding']['top'], 107)
        self.assertEqual(tree['children'][0]['node']['source']['sha256'], 'body')
        self.assertEqual(tree['children'][1]['padding']['top'], 0)
        self.assertIn('native visibility unknown', tree['children'][1]['node']['excluded_reason'])
        with self.assertRaises(ValueError):
            desired.compile_tree(package, 'Root', {})
        with self.assertRaises(ValueError):
            desired.compile_tree(package, 'Root', dict(exclude={'Missing': 'must not silently ignore a stale policy'}))

    def test_desired_tree_does_not_invent_inherited_padding_or_disabled_size_overrides(self):
        import ui_desired_geometry as desired
        leaf = dict(export=2, name='Body', type='SizeBox', sha256='body', size_constraints={k: dict(status='explicitly_enabled', value=100) for k in ['WidthOverride', 'HeightOverride']})
        package = dict(controls=[dict(export=1, name='Root', type='HorizontalBox', sha256='root'), leaf], decoded_slots=[dict(decoded=dict(parent_export=1, content_export=2), provenance=dict(slot_export=10))])
        with self.assertRaisesRegex(ValueError, 'padding'):
            desired.compile_tree(package, 'Root', {})
        result = desired.compile_tree(package, 'Root', dict(omitted_padding_zero=True))['1']
        self.assertTrue(any('padding' in a for a in result['children'][0]['node']['assumptions']))
        leaf['size_constraints']['WidthOverride']['status'] = 'unresolved_default_or_archetype'
        with self.assertRaisesRegex(ValueError, 'размерности'):
            desired.compile_tree(package, 'Root', dict(omitted_padding_zero=True))

    def test_collections_preserve_sources_and_reject_changed_icons(self):
        import ui_collection_catalog as collections
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / 'maps/collections'; target.mkdir(parents=True)
            (root / 'archive-images').mkdir()
            icon = root / 'archive-images/icon.png'; icon.write_bytes(b'historical fixture PNG')
            image = dict(file='archive-images/icon.png', sha256=collections.digest(icon), asset_path='/Old/Icon')
            entry = dict(id='11001', name='Source name', row=dict(CollectionTabId='1', Rarity='0', DisplayOrder='2'), rarity=dict(label='Common'),
                requirements=[dict(item_id='11', row=dict(Id='7', GroupId='11001', Count='1'))], bonuses=[dict(row=dict(Min='3', Max='3'))])
            data = dict(entries=[entry], items={'11': dict(id='11', name='Sword', icon=dict(images=[image]), provenance=dict(entry=194, csv_record=513))}, tabs=[dict(id='1', name='Krvna')], statistics=dict(collections=1, items=1, requirements=1))
            source = target / 'collections.json'; source.write_text(json.dumps(data), 'utf-8')
            metadata = dict(file='collections.json', sha256=collections.digest(source), sources={'historical-input': 'old SHA, not current'})
            (target / 'manifest.json').write_text(json.dumps(metadata), 'utf-8')
            prepared = collections.prepare(root)
            output = root / 'published'; output.mkdir()
            collections.publish(prepared, output, root)
            index = json.loads((output / 'collection-index.json').read_text('utf-8'))
            self.assertEqual(index['source']['original_manifest'], metadata)
            self.assertEqual(index['entries'][0]['id'], '11001')
            items = json.loads((output / index['items']['11']).read_text('utf-8'))
            self.assertEqual(items['11']['provenance']['csv_record'], 513)
            self.assertEqual((output / items['11']['icon']['images'][0]['url']).read_bytes(), icon.read_bytes())
            icon.write_bytes(b'changed original')
            with self.assertRaisesRegex(ValueError, 'иконка'):
                collections.prepare(root)
            source.write_text('changed catalog', 'utf-8')
            with self.assertRaisesRegex(ValueError, 'каталог'):
                collections.prepare(root)

    def test_shared_currency_join_uses_ids_and_rejects_changed_csv(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'table-study').mkdir()
            (root / 'code-clues').mkdir()
            (root / 'code-clues/native-enums.json').write_text(json.dumps(dict(sha256='historical', enums={'EAsset': [dict(name='EAsset::Gold', value=0), dict(name='EAsset::Diamond', value=1)]})), 'utf-8')
            definitions = root / 'table-study/ProjectRED-Windows-6076.csv'
            definitions.write_text('AssetType,Img,OwnerType\n1,Icon,2\n0,Icon,0\n', 'utf-8')
            labels = root / 'table-study/ProjectRED-Windows-6096.csv'
            labels.write_text('AssetType,Name\nGold,Gold label\nDiamond,Diamond label\n', 'utf-8')
            metadata = [dict(file=p.name, sha256=shared.digest(p), entry=i, source={}) for i, p in enumerate([definitions, labels])]
            (root / 'table-study/index.json').write_text(json.dumps(dict(tables=metadata)), 'utf-8')
            (root / 'icon.png').write_bytes(b'fixture')
            registry, _ = shared.build(root, [dict(asset_path='/A/Icon', file='icon.png', sha256=shared.digest(root / 'icon.png'))])
            self.assertEqual([c['symbol'] for c in registry['currencies']], ['Diamond', 'Gold'])
            self.assertEqual([c['name_en'] for c in registry['currencies']], ['Diamond label', 'Gold label'])
            self.assertNotEqual(registry['currencies'][0]['id'], registry['currencies'][1]['id'])
            self.assertEqual(registry['currencies'][0]['texture_candidates'], registry['currencies'][1]['texture_candidates'])
            definitions.write_text('changed', 'utf-8')
            with self.assertRaises(ValueError):
                shared.build(root, [])

    def test_skin_package_sources_are_checked_without_inventing_brush_binding(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'ui-catalog').mkdir(); (root / 'ui-layout-study').mkdir()
            asset, body = root / 'ui-layout-study/test.uasset', root / 'ui-layout-study/test.uexp'
            asset.write_bytes(b'asset fixture'); body.write_bytes(b'body fixture')
            texture = root / 'icon.png'; texture.write_bytes(b'original PNG fixture')
            control = dict(name='ButtonClose', export=1, sha256='control-source')
            metadata = dict(asset_sha256=shared.digest(asset), body_sha256=shared.digest(body))
            catalog = dict(metadata, name='WBP_Test', controls=[control], source={'path': 'archive'}, entry=8)
            package = dict(metadata, names=['/Texture/Close'])
            (root / 'ui-catalog/test.json').write_text(json.dumps(catalog), 'utf-8')
            parsed = root / 'ui-layout-study/test.json'
            parsed.write_text(json.dumps(package), 'utf-8')
            images = [dict(asset_path='/Texture/Close', file='icon.png', sha256=shared.digest(texture))]
            definitions = dict(roles={'close-icon': dict(asset_path='/Texture/Close', catalog_file='test.json', resource='WBP_Test', control='ButtonClose')})
            decode = lambda a, b: dict(names=['/Texture/Close'], exports=[control])
            evidence, originals, inputs = shared.skin_roles(root, images, definitions, decode)
            row = evidence['roles']['close-icon']
            self.assertEqual(row['source']['name_index'], 0)
            self.assertEqual(row['source']['control']['sha256'], 'control-source')
            self.assertFalse(row['runtime_brush_binding_verified'])
            self.assertEqual(originals, images); self.assertIn('ui-layout-study/test.uasset', inputs)
            body.write_bytes(b'changed')
            with self.assertRaises(ValueError): shared.skin_roles(root, images, definitions, decode)
            body.write_bytes(b'body fixture')
            package['names'] = ['/Texture/Other']
            parsed.write_text(json.dumps(package), 'utf-8')
            with self.assertRaises(ValueError): shared.skin_roles(root, images, definitions, decode)

    def test_skin_roles_reject_ambiguous_texture_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            image = dict(asset_path='/Texture/Close')
            with self.assertRaises(ValueError):
                shared.skin_roles(Path(folder), [image, image], dict(roles={'close': dict(asset_path='/Texture/Close')}), lambda a, b: {})

    def test_shared_button_states_do_not_invent_hover(self):
        rows = shared.button_families({'BTN_A', 'BTN_A_Press', 'BTN_A_On', 'BTN_B'})
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['pressed'], 'BTN_A_Press')
        self.assertIsNone(rows[0]['hover'])
        self.assertIsNone(rows[1]['pressed'])

    def test_shared_texture_basename_collisions_remain_candidates(self):
        rows = [dict(asset_path='/A/Icon'), dict(asset_path='/B/Icon')]
        self.assertEqual(len(shared.texture_candidates(rows)['Icon']), 2)

    def test_pathless_roots_are_not_silently_dropped(self):
        index = dict(resource_variants={'/UI/Window': [dict(file='known.json')]}, windows=[
            dict(file='known.json', name='Known'), dict(file='no-path-root-2.json', name='Unknown')])
        entries = builder.catalog_entries(index)
        self.assertEqual({v['file'] for variants in entries.values() for v in variants}, {'known.json', 'no-path-root-2.json'})
        self.assertEqual(entries['unresolved:no-path-root-2.json'][0]['unresolved_name'], 'Unknown')

    def test_update_lists_removal_and_client_sha_changes(self):
        old = dict(resources={'old': 'a', 'changed': 'x'}, images={'icon': 'a'}, client={'sha256': 'old'}, tools={'inspect-ui.py': 'old'})
        new = dict(resources={'new': 'b', 'changed': 'y'}, images={'icon': 'a'}, client={'sha256': 'new'}, tools={'inspect-ui.py': 'new'})
        changes = builder.compare(old, new)
        self.assertEqual(changes['resources'], dict(added=['new'], removed=['old'], changed=['changed']))
        self.assertEqual(changes['images']['changed'], [])
        self.assertEqual(changes['client']['changed'], ['sha256'])
        self.assertEqual(changes['tools']['changed'], ['inspect-ui.py'])

    def test_task_sync_preserves_checked_and_in_progress_entries(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            index_path, tasks = folder / 'index.json', folder / 'tasks.md'
            index = dict(resource_variants={'/UI/A': [dict(file='a')]}, windows=[])
            index_path.write_text(json.dumps(index), 'utf-8')
            self.assertEqual(task_sync.sync(index_path, tasks), 1)
            original = tasks.read_text('utf-8').replace('- [ ] UI-W-', '- [x] UI-W-')
            tasks.write_text(original, 'utf-8')
            index['resource_variants']['/UI/B'] = [dict(file='b')]
            index_path.write_text(json.dumps(index), 'utf-8')
            self.assertEqual(task_sync.sync(index_path, tasks), 1)
            changed = tasks.read_text('utf-8')
            self.assertTrue(changed.startswith(original))
            changed = changed.replace('- [ ] UI-W-', '- [ ] ~ UI-W-')
            tasks.write_text(changed, 'utf-8')
            self.assertEqual(task_sync.sync(index_path, tasks), 0)
            self.assertEqual(changed, tasks.read_text('utf-8'))

    def test_verifier_detects_corrupt_published_assets(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            (folder / 'asset.png').write_bytes(b'expected')
            digest = builder.sha(folder / 'asset.png')
            manifest = dict(id='test', registry_count=0, variant_count=0, resources={}, images={'icon': digest}, implementation={})
            for filename, value in [('manifest.json', manifest), ('registry-index.json', []), ('textures.json', {'icon': {'url': 'asset.png', 'sha256': digest}})]:
                builder.write(folder / filename, value)
            self.assertEqual(verifier.verify(folder)['state'], 'passed')
            (folder / 'asset.png').write_bytes(b'corrupt')
            with self.assertRaisesRegex(AssertionError, 'Changed texture'):
                verifier.verify(folder)


if __name__ == '__main__':
    unittest.main()
