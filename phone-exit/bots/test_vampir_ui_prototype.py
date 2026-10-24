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
        old = dict(resources={'old': 'a', 'changed': 'x'}, images={'icon': 'a'}, client={'sha256': 'old'})
        new = dict(resources={'new': 'b', 'changed': 'y'}, images={'icon': 'a'}, client={'sha256': 'new'})
        changes = builder.compare(old, new)
        self.assertEqual(changes['resources'], dict(added=['new'], removed=['old'], changed=['changed']))
        self.assertEqual(changes['images']['changed'], [])
        self.assertEqual(changes['client']['changed'], ['sha256'])

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
