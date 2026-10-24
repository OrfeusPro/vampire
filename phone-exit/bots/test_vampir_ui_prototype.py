"""Offline checks for complete catalog accounting and non-destructive update tasks."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).parent / 'resource-tools/vampir'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load('ui_prototype_builder', 'build-ui-prototype.py')
task_sync = load('ui_prototype_tasks', 'sync-ui-window-tasks.py')
verifier = load('ui_prototype_verifier', 'verify-ui-prototype.py')


class PrototypeTests(unittest.TestCase):
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
