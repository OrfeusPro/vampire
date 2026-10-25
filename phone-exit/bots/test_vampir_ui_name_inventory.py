"""Uppercase UI cohort must use names, preserve unresolved variants and reject stale registry identities."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'
spec = importlib.util.spec_from_file_location('ui_names', HERE / 'inventory-ui-names.py')
names = importlib.util.module_from_spec(spec)
spec.loader.exec_module(names)


def fixture():
    paths = ['/Game/RED/UI/WBP_MainUI', '/Game/RED/UI/WBP_MainUI_JP',
             '/Game/RED/UI/WBP_ItemT', '/Game/Other/WBP_MixedUi']
    groups = {path: [dict(file=str(i) + '.json')] for i, path in enumerate(paths)}
    groups[paths[0]].append(dict(file='historical-main.json'))
    index = dict(resource_variants=groups, windows=[dict(file='orphan.json', name='WBP_OrphanUI'),
                                                  dict(file='orphan-component.json', name='WBP_OrphanT')])
    entries = names.builder.catalog_entries(index)
    registry = [dict(path=path, id='W-' + hashlib.sha256(path.encode()).hexdigest()[:12],
                     name=variants[0].get('unresolved_name', path.rsplit('/', 1)[-1]),
                     variants=len(variants), status='structure_only') for path, variants in entries.items()]
    return index, registry


class UiNameInventoryTests(unittest.TestCase):
    def test_name_path_case_and_suffix_have_distinct_cohorts(self):
        index, registry = fixture()
        value = names.compile_inventory(index, registry)
        selected = [r['name'] for r in value['records'] if r['flags']['name_contains_UI']]
        self.assertEqual(set(selected), {'WBP_MainUI', 'WBP_MainUI_JP', 'WBP_OrphanUI'})
        self.assertEqual(value['counts']['name_contains_UI_resources'], 3)
        self.assertEqual(value['counts']['name_contains_UI_variants'], 4)
        self.assertEqual(value['counts']['name_ends_UI_resources'], 2)
        self.assertEqual(value['counts']['path_only_UI_resources'], 1)
        mixed = next(r for r in value['records'] if r['name'] == 'WBP_MixedUi')
        self.assertFalse(mixed['flags']['name_contains_UI'])
        self.assertTrue(mixed['flags']['case_insensitive_search_UI'])
        self.assertEqual({r['review_state'] for r in value['records']}, {'not_reviewed'})

    def test_unresolved_identity_matches_existing_task_hash(self):
        index, registry = fixture()
        row = next(r for r in names.compile_inventory(index, registry)['records'] if r['name'] == 'WBP_OrphanUI')
        self.assertEqual(row['path'], 'unresolved:orphan.json')
        self.assertEqual(row['task_id'], 'UI-W-' + hashlib.sha256(b'unresolved:orphan.json').hexdigest()[:12])
        self.assertEqual(row['name_basis'], 'unresolved_class_name')
        self.assertTrue(row['flags']['unresolved'])

    def test_registry_drift_cannot_silently_change_the_review_cohort(self):
        index, registry = fixture()
        for field, change in [('id', 'W-invented'), ('name', 'WBP_WrongUI'), ('variants', 99)]:
            altered = copy.deepcopy(registry); altered[0][field] = change
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'identity/name/variant'):
                names.compile_inventory(index, altered)
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            names.compile_inventory(index, registry + [registry[0]])
        with self.assertRaisesRegex(ValueError, 'paths differ'):
            names.compile_inventory(index, registry[:-1])

    def test_source_paths_cannot_escape_the_requested_root(self):
        with self.assertRaisesRegex(ValueError, 'leaves'):
            names.child(HERE, '../../outside.json')

    def test_full_inventory_binds_published_snapshot_to_current_catalog_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            catalog_dir = root / 'ui-catalog'; catalog_dir.mkdir()
            snapshot = root / 'maps/ui-prototype/snapshots/test-snapshot'; snapshot.mkdir(parents=True)
            path = '/Game/RED/UI/WBP_ExampleUI'
            index = dict(resource_variants={path: [dict(file='one.json')]}, windows=[])
            identity = hashlib.sha256(path.encode()).hexdigest()[:12]
            registry = [dict(path=path, id='W-' + identity, name='WBP_ExampleUI', variants=1, status='structure_only')]
            def save(destination, value):
                destination.write_text(json.dumps(value), 'utf8')
                return hashlib.sha256(destination.read_bytes()).hexdigest()
            index_sha = save(catalog_dir / 'index.json', index)
            catalog_sha = save(catalog_dir / 'one.json', dict(file='one.json', asset_sha256='a'*64, body_sha256='b'*64, entry=1))
            save(snapshot / 'registry-index.json', registry)
            manifest = dict(id='test-snapshot', inputs={'ui-catalog/index.json': index_sha}, registry_count=1, variant_count=1,
                            resources={path + '|one.json': catalog_sha}, client={'compatibility': 'not_established'})
            save(snapshot / 'manifest.json', manifest)
            save(root / 'maps/ui-prototype/current.json', dict(snapshot='snapshots/test-snapshot/'))
            value = names.build(root)
            self.assertEqual(value['cohorts']['name_contains_UI'], ['UI-W-' + identity])
            self.assertEqual(value['sources']['catalog_files']['one.json']['sha256'], catalog_sha)
            self.assertEqual(value['sources']['published_snapshot']['manifest_sha256'], names.digest((snapshot/'manifest.json').read_bytes()))
            save(catalog_dir / 'one.json', dict(file='one.json', asset_sha256='c'*64, body_sha256='b'*64, entry=1))
            with self.assertRaisesRegex(ValueError, 'SHA map differs'):
                names.build(root)


if __name__ == '__main__':
    unittest.main()
