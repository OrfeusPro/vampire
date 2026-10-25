"""Source root annotations cannot silently become runtime roots or cross variants."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'resource-tools/vampir'))
import ui_source_roots as roots


class RootAnnotationTests(unittest.TestCase):
    def fixture(self):
        schema = dict(source=dict(catalog_file='a.json', asset_sha256='a', body_sha256='b'),
            blueprint_root=dict(index=10), runtime_root=None, root_candidates=['3'],
            nodes={'2': dict(kind='WidgetTree', source=dict(sha256='tree')),
                   '3': dict(kind='CanvasPanel', source=dict(sha256='canvas'))})
        row = dict(source_file='a.json', asset_sha256='a', body_sha256='b', source_owner_root=10,
            export=dict(index=2, type='WidgetTree', sha256='tree'),
            source_root_widget=dict(index=3, type='CanvasPanel', sha256='canvas'),
            status='explicit_local_root_candidate', runtime_root=None, geometry_verified=False)
        return schema, dict(schema=1, kind='source_widget_tree_roots', records=[row])

    def test_annotation_preserves_runtime_and_solver_candidates(self):
        schema, report = self.fixture()
        result = roots.annotate(schema, report)
        self.assertIsNone(result['runtime_root'])
        self.assertEqual(result['root_candidates'], ['3'])
        self.assertEqual(result['source_widget_trees'], report['records'])
        result['source_widget_trees'][0]['status'] = 'edited'
        self.assertEqual(report['records'][0]['status'], 'explicit_local_root_candidate')

    def test_omitted_and_other_owner_have_no_name_fallback(self):
        schema, report = self.fixture()
        report['records'][0].update(status='omitted_or_null_or_external_root')
        report['records'][0].pop('source_root_widget')
        result = roots.annotate(schema, report)
        self.assertNotIn('source_root_widget', result['source_widget_trees'][0])
        schema, report = self.fixture()
        report['records'][0]['source_owner_root'] = 11
        self.assertEqual(roots.annotate(schema, report)['source_widget_tree_status'], 'not_resolved_no_fallback')

    def test_stale_package_and_changed_export_rejected(self):
        for change in ['package', 'export']:
            schema, report = self.fixture()
            if change == 'package': report['records'][0]['body_sha256'] = 'changed'
            if change == 'export': schema['nodes']['3']['source']['sha256'] = 'changed'
            with self.assertRaises(ValueError): roots.annotate(schema, report)

    def test_unprojected_source_export_is_explicit_gap_not_invented_node(self):
        schema, report = self.fixture()
        schema['nodes'].pop('3')
        result = roots.annotate(schema, report)
        self.assertEqual(result['source_widget_tree_ir_gaps'][0]['export'], 3)
        self.assertNotIn('3', result['nodes'])
        self.assertIsNone(result['runtime_root'])

    def test_split_variant_matches_full_bytes_and_retains_all_archive_provenance(self):
        schema, report = self.fixture()
        schema['source']['catalog_file'] = 'split.json'
        second = copy.deepcopy(report['records'][0])
        second['source_file'] = 'archive.json'
        report['records'].append(second)
        result = roots.annotate(schema, report)
        self.assertEqual(result['source_widget_tree_match_basis'], 'full_package_sha_pair')
        self.assertEqual(len(result['source_widget_trees']), 2)
        self.assertIsNone(result['runtime_root'])
        schema['source']['body_sha256'] = 'different'
        self.assertEqual(roots.annotate(schema, report)['source_widget_trees'], [])

    def test_report_sha_duplicate_and_runtime_promotion_rejected(self):
        _, original = self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'index.json'
            for change in ['valid', 'sha', 'duplicate', 'runtime']:
                report = copy.deepcopy(original)
                if change == 'duplicate': report['records'].append(copy.deepcopy(report['records'][0]))
                if change == 'runtime': report['records'][0]['runtime_root'] = 3
                path.write_text(json.dumps(report), 'utf8')
                digest = roots.cache.sha(path) if change != 'sha' else '0' * 64
                if change == 'valid': self.assertEqual(roots.read(path, digest), report)
                else:
                    with self.assertRaises(ValueError): roots.read(path, digest)


if __name__ == '__main__':
    unittest.main()
