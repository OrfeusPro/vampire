"""Declaration coverage is separate from observed values and active runtime semantics."""
import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).parent / 'resource-tools/vampir'
spec = importlib.util.spec_from_file_location('coverage_audit', HERE / 'audit-ui-property-coverage.py')
coverage = importlib.util.module_from_spec(spec); spec.loader.exec_module(coverage)
spec = importlib.util.spec_from_file_location('game_ui_data', HERE / 'scan-game-ui-data.py')
game_data = importlib.util.module_from_spec(spec); spec.loader.exec_module(game_data)


def schema():
    rows = [dict(index=i, name=name, gen_flags=flags) for i, (name, flags) in enumerate([
        ('RenderOpacity', 10), ('Visibility', 30), ('UnderlyingType', 0), ('NativeBindings', 22), ('RenderTransform', 25)])]
    return dict(source='absent.exe', sha256='historical SHA',
        widget=dict(array_offset=10, properties=rows, nested_descriptor_indices=[2],
            serialized_properties=[dict(row, schema_index=i) for i, row in enumerate([r for r in rows if r['index'] != 2])]),
        widget_transform=dict(array_offset=20, properties=[dict(index=i, name=n, gen_flags=25 if i < 3 else 10) for i, n in enumerate(['Translation', 'Scale', 'Shear', 'Angle'])]),
        size_box=dict(array_offset=30, properties=[dict(index=0, name='WidthOverride', gen_flags=10)]),
        scale_box=dict(array_offset=40, properties=[dict(index=0, name='Stretch', gen_flags=0)]))


class PropertyCoverageTests(unittest.TestCase):
    def test_spatial_registry_keeps_hashed_evidence_and_rejects_escape(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); atlas = root / 'maps/atlas'; atlas.mkdir(parents=True)
            payload = atlas / 'navigation-overlay.json'; payload.write_text('{}', encoding='utf-8')
            def digest(path):
                return hashlib.sha256(path.read_bytes()).hexdigest()
            data = {
                'index.json': {}, 'geometry-readiness.json': {'navigation_ready': False},
                'lift-preview.json': {'sources': {}},
                'projection.json': {'native_evidence': {'file': 'navigation-overlay.json', 'sha256': digest(payload)}},
                'navigation-overlay-manifest.json': {'file': 'navigation-overlay.json', 'sha256': digest(payload)},
            }
            for name, value in data.items():
                (atlas / name).write_text(json.dumps(value), encoding='utf-8')
            def read(relative):
                return json.loads((root / relative).read_text('utf-8'))
            def tracked(relative, expected):
                if digest(root / relative) != expected:
                    raise ValueError('changed')
            result = game_data.map_registry(root, read, tracked)
            self.assertEqual(len(result), 5)
            self.assertEqual(result['navigation-overlay-manifest.json']['dependencies'][0]['file'], 'maps/atlas/navigation-overlay.json')
            payload.write_text('{"changed":true}', encoding='utf-8')
            with self.assertRaises(ValueError):
                game_data.map_registry(root, read, tracked)
            data['projection.json']['native_evidence']['file'] = '../../../outside.json'
            (atlas / 'projection.json').write_text(json.dumps(data['projection.json']), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'корень'):
                game_data.map_registry(root, read, tracked)

    def test_quest_links_keep_missing_tokens_and_check_explicit_parent_fields(self):
        value = dict(quests=[dict(Id='1', PreQuestId='2|999', previous_id_tokens=['2', '999'], tasks=[dict(Id='10', QuestInfoId='1', TargetSpotInfoId='7', world_spot=dict(Id='7'), actions=[dict(Id='100', TaskId='10', ActionParam='raw')])]), dict(Id='2', tasks=[])])
        before = copy.deepcopy(value); nodes, edges = game_data.quest_graph(value)
        self.assertEqual(value, before)
        self.assertIn('QuestTaskAction:100', nodes)
        self.assertEqual(nodes['Quest:1']['fields']['PreQuestId'], '2|999')
        self.assertTrue(any(e['target'] == 'Quest:999' and e['status'] == 'unresolved_previous_token' for e in edges))
        self.assertTrue(any(e['target'] == 'Quest:2' and 'semantics_unknown' in e['status'] for e in edges))
        value['quests'][0]['tasks'][0]['QuestInfoId'] = '2'
        with self.assertRaisesRegex(ValueError, 'QuestInfoId'):
            game_data.quest_graph(value)

    def test_npc_ids_are_namespaced_and_battle_variants_do_not_collapse(self):
        detail = dict(npc_id='1', npc=dict(Id='1', BattleGroupId='10'), battle=[dict(GroupId='10', HP='100', provenance=dict(csv_record=2)), dict(GroupId='10', HP='200', provenance=dict(csv_record=3))])
        nodes, edges = game_data.npc_graph('1', detail)
        self.assertEqual(len(nodes), 3); self.assertEqual(len(edges), 2)
        self.assertNotIn('Quest:1', nodes)
        self.assertEqual(nodes['Battle:10:record:3']['fields']['HP'], '200')
        detail['battle'][1]['GroupId'] = '11'
        with self.assertRaisesRegex(ValueError, 'BattleGroupId'):
            game_data.npc_graph('1', detail)

    def test_normalized_game_values_are_checked_against_exact_csv_records(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); path = root / 'battle.csv'; path.write_text('GroupId,HP\n10,100\n10,200\n', 'utf-8')
            report = dict(dataset_id='fixture', inputs={'battle.csv': game_data.sha(path)}, table_schemas={'1': dict(file='battle.csv', sha256=game_data.sha(path))}, nodes={'Battle:10:record:3': dict(kind='Battle', id='10', fields=dict(GroupId='10', HP='200', provenance=dict(entry=1, csv_record=3)))})
            self.assertEqual(game_data.verify_rows(root, report)['records'], 1)
            report['nodes']['Battle:10:record:3']['fields']['HP'] = '999'
            with self.assertRaisesRegex(ValueError, 'CSV'):
                game_data.verify_rows(root, report)
            report['nodes']['Battle:10:record:3']['fields']['HP'] = '200'
            report['nodes']['Battle:10:record:3']['fields']['provenance']['csv_record'] = 1
            with self.assertRaisesRegex(ValueError, 'логической'):
                game_data.verify_rows(root, report)

    def test_nested_descriptors_do_not_shift_unversioned_field_indices(self):
        value = schema(); before = copy.deepcopy(value)
        rows = list(coverage.declarations(value))
        self.assertEqual(len(rows), 10)
        self.assertEqual([r['name'] for r in rows if r['family'] == 'widget'], ['RenderOpacity', 'Visibility', 'NativeBindings', 'RenderTransform'])
        self.assertEqual(value, before)
        value['widget']['serialized_properties'][2]['schema_index'] = 3
        with self.assertRaisesRegex(ValueError, 'schema_index'):
            list(coverage.declarations(value))

    def test_serialized_zero_absence_and_nonempty_bindings_remain_distinct(self):
        value = schema(); fields = {r['name']: r for r in value['widget']['serialized_properties']}
        opacity = coverage.probe(value, fields['RenderOpacity'])
        self.assertEqual(opacity['serialized_zero']['value'], 0)
        self.assertEqual(opacity['nonzero']['value'], .625)
        transform = coverage.probe(value, fields['RenderTransform'])
        self.assertEqual(transform['serialized_zero']['value'], {'serialized_zero': True})
        self.assertEqual(transform['nonzero']['value']['explicit_properties']['Scale'], [1.5, 1.5])
        bindings = coverage.probe(value, fields['NativeBindings'])
        self.assertEqual(bindings['nonzero']['state'], 'unsupported_fixture')
        self.assertEqual(bindings['explicit_empty_array']['value'], [])
        self.assertIn('unresolved', bindings['absent_default'])

    def test_metadata_names_do_not_become_observed_native_values_or_current_compatibility(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root / 'code-clues').mkdir(); (root / 'scan').mkdir()
            value = schema(); exe = root / 'current.exe'; exe.write_bytes(b'fixture executable')
            value['source'] = str(exe)
            (root / 'code-clues/ui-properties.json').write_text(json.dumps(value), 'utf-8')
            report = dict(dataset_id='fixture', properties={
                'metadata': dict(scope='catalog_control', owner='SizeBox', field='RenderOpacity', observations=99),
                'actual': dict(scope='inherited_properties', owner='SizeBox', field='RenderOpacity', observations=3)})
            (root / 'scan/index.json').write_text(json.dumps(report), 'utf-8')
            result = coverage.audit(root, root / 'scan')
            opacity = next(r for r in result['declarations'] if r['family'] == 'widget' and r['name'] == 'RenderOpacity')
            self.assertEqual(opacity['candidate_observation_fields'], ['actual'])
            self.assertEqual(opacity['observations'], 3)
            self.assertFalse(result['native_source']['installed_matches'])
            self.assertEqual(result['native_source']['installed_exe_sha256'], hashlib.sha256(exe.read_bytes()).hexdigest())
            self.assertEqual(opacity['default_and_application'], 'unresolved')


if __name__ == '__main__':
    unittest.main()
