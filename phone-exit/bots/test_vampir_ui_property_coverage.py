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
spec = importlib.util.spec_from_file_location('game_ui_verify', HERE / 'verify-game-ui-data.py')
game_verify = importlib.util.module_from_spec(spec); spec.loader.exec_module(game_verify)


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
    def test_saved_spatial_verifier_detects_removed_links_and_forged_pointers(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); atlas = root / 'maps/atlas'; atlas.mkdir(parents=True)
            tables = {k: [] for k in game_data.SPATIAL_TABLES}
            tables['World'] = [dict(Id='1', MapId='99')]
            overlay = dict(tiles=[dict(id=1, vertices=[[0, 0]], polygons=[[0]], bounds=[0, 0, 0, 0], height_range=[0, 0])],
                special_links=[], navigation_filter_presets=[], coordinate_space='world_xy', navigation_ready=False,
                stats=dict(tiles=1, surface_polygons=1))
            lifts = dict(lifts=[]); inputs = {}
            for name, value in [('tables.json', tables), ('navigation-overlay.json', overlay), ('lift-preview.json', lifts)]:
                path = atlas / name; path.write_text(json.dumps(value), 'utf-8')
                inputs['maps/atlas/' + name] = game_data.sha(path)
            nodes, edges = game_data.spatial_graph(tables, {})
            inventory = game_data.overlay_inventory(overlay, lifts)
            report = dict(inputs=inputs, nodes=nodes, relations=edges, reverse={'Map:99': edges},
                spatial_inventory=inventory, spatial_properties=game_data.spatial_properties(tables, inventory))
            self.assertEqual(game_verify.verify_spatial(root, report)['unresolved_spatial_relations'], 1)
            forged = copy.deepcopy(report); forged['relations'] = []; forged['reverse'] = {}
            with self.assertRaisesRegex(ValueError, 'связи'):
                game_verify.verify_spatial(root, forged)
            forged = copy.deepcopy(report); forged['spatial_inventory']['objects']['NavTile:1']['pointer'] = '/tiles/99'
            with self.assertRaisesRegex(ValueError, 'указатели'):
                game_verify.verify_spatial(root, forged)
            forged = copy.deepcopy(report); forged['reverse'] = {}
            with self.assertRaisesRegex(ValueError, 'Обратный'):
                game_verify.verify_spatial(root, forged)

    def test_spatial_joins_preserve_missing_targets_and_reject_conflicting_world_spots(self):
        tables = {k: [] for k in game_data.SPATIAL_TABLES}
        tables['World'] = [dict(Id='1', MapId='999', StartSpotInfoId='2')]
        tables['WorldSpot'] = [dict(Id='2', WorldInfoId='1', PosZ='20')]
        tables['NpcSpawn'] = [dict(Id='3', WorldInfoId='1', NpcInfoId='2')]
        old = {'Npc:2': dict(kind='Npc', id='2', fields=dict(Id='2'))}
        before = copy.deepcopy(tables)
        nodes, edges = game_data.spatial_graph(tables, old)
        self.assertEqual(tables, before)
        self.assertIn('WorldSpot:2', nodes)
        self.assertTrue(any(e['target'] == 'Map:999' and e['status'] == 'unresolved_static_table_reference' for e in edges))
        self.assertTrue(any(e['source'] == 'NpcSpawn:3' and e['target'] == 'Npc:2' for e in edges))
        with self.assertRaisesRegex(ValueError, 'Несогласованные'):
            game_data.spatial_graph(tables, {'WorldSpot:2': dict(kind='WorldSpot', id='2', fields=dict(Id='2', PosZ='21'))})
        tables['World'].append(copy.deepcopy(tables['World'][0]))
        with self.assertRaisesRegex(ValueError, 'Повторный'):
            game_data.spatial_graph(tables, {})

    def test_spatial_inventory_checks_geometry_without_promoting_it_to_routes(self):
        overlay = dict(tiles=[dict(id=7, vertices=[[0, 0], [1, 0], [1, 1]], polygons=[[0, 1, 2]], bounds=[0, 0, 1, 1], height_range=[0, 2])],
            special_links=[dict(id='link', start=[0, 0, 0], end=[1, 1, 2], attachment_verified=False)],
            navigation_filter_presets=[], navigation_ready=False, coordinate_space='world_xy', stats=dict(tiles=1, surface_polygons=1))
        lifts = dict(lifts=[dict(id='7', missing=['RelativeRotation'], world_transform_verified=False)])
        before = copy.deepcopy(overlay)
        inventory = game_data.overlay_inventory(overlay, lifts)
        self.assertEqual(overlay, before)
        self.assertFalse(inventory['source_navigation_ready'])
        self.assertEqual(inventory['objects']['NavTile:7']['pointer'], '/tiles/0')
        self.assertIn('Lift:7', inventory['objects'])
        tables = {k: [] for k in game_data.SPATIAL_TABLES}; tables['World'] = [dict(Id='1')]
        properties = game_data.spatial_properties(tables, inventory)
        ids = {p['owner'] + '.' + p['field']: p['id'] for p in properties}
        tables['World'].append(dict(Id='2'))
        self.assertEqual(ids, {p['owner'] + '.' + p['field']: p['id'] for p in game_data.spatial_properties(tables, inventory)})
        overlay['tiles'][0]['polygons'][0][0] = -1
        with self.assertRaisesRegex(ValueError, 'индекс'):
            game_data.overlay_inventory(overlay, lifts)
        overlay['tiles'][0]['polygons'][0][0] = True
        with self.assertRaisesRegex(ValueError, 'индекс'):
            game_data.overlay_inventory(overlay, lifts)
        overlay['tiles'][0]['polygons'][0][0] = 0
        overlay['stats']['surface_polygons'] = 2
        with self.assertRaisesRegex(ValueError, 'Сводка'):
            game_data.overlay_inventory(overlay, lifts)

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
