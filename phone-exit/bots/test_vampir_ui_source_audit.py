"""Source audit rejects stale bytes and never promotes structural checks to UI completion."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent / 'resource-tools/vampir'
spec = importlib.util.spec_from_file_location('source_audit', HERE / 'audit-ui-sources.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class SourceAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'ui-catalog').mkdir()
        (self.root/'ui-layout-study').mkdir()
        asset, body = b'fixture asset', b'fixture body'
        (self.root/'ui-layout-study/test.uasset').write_bytes(asset)
        self.body = self.root/'ui-layout-study/test.uexp'
        self.body.write_bytes(body)
        control = dict(name='Child', type='WBP_Missing_C', export=1, sha256='c'*64,
            parent_chain=[], local_slots=[], size_constraints=None, container_geometry=None)
        self.variant = dict(file='test.json', asset_sha256=audit.digest(asset), body_sha256=audit.digest(body),
            root=None, controls=[control], slots=[], excluded_slots=[])
        self.package = dict(file='test.json', asset_sha256=audit.digest(asset), body_sha256=audit.digest(body),
            root_export=None, controls=[control], decoded_slots=[], excluded_slots=[])
        self.record = dict(id='W-test', path='/Game/RED/UI/TestUI', name='TestUI')
        self.exports = [dict(index=1, name='Child', type='WBP_Missing_C', sha256='c'*64, offset=100)]
        self.edges = [dict(control={k: control[k] for k in ['name','type','export','sha256']},
            candidates=[], status='unresolved_class')]
        self.save()

    def save(self):
        raw = json.dumps(self.package).encode()
        (self.root/'ui-catalog/test.json').write_bytes(raw)
        self.variant['sha256'] = audit.digest(raw)

    def run_audit(self, schema=None):
        with patch.object(audit.inspector, 'exports', return_value={'exports': self.exports}):
            return audit.audit_variant(self.root, self.record, self.variant,
                schema if schema is not None else audit.ui_layout_schema.compile_schema(self.record,self.variant),
                {}, self.edges)

    def test_success_confirms_only_executed_checks_and_keeps_unknown_bindings(self):
        result = self.run_audit()
        self.assertTrue(result['automatic_source_checks_passed'])
        self.assertFalse(result['implementation_verified'])
        self.assertIsNone(result['runtime_root'])
        self.assertIn('missing_nested_classes',result['unknowns'])
        self.assertIn('event_bindings_and_data',result['unknowns'])

    def test_changed_package_bytes_fail_before_export_parser(self):
        self.body.write_bytes(b'changed body')
        with patch.object(audit.inspector, 'exports') as parse:
            with self.assertRaisesRegex(ValueError,'SHA mismatch'):
                self.run_audit_without_mock()
            parse.assert_not_called()

    def run_audit_without_mock(self):
        return audit.audit_variant(self.root,self.record,self.variant,{}, {}, self.edges)

    def test_stale_published_schema_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError,'schema reproduction'):
            self.run_audit(schema={})

    def test_published_source_root_annotations_are_reproduced_during_reaudit(self):
        report = dict(records=[])
        schema = audit.ui_source_roots.compile_schema(self.record, self.variant, report)
        with patch.object(audit.inspector, 'exports', return_value={'exports': self.exports}):
            result = audit.audit_variant(self.root, self.record, self.variant, schema, {}, self.edges, report)
            self.assertTrue(result['automatic_source_checks_passed'])
            schema['runtime_root'] = 1
            with self.assertRaisesRegex(ValueError, 'schema reproduction'):
                audit.audit_variant(self.root, self.record, self.variant, schema, {}, self.edges, report)

    def test_unaccounted_slot_does_not_pass_automatic_check(self):
        self.exports.append(dict(index=2,name='Unknown',type='GridSlot',sha256='d'*64,offset=120,size=14))
        value=self.run_audit()
        self.assertFalse(value['automatic_source_checks_passed'])
        self.assertEqual(value['unaccounted_slot_exports'],[2])

    def named_slot_report(self):
        payload = bytes.fromhex('180100000000')
        entry = dict(index=2, name='NamedSlot', type='NamedSlot', sha256=audit.digest(payload), offset=120, size=len(payload))
        self.exports.append(copy.deepcopy(entry))
        return dict(records=[], container_candidates=[dict(source_file='test.json',
            asset_sha256=self.variant['asset_sha256'], body_sha256=self.variant['body_sha256'],
            source_owner_root=None, export=entry, imported_class='/Script/UMG.NamedSlot',
            raw_hex=payload.hex(), geometry_verified=False, inherited_properties_decoded=False)])

    def audit_with_report(self, report):
        schema = audit.ui_source_roots.compile_schema(self.record, self.variant, report)
        with patch.object(audit.inspector, 'exports', return_value={'exports': self.exports}):
            return audit.audit_variant(self.root, self.record, self.variant, schema, {}, self.edges, report)

    def test_named_slot_counts_as_classified_container_without_geometry_claim(self):
        result = self.audit_with_report(self.named_slot_report())
        self.assertTrue(result['automatic_source_checks_passed'])
        self.assertEqual(result['counts']['classified_source_containers'], 1)
        self.assertEqual(result['unaccounted_slot_exports'], [])
        self.assertFalse(result['classified_source_containers'][0]['geometry_verified'])
        self.assertFalse(result['classified_source_containers'][0]['implementation_verified'])
        self.assertFalse(result['classified_source_containers'][0]['inherited_properties_decoded'])
        self.assertIn('classified_containers_require_inherited_property_and_geometry_review', result['unknowns'])
        self.assertFalse(result['implementation_verified'])

    def test_named_slot_without_matching_proof_stays_unaccounted(self):
        report = self.named_slot_report()
        self.assertEqual(self.run_audit()['unaccounted_slot_exports'], [2])
        report['container_candidates'][0]['source_owner_root'] = 99
        result = self.audit_with_report(report)
        self.assertEqual(result['unaccounted_slot_exports'], [2])
        self.assertEqual(result['counts']['classified_source_containers'], 0)

    def test_classification_does_not_hide_other_missing_slots_or_count_provenance_twice(self):
        report = self.named_slot_report()
        duplicate = copy.deepcopy(report['container_candidates'][0])
        duplicate['source_file'] = 'archive.json'
        # Use a catalog alias so both equivalent provenances are retained.
        report['container_candidates'][0]['source_file'] = 'physical.json'
        report['container_candidates'].append(duplicate)
        self.exports.append(dict(index=3, name='Grid', type='GridSlot', sha256='d'*64, offset=140, size=14))
        result = self.audit_with_report(report)
        self.assertEqual(result['counts']['classified_source_containers'], 1)
        self.assertEqual(result['unaccounted_slot_exports'], [3])
        self.assertFalse(result['automatic_source_checks_passed'])

    def test_changed_raw_export_cannot_be_reclassified_from_a_forged_annotation(self):
        report = self.named_slot_report()
        self.exports[-1]['offset'] += 1
        with self.assertRaisesRegex(ValueError, 'Source container differs from raw exports'):
            self.audit_with_report(report)

    def test_false_provenance_or_forged_dependency_is_rejected(self):
        self.package['excluded_slots']=[dict(provenance=dict(slot_export=1,file='test.json',sha256='bad',offset=100))]
        self.variant['excluded_slots']=copy.deepcopy(self.package['excluded_slots'])
        self.save()
        with self.assertRaisesRegex(ValueError,'Slot provenance'):
            self.run_audit()
        self.package['excluded_slots']=[];self.variant['excluded_slots']=[];self.save()
        self.edges[0]['candidates']=['invented variant']
        with self.assertRaisesRegex(ValueError,'class candidates'):
            self.run_audit()

    def test_virtual_catalog_alias_keeps_physical_slot_source_and_multiple_roots_explicit(self):
        self.exports.extend([dict(index=2,name='Slot',type='ButtonSlot',sha256='d'*64,offset=120,size=14),
            dict(index=3,name='First_C',type='WidgetBlueprintGeneratedClass',sha256='e'*64),
            dict(index=4,name='Second_C',type='WidgetBlueprintGeneratedClass',sha256='f'*64)])
        self.package['excluded_slots']=[dict(provenance=dict(slot_export=2,slot_type='ButtonSlot',file='test.json',sha256='d'*64,offset=120))]
        self.variant['excluded_slots']=copy.deepcopy(self.package['excluded_slots'])
        self.variant['file']='test-root-3.json'
        raw=json.dumps(self.package).encode();(self.root/'ui-catalog/test-root-3.json').write_bytes(raw)
        self.variant['sha256']=audit.digest(raw)
        value=self.run_audit()
        self.assertTrue(value['automatic_source_checks_passed'])
        self.assertEqual(len(value['package_blueprint_roots']),2)
        self.assertIn('multiple_blueprint_roots_share_package_scope',value['unknowns'])
        self.assertIsNone(value['runtime_root'])


class SourceAuditScopeTests(unittest.TestCase):
    def fixture(self):
        rows=[dict(registry_id='A',path='/Game/RED/UI/Lobby/StartUI',flags=dict(name_contains_UI=True)),
            dict(registry_id='B',path='/Game/RED/UI/Common/ButtonT',flags=dict(name_contains_UI=False)),
            dict(registry_id='C',path='unresolved:child.json',flags=dict(name_contains_UI=False)),
            dict(registry_id='D',path='/Game/RED/UI/Common/LabelT',flags=dict(name_contains_UI=False)),
            dict(registry_id='Z',path='/Game/RED/UI/Other/OtherUI',flags=dict(name_contains_UI=True))]
        graph=dict(nodes={
            'a':dict(resource_id='A',dependencies=[dict(candidates=['b-old'])]),
            'b-old':dict(resource_id='B',dependencies=[dict(candidates=['c'])]),
            'b-new':dict(resource_id='B',dependencies=[dict(candidates=['d'])]),
            'c':dict(resource_id='C',dependencies=[dict(candidates=['b-old'])]),
            'd':dict(resource_id='D',dependencies=[dict(candidates=[])]),
            'z':dict(resource_id='Z',dependencies=[])})
        return rows,graph

    def test_default_and_full_scopes_have_distinct_cohorts(self):
        rows,graph=self.fixture()
        self.assertEqual([r['registry_id'] for r in audit.select_records(rows,graph)],['A','Z'])
        self.assertEqual(audit.select_records(rows,graph,scope='all'),rows)
        self.assertEqual([r['registry_id'] for r in audit.select_records(rows,graph,['Lobby'],'all')],['A'])

    def test_dependency_closure_retains_unresolved_sibling_versions_and_cycles(self):
        rows,graph=self.fixture()
        original=copy.deepcopy((rows,graph))
        selected=audit.select_records(rows,graph,['Lobby'],'dependencies')
        self.assertEqual([r['registry_id'] for r in selected],['A','B','C','D'])
        self.assertEqual((rows,graph),original)

    def test_missing_graph_target_or_unknown_scope_is_not_silently_ignored(self):
        rows,graph=self.fixture();graph['nodes']['a']['dependencies'][0]['candidates']=['missing']
        with self.assertRaisesRegex(ValueError,'missing from graph'):
            audit.select_records(rows,graph,['Lobby'],'dependencies')
        with self.assertRaisesRegex(ValueError,'Unknown'):
            audit.select_records(rows,graph,scope='guess')


if __name__ == '__main__':
    unittest.main()
