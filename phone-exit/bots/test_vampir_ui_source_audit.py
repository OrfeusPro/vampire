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

    def test_unaccounted_slot_does_not_pass_automatic_check(self):
        self.exports.append(dict(index=2,name='Unknown',type='GridSlot',sha256='d'*64,offset=120))
        value=self.run_audit()
        self.assertFalse(value['automatic_source_checks_passed'])
        self.assertEqual(value['unaccounted_slot_exports'],[2])

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


if __name__ == '__main__':
    unittest.main()
