"""Current NO DATA responses and actual two-stage native continuation."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).parent/'resource-tools/vampir'


class CurrentFirstSdkTermsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('current_terms_fixture',HERE/'inspect-first-sdk-terms-current.py')
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        selector=json.loads((HERE/'knowledge/sdk-first-terms-current.json').read_bytes())
        cls.path=Path(selector['contracts']['terms']['path'])
        cls.report=cls.tool.verify_report(cls.path)

    def test_no_data_and_error_branches_keep_result_and_state(self):
        self.assertEqual(len(self.report['cases']),56)
        for case in self.report['cases']:
            self.assertEqual(case['state'],2 if case['scenario']=='no_data' else 3)
            self.assertEqual(case['continuation_calls'],int(case['bound']))
        self.assertTrue(self.report['native_execution']);self.assertFalse(self.report['network_used'])
        self.assertFalse(self.report['runtime_admitted'])

    def test_actual_basic_then_individual_no_data_reach_netmarble_handoff(self):
        first,second=self.report['composition']
        self.assertEqual([a['kind'] for a in first['composed_actions']],['individual_terms'])
        self.assertEqual([(a['kind'],a['channel'],a['step']) for a in second['composed_actions']], [('sign_up',33,13)])
        self.assertEqual((first['state'],second['state']),(2,2))
        self.assertEqual(self.tool.verify_report(self.path),self.report)

    def test_changed_type_vtable_cannot_supply_individual_terms_type(self):
        context=json.loads(self.tool.CONTEXT.read_bytes());context['type_table']='0x14954a958'
        with self.assertRaisesRegex(ValueError,'virtual binding'):
            self.tool.static_contract(context,self.tool.ROOT,{})

    def test_cached_report_requires_retained_checker(self):
        report=json.loads(self.path.read_bytes());report['inputs'].pop(str(Path(self.tool.__file__).resolve()))
        report['negative_tooling_fixture']=True
        target=self.tool.load('audit-client-release').save_snapshot(self.tool.ROOT/'code-clues'/self.tool.RECIPE,report)
        with self.assertRaisesRegex(ValueError,'not pinned'):self.tool.verify_report(target)


if __name__=='__main__':unittest.main()
