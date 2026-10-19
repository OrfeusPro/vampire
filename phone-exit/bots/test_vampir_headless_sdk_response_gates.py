"""Native response gates linked to field traversal, using verified Windows CRT."""
import importlib.util
import json
from pathlib import Path
import unittest


class SdkResponseGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-sdk-sign-in-response-gates.py'
        spec = importlib.util.spec_from_file_location('sdk_response_gates_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT / 'code-clues/sdk-sign-in-response-gates-replay.json').read_text('utf-8'))

    def test_source_and_real_crt_evidence_reproduce(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertEqual(self.report['evidence']['numeric_import']['name'], '_wtoi')
        self.assertEqual(self.report['evidence']['crt']['sha256'], 'dedb7611e1abc1ff3852dcac3d4c93a048d729e25b061973b9969f22698f14ca')
        self.assertEqual(len(self.report['evidence']['leaves']), 4)
        self.assertFalse(self.report['network_ready'])

    def test_native_predicates_object_and_status_gates(self):
        cases = {c['fixture']['name']: c for c in self.report['cases']}
        self.assertEqual(len(cases), 18)
        for key in ('00', '01', '11'):
            self.assertEqual(cases['predicates-'+key]['stage'], 'player_fields_processed')
        self.assertEqual(cases['predicates-10']['stage'], 'response_predicates_rejected')
        for key in ('not-json','[]','null'):
            case = cases['non-object-'+key]
            self.assertEqual(case['stage'], 'json_object_rejected')
            self.assertEqual(case['sdk_access_token'], 'old-sdk-token-fixture')
        for status in (199,207):
            self.assertEqual(cases['status-'+str(status)]['stage'], 'http_outside_200_206')
        self.assertEqual(cases['status-206']['stage'], 'player_fields_processed')

    def test_native_numeric_import_and_missing_errorcode_behavior(self):
        cases = {c['fixture']['name']: c for c in self.report['cases']}
        for value in ('0', '0abc', '', 'oops', ' 0'):
            case = cases['errorCode-'+repr(value)]
            self.assertEqual(case['numeric_calls'], [dict(input=value,result=0)])
            self.assertEqual(case['stage'], 'player_fields_processed')
            self.assertEqual(case['sdk_access_token'], 'new-sdk-token-fixture')
        for value in ('1','-1','200'):
            case = cases['errorCode-'+repr(value)]
            self.assertEqual(case['numeric_calls'], [dict(input=value,result=int(value))])
            self.assertEqual(case['stage'], 'nonzero_errorCode')
            self.assertEqual(case['sdk_access_token'], 'old-sdk-token-fixture')
        self.assertEqual(cases['predicates-00']['numeric_calls'], [])


if __name__ == '__main__':
    unittest.main()
