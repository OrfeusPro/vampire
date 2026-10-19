"""Native variant conversion and actual CRT gate, no parser representation claim."""
import importlib.util
import json
from pathlib import Path
import unittest


class SdkResponseVariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-sdk-response-variant.py'
        spec = importlib.util.spec_from_file_location('sdk_response_variant_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT / 'code-clues/sdk-response-variant-replay.json').read_text('utf-8'))

    def test_source_factory_and_vtable_bindings_reproduce(self):
        self.assertEqual(self.tool.build(), self.report)
        bindings = self.report['evidence']['bindings']
        self.assertEqual([b['tag'] for b in bindings], [2,3])
        self.assertTrue(all(b['try_get_string']==0x1415ef250 for b in bindings))
        rows = {r['address']:r for f in self.report['evidence']['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x14446ef25]['operands'], 'dword ptr [rbx + 8], 2')
        self.assertEqual(rows[0x14446f073]['operands'], 'dword ptr [rbx + 8], 3')
        self.assertEqual(rows[0x1415ef25e]['direct_target'], 0x14143c260)
        self.assertFalse(self.report['network_ready'])

    def test_native_numeric_variant_and_crt_outcomes(self):
        cases = {c['fixture']['name']: c for c in self.report['cases']}
        expected = {'0':0,'1':1,'-1':-1,'0.1':0,'1e3':1,'-0':0,'0e2':0,'2147483648':2147483647}
        for text, result in expected.items():
            case = cases['numeric-'+text]
            self.assertEqual(case['variant_events'], [dict(tag=3,text=text)])
            self.assertEqual(case['numeric_calls'], [dict(input=text,result=result)])
            self.assertEqual(case['stage'], 'player_fields_processed' if result==0 else 'nonzero_errorCode')

    def test_native_string_variant_uses_separate_tag(self):
        cases = {c['fixture']['name']: c for c in self.report['cases']}
        for text in ('0','oops'):
            case = cases['numeric-'+json.dumps(text)]
            self.assertEqual(case['variant_events'], [dict(tag=2,text=text)])
            self.assertEqual(case['numeric_calls'], [dict(input=text,result=0)])


if __name__ == '__main__':
    unittest.main()
