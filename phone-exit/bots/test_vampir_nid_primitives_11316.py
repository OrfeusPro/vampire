import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent/'resource-tools/vampir'


class NidPrimitives11316Tests(unittest.TestCase):
    def tool(self):
        spec=importlib.util.spec_from_file_location('nid_primitives_test',HERE/'replay-nid-primitives-11316.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def test_real_helpers_and_onresult_integration(self):
        report=self.tool().replay()
        self.assertTrue(report['native_primitives']); self.assertFalse(report['network_ready'])
        self.assertEqual(len(report['cases']),1124)
        self.assertEqual(len(report['primitive_cases']['numeric']),112)
        self.assertEqual(len(report['primitive_cases']['channels']),176)
        self.assertEqual(len(report['primitive_evidence']['bindings']),13)
        numeric={c['text']:c for c in report['primitive_cases']['numeric'] if c['poison']==0}
        self.assertFalse(numeric['abc']['ok']); self.assertFalse(numeric['']['ok'])
        for value in ('0','00','+0','-0',' 0','0.0','0abc','0x10'):
            self.assertTrue(numeric[value]['ok']); self.assertEqual(numeric[value]['value'],0)
        self.assertEqual(numeric['2147483648']['value'],2147483647)
        self.assertEqual(numeric['-2147483649']['value'],-2147483648)
        channels={c['text']:c['channel'] for c in report['primitive_cases']['channels']}
        self.assertEqual(channels['mailUserKey'],20); self.assertEqual(channels['MAILUSERKEY'],20)
        self.assertEqual(channels['mailUserKey '],0); self.assertEqual(channels['unknown'],0)
        for case in report['cases']:
            self.assertFalse(any(e['kind'] in ('integer_fixture','channel_fixture') for e in case['events']))
            self.assertEqual(set(case['inputs']),{'auth_type'})
            self.assertTrue(case['canaries_unchanged'])
        cases={c['name']:c for c in report['cases'] if c['poison']==0}
        self.assertEqual(cases['prefix_zero_upper_channel']['outcome'],'adoption_calls_reached')
        self.assertEqual(cases['nonzero_prefix']['outcome'],'invalid_or_nonzero_result')
        self.assertEqual(cases['trailing_channel_space']['outcome'],'unknown_channel')
        self.assertTrue(any(e['kind']=='local_CRT_call' for e in cases['complete']['events']))

    def test_corrupted_helper_export_is_rejected(self):
        original=Path.read_bytes
        def read(path):
            data=original(path)
            return data+b'changed' if path.parent.name=='run-37fa5992ea23' and path.name=='details.json' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'export SHA changed'): self.tool().replay()


if __name__=='__main__': unittest.main()
