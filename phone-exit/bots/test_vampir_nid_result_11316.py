import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent/'resource-tools/vampir'


class NidResult11316Tests(unittest.TestCase):
    def tool(self):
        spec=importlib.util.spec_from_file_location('nid_result_test',HERE/'replay-nid-result-11316.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def test_current_missing_empty_mode_gates_and_token_arguments(self):
        report=self.tool().replay()
        self.assertEqual(len(report['cases']),1100)
        self.assertFalse(report['network_ready'])
        cases={c['name']:c for c in report['cases'] if c['poison']==0}
        self.assertEqual(cases['missing_resultCode']['outcome'],'missing_resultCode')
        for field in ('accessToken','refreshToken','channelKey','netmarbleId','joinedCountryCode'):
            self.assertEqual(cases['missing_'+field]['outcome'],'unmapped_null_access')
            faults=[e for e in cases['missing_'+field]['events'] if e['kind']=='unmapped_null_access']
            self.assertEqual(len(faults),1); self.assertLess(faults[0]['address'],4096)
        self.assertEqual(cases['empty_refreshToken']['outcome'],'adoption_calls_reached')
        for field in ('resultCode','accessToken','channelKey','netmarbleId','joinedCountryCode'):
            self.assertEqual(cases['empty_'+field]['outcome'],'empty_'+field)
        for mode in (*range(256),0x100,0x80000000,0xffffffff):
            self.assertEqual(cases['auth_type_'+str(mode)]['outcome'],
                'adoption_calls_reached' if mode in (0,1,4,5) else 'auth_type_gate')
        captures=[e for e in cases['complete']['events'] if e['kind']=='settings_capture']
        self.assertEqual([e['value'] for e in captures],['access-fixture','user-fixture','refresh-fixture'])
        self.assertEqual([e['target'] for e in captures],['0x144550d80','0x1445523c0','0x144552e10'])
        self.assertEqual(captures[1]['mode'],1)
        self.assertTrue(all(c['canaries_unchanged'] for c in report['cases']))

    def test_corrupted_copy_export_is_rejected(self):
        original=Path.read_bytes
        def read(path):
            data=original(path)
            return data+b'changed' if path.parent.name=='run-1740fcc91625' and path.name=='details.json' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'export SHA changed'): self.tool().replay()


if __name__=='__main__': unittest.main()
