"""Title success slice flag is distinct from actual BeginGame IsSignIn byte gate."""
import importlib.util
import json
from pathlib import Path
import unittest


class TitleAuthStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-title-auth-state.py'
        spec=importlib.util.spec_from_file_location('title_state_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/title-auth-state-replay.json').read_text('utf-8'))

    def test_source_flag_getter_and_gate(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),10)
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x14641dac5]['operands'],'byte ptr [r15 + 0x230], 1')
        self.assertEqual(rows[0x14452b02c]['operands'],'eax, byte ptr [rcx + 0x400]')
        self.assertEqual(rows[0x14641809c]['direct_target'],0x145609b00)
        self.assertEqual(rows[0x145609b31]['direct_target'],0x14452afb0)
        self.assertTrue(any('UNMServiceSettings::IsSignIn(' in l['text'] for l in self.report['literals']))
        self.assertTrue(any(l['text']=='ConnectCountryCode' for l in self.report['literals']))

    def test_title_country_and_guard_slices(self):
        for case in self.report['cases']:
            f=case['fixture'];reached=f['manager'] and f['auth_service']
            with self.subTest(f):
                self.assertEqual(case['title_head_reached'],reached)
                self.assertEqual(case['title_ready_byte'],int(reached))
                copied=[e['value'] for e in case['events'] if e['action']=='connect_country_setter_capture']
                self.assertEqual(copied,[f['country']] if reached else [])
                self.assertEqual(sum(e['action']=='fixture_skip_title_middle' for e in case['events']),int(reached))

    def test_ui_flag_and_sdk_gate_are_independent(self):
        for case in self.report['cases']:
            f=case['fixture']
            self.assertEqual(case['sdk_flag_after'],int(f['sdk_flag']))
            self.assertEqual(case['begin_game_gate_passed'],f['sdk_flag'])
        self.assertTrue(any(c['title_ready_byte']==1 and not c['begin_game_gate_passed'] for c in self.report['cases']))
        self.assertTrue(any(c['title_ready_byte']==0 and c['begin_game_gate_passed'] for c in self.report['cases']))


if __name__=='__main__':
    unittest.main()
