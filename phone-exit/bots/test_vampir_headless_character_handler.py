"""Native body -> handler gates/state/preferred selection and portable preference."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.character_list import decode_character_list,preferred_character_index,SOURCE_SHA256


class CharacterHandlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-character-list-handler.py'
        spec=importlib.util.spec_from_file_location('list_handler_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/character-list-handler-replay.json').read_text('utf-8'))

    def test_native_report_reproduces(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(self.report['sha256'],SOURCE_SHA256)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),45)
        self.assertEqual(self.report['sentinel'],0)

    def test_gate_and_policy_separate_acceptance_from_decode(self):
        for c in self.report['cases']:
            decoded,fixture=c['decoded'],c['fixture']
            gate=[e for e in c['events'] if e['action']=='native_gate']
            self.assertEqual(gate,[dict(action='native_gate',code=decoded['raw10'],packet_id=102)])
            accepted=decoded['raw10']==0
            self.assertEqual([e['value'] for e in c['events'] if e['action']=='native_gate_return'],[int(accepted)])
            applied=accepted and not fixture['policy_disabled'] and fixture['policy_present'] and fixture['policy']==1
            actions=[e['action'] for e in c['events']]
            self.assertEqual('selection_exit_capture' in actions,not accepted)
            self.assertEqual('selection_event_capture' in actions,applied)
            self.assertEqual(c['state']['count'],decoded['count'] if applied else 0)
            if not applied:
                self.assertEqual(c['state']['record_raw8'],[])
                self.assertEqual(c['selected_index'],-9)
                continue
            self.assertEqual(c['state']['raw80'],decoded['tail'][1])
            self.assertEqual(c['state']['raw84'],decoded['tail'][0] & 0xffffffff)
            self.assertEqual(c['state']['record_raw8'],[r['u64'][0] for r in decoded['records']])
            self.assertEqual('negative_tail28_warning_capture' in actions,decoded['tail'][0]>=2**63)
            self.assertEqual('owner_a00_capture' in actions,fixture['owner_present'])
            self.assertEqual([e['event'] for e in c['events'] if e['action']=='selection_event_capture'],[6])
            self.assertEqual([e['value'] for e in c['events'] if e['action']=='transport_flag_capture'],[0])

    def test_preferred_rule_matches_native_after_acceptance(self):
        for c in self.report['cases']:
            model=decode_character_list(bytes.fromhex(c['decoded']['payload_hex']),max_payload_size=4096,max_characters=4,max_extension_items=64)
            result=preferred_character_index(model)
            if not model.records or model.result_code!=0:
                self.assertIsNone(result)
            elif any(e['action']=='selection_event_capture' for e in c['events']) and c['fixture']['ui_present']:
                self.assertEqual(result,c['selected_index'])
        with self.assertRaises(ValueError):preferred_character_index(None)


if __name__=='__main__':unittest.main()
