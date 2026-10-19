"""Whole ID110 body -> native gate/handler/apply with documented boundaries."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.character_select_result import decode_character_select_result


class CharacterSelectHandlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-character-select-handler.py'
        spec=importlib.util.spec_from_file_location('select_handler_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/character-select-handler-replay.json').read_text('utf-8'))

    def test_native_pipeline_reproduces(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(len(self.report['cases']),31)
        self.assertFalse(self.report['network_ready'])
        self.assertTrue({'GetActiveWindow','SetWindowTextW'}<={r['name'] for r in self.report['title_imports']})

    def test_portable_fields_match_actual_player_and_state_writes(self):
        for c in self.report['cases']:
            model=decode_character_select_result(bytes.fromhex(c['decoded']['payload_hex']),max_payload_size=4096,max_collection_items=256)
            f=c['fixture'];accepted=f['code']==0 or (f['code']==0x1197 and f['gate_state']!=1)
            applied=[e for e in c['events'] if e['action']=='native_player_apply']
            self.assertEqual(len(applied),int(accepted))
            state=c['state'];self.assertEqual(state['owner_refs'],2)
            if not accepted:
                self.assertEqual(state['vector_hex'],bytes(24).hex())
                self.assertEqual(state['service_flag'],f['service_flag'])
                continue
            self.assertEqual(state['raw8'],model.player.at(8))
            self.assertEqual(state['raw10'],model.player.at(0x30))
            self.assertEqual(state['vector_hex'],struct.pack('<ddd',*model.player.at(0x188).finite_values()).hex())
            self.assertEqual(state['derived249'],int(model.player.at(0x260)==2))
            self.assertEqual(state['flag24a'],int(model.data.at(0x349)))
            self.assertEqual(state['service_flag'],1 if model.data.at(0x348) else f['service_flag'])
            self.assertEqual(state['raw_f0'],model.data.at(0x2b0))
            self.assertEqual(state['raw250'],model.data.at(0x2b8).at(0x50))
            self.assertEqual([e['event'] for e in c['events'] if e['action']=='selection_event_capture'],[1])
            updates=[e for e in c['events'] if e['action']=='array238_entry_capture']
            self.assertEqual(updates,[dict(action='array238_entry_capture',index=i+1,value=v) for i,v in enumerate(model.player.at(0x238))])

    def test_special_codes_and_gate_state_keep_distinct_paths(self):
        for c in self.report['cases']:
            f=c['fixture'];events=c['events'];code=f['code']
            gates=[e for e in events if e['action']=='native_gate']
            self.assertEqual(len(gates),int(code not in (0x26,0x3c)))
            if gates:self.assertEqual(gates[0]['packet_id'],110)
            if code==0x24b9:
                self.assertEqual([e['offsets'] for e in events if e['action']=='code24b9_capture'],[[0x338,0x328,0x318]])
            if code==0x3c and f['ui_present']:
                addresses=[e['address'] for e in events if e['action']=='backend_capture']
                self.assertIn(0x1463df2a0,addresses)
                self.assertEqual(0x144a24f80 in addresses,not f['ui_same'])
            if f['metadata']:
                self.assertIn(dict(action='metadata_capture',raw20=7,raw80=5),events)


if __name__=='__main__':unittest.main()
