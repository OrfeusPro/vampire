"""Current native writer vs portable body; no authentication or game IO."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.world_move_start import WorldMoveStartPayload, SOURCE_SHA256
from vampir_core.character_select_result import decode_character_select_result


class ReleaseWorldStartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=HERE.parents[1]
        tool=HERE/'resource-tools/vampir/replay-release-world-start.py'
        run=subprocess.run([sys.executable,'-X','utf8',str(tool.resolve())],cwd=root,
            capture_output=True,text=True,encoding='utf-8',check=True,timeout=60)
        cls.report=json.loads(Path(json.loads(run.stdout)['report']).read_text('utf-8'))

    def test_current_native_ids_constructor_and_all_writer_outputs(self):
        self.assertEqual(self.report['source_sha256'],SOURCE_SHA256)
        self.assertEqual(self.report['packet_ids'],[202,203])
        self.assertTrue(self.report['native_execution'])
        self.assertFalse(self.report['network_used'])
        self.assertEqual(len(self.report['cases']),20)
        for case in self.report['cases']:
            packet=WorldMoveStartPayload(case['value'])
            if case['accepted']:
                self.assertEqual(packet.encode(max_payload_size=case['capacity']).hex(),case['body_hex'])
            else:
                with self.assertRaises(BufferError):packet.encode(max_payload_size=case['capacity'])

    def test_source_is_the_accepted_selection_player_field(self):
        fixture=json.loads((HERE/'fixtures/vampir-selection-flow.json').read_text('utf-8'))
        body=decode_character_select_result(bytes.fromhex(fixture['select_result_hex']),
            max_payload_size=1048576,max_collection_items=4096)
        packet=WorldMoveStartPayload.from_selection(body,source_sha256=SOURCE_SHA256)
        self.assertEqual(packet.raw10,body.player.at(8))
        self.assertNotIn(str(packet.raw10),repr(packet))
        with self.assertRaises(ValueError):WorldMoveStartPayload.from_selection(body,source_sha256='old')
        from dataclasses import replace
        with self.assertRaises(ValueError):WorldMoveStartPayload.from_selection(replace(body,result_code=16),source_sha256=SOURCE_SHA256)

    def test_invalid_fields_and_budgets_reject(self):
        for value in (-1,2**64,True,None,'1'):
            with self.assertRaises(ValueError):WorldMoveStartPayload(value)
        for budget in (-1,2**24,True,None):
            with self.assertRaises(ValueError):WorldMoveStartPayload(0).encode(max_payload_size=budget)


if __name__=='__main__':unittest.main()
