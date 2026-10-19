"""Source-bound derived selection slots and raw CharacterSelect handoff fields."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest

HERE=Path(__file__).resolve().parent


class SelectionServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-selection-service.py'
        spec=importlib.util.spec_from_file_location('selection_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/selection-service-replay.json').read_text('utf-8'))

    def test_native_report_and_source_table_slots_reproduce(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(self.report['packet_id'],109)
        raw=Path(self.report['source']).read_bytes()
        for r in self.report['anchors']+self.report['leaves']:
            content=bytes.fromhex(r['bytes'])
            self.assertEqual(raw[r['file_offset']:r['file_offset']+len(content)],content)
        table=bytes.fromhex(self.report['anchors'][0]['bytes'])
        self.assertEqual(struct.unpack_from('<Q',table,0x40)[0],0x145dbba60)
        self.assertEqual(struct.unpack_from('<Q',table,0x50)[0],0x145dc05f0)
        self.assertEqual(struct.unpack_from('<Q',table,0x90)[0],0x145dbd4b0)

    def test_constructor_publishes_service_and_null_allocation_preserves_previous_global(self):
        success,failure=self.report['initializations']
        self.assertTrue(success['global_is_service'])
        self.assertTrue(success['attach_is_service'])
        self.assertEqual(success['vtable'],0x1499f11f0)
        self.assertEqual(success['owner_offset'],8)
        self.assertFalse(success['global_preserved'])
        self.assertTrue(failure['allocation_failed'])
        self.assertTrue(failure['global_preserved'])
        self.assertTrue(failure['attach_is_null'])
        self.assertFalse(failure['global_is_service'])
        self.assertEqual(failure['owner_offset'],8)
        self.assertIsNone(failure['vtable'])

    def test_virtual50_passes_arguments_and_state_value_to_real_packet(self):
        self.assertEqual(len(self.report['cases']),4)
        opaque=int.from_bytes(bytes.fromhex(self.report['anchors'][1]['bytes']),'little')
        raw_default=int.from_bytes(bytes.fromhex(self.report['anchors'][2]['bytes']),'little')
        for case in self.report['cases']:
            events=case['events']
            self.assertEqual(events[0],dict(action='base_selection_capture',raw64=case['raw64'],raw32=raw_default))
            self.assertEqual(events[1],dict(action='select_handoff_capture',kind=110,opaque_argument=opaque,timeout=0.0,
                packet_raw10=case['raw64'],packet_raw18=case['raw32'],packet_raw20=case['state_raw_f0']))
            self.assertEqual(events[2],dict(action='packet_cleanup_capture'))


if __name__=='__main__':unittest.main()
