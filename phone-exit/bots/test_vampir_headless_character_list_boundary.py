"""Keep actual post-login reset distinct from independent character requests."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest

HERE=Path(__file__).resolve().parent


class CharacterListBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-character-list-boundary.py'
        spec=importlib.util.spec_from_file_location('character_boundary_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/character-list-boundary-replay.json').read_text('utf-8'))

    def test_native_report_reproduces_and_slot_points_to_reset(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertTrue(self.report['native_execution'])
        self.assertFalse(self.report['network_ready'])
        raw=Path(self.report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),self.report['sha256'])
        for r in self.report['leaves']+self.report['anchors']:
            data=bytes.fromhex(r['bytes'])
            self.assertEqual(raw[r['file_offset']:r['file_offset']+len(data)],data)
        table=bytes.fromhex(self.report['anchors'][0]['bytes'])
        self.assertEqual(struct.unpack_from('<Q',table,0x28)[0],0x1464846c0)

    def test_reset_ranges_clear_fields_and_select_container_branches(self):
        self.assertEqual(len(self.report['resets']),8)
        for case in self.report['resets']:
            self.assertTrue(case['singleton_matches'])
            self.assertEqual(case['derived_vtable'],0x149c5f828)
            self.assertEqual((case['field308'],case['global_flag']),(0,0))
            values=case['values']
            for offset in (0xf0,0x140,0x190,0x210,0x260,0x2b0,0x300):
                self.assertEqual(values[hex(offset)],min(case['level'],1))
            for offset in (0x244,0x294,0x2e4):self.assertEqual(values[hex(offset)],128)
            for offset in (0x248,0x298,0x2e8):self.assertEqual(values[hex(offset)],0xffffffff)
            excluded={hex(o) for o in (0xf0,0x140,0x190,0x210,0x260,0x2b0,0x300,0x244,0x294,0x2e4,0x248,0x298,0x2e8,0x338)}
            self.assertTrue(all(value==0 for key,value in values.items() if key not in excluded))
            constant=int.from_bytes(bytes.fromhex(self.report['anchors'][2]['bytes']),'little')
            self.assertEqual(values['0x338'],constant)
            calls=[e['address'] for e in case['events']]
            self.assertEqual(calls.count(0x14142e310),3 if case['capacity']>128 else 0)
            self.assertEqual(calls.count(0x141833c60),2 if case['level']>1 else 0)
            self.assertEqual(calls.count(0x14145b150),0 if case['level']>1 else 2)
            self.assertFalse(any(e['action']=='send_capture' for e in case['events']))

    def test_separate_request_entries_construct_and_send_id101(self):
        self.assertEqual(len(self.report['requests']),2)
        for case in self.report['requests']:
            self.assertEqual(case['packet_id'],101)
            self.assertEqual(case['writer_returned'],1)
            self.assertTrue(case['archive_unchanged'])
            sends=[e for e in case['events'] if e['action']=='send_capture']
            self.assertEqual(sends,[dict(action='send_capture',vtable=0x1498d84d8,packet_byte_a=0)])
            self.assertEqual(case['events'][-1],dict(action='packet_cleanup_capture'))
        pre=[e for e in self.report['requests'][0]['events'] if e['action']=='helper_capture']
        self.assertEqual([e['address'] for e in pre],[0x14560dd00])
        self.assertFalse(any(e['action']=='helper_capture' for e in self.report['requests'][1]['events']))


if __name__=='__main__':unittest.main()
