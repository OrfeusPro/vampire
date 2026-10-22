"""Self identity and retained height policies; synthetic events, no network."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.character_select_result import CharacterSelectResultBody, SelectionRecord, WireVector3
from vampir_core.character_target import CharacterTargetTracker
from vampir_core.world_entry_flow import ServerTargetPosition
from vampir_core.world_move_start import SOURCE_SHA256


class CharacterTargetTests(unittest.TestCase):
    def tracker(self,key=42,code=0,source=SOURCE_SHA256):
        selection=CharacterSelectResultBody(code,SelectionRecord(((0x18,SelectionRecord(((8,key),))),)))
        point=ServerTargetPosition(10010,WireVector3((0,0,0x80000000)))
        return CharacterTargetTracker(selection,point,source_sha256=source)

    def test_foreign_key_cannot_move_us_and_own_target_retains_height(self):
        tracker=self.tracker()
        self.assertFalse(tracker.receive(struct.pack('<Qff',43,12,34)))
        self.assertEqual(tracker.revision,1)
        self.assertTrue(tracker.receive(struct.pack('<Qff',42,12,34)))
        self.assertEqual(tracker.position.vector.finite_values(),(12,34,-0.0))
        self.assertEqual(tracker.position.vector.bits[2],0x80000000)
        self.assertEqual(tracker.position.world_id,10010)
        self.assertEqual(tracker.position.source,'character_move_notify_xy_retained_z')
        self.assertEqual(tracker.update_count,1)

    def test_invalid_update_keeps_previous_target_and_cleanup_forgets_identity(self):
        tracker=self.tracker();previous=tracker.position
        for body in (bytes(15),struct.pack('<Qff',42,float('nan'),1)):
            with self.assertRaises(ValueError):tracker.receive(body)
            self.assertIs(tracker.position,previous)
        tracker.close()
        self.assertIsNone(tracker.position);self.assertIsNone(tracker._key)
        with self.assertRaises(ValueError):tracker.receive(struct.pack('<Qff',42,1,2))

    def test_zero_identity_and_unaccepted_selection(self):
        tracker=self.tracker(key=0)
        self.assertFalse(tracker.receive(bytes(16)))
        for options in ({'code':16},{'source':'old'}):
            with self.assertRaises(ValueError):self.tracker(**options)


if __name__=='__main__':unittest.main()
