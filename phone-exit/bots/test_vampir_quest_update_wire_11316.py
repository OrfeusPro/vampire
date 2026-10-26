"""Whole current wire and typed per-owner queue integration; no game commands."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.quest_update import QuestUpdate,encode_quest_update,decode_quest_update
from vampir_core.world_move_start import CURRENT_PROBE_SOURCE
from vampir_core.outbound import OutboundFrames
from vampir_core.frame_primitives import xor_transform,payload_crc32


class CurrentQuestUpdateTests(unittest.TestCase):
    def test_whole_current_native_writer_mirror_and_boundaries(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-quest-update-wire-11316.py'
        spec=importlib.util.spec_from_file_location('quest_wire_current',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        saved,report=module.run()
        self.assertTrue(saved.is_file());self.assertTrue(report['native_execution']);self.assertFalse(report['network_used'])
        self.assertEqual(report['source_sha256'],CURRENT_PROBE_SOURCE)
        self.assertEqual(len(report['cases']),81)
        self.assertEqual(len(report['short_prefixes']),29)
        self.assertEqual([r['widths'] for r in report['writer_failures']],[[4,4,4,8,8,1][:n] for n in range(1,7)])

    def test_source_bound_typed_frames_keep_owner_sequence_key_and_backpressure(self):
        value=QuestUpdate((90049.,151840.,-44.),0,110120,0)
        body=encode_quest_update(value,source_sha256=CURRENT_PROBE_SOURCE)
        self.assertEqual(decode_quest_update(body,source_sha256=CURRENT_PROBE_SOURCE),value)
        for key,sequence in ((0,65535),(0x123456789abcdef0,7)):
            with self.subTest(key=key):
                queue=OutboundFrames(key_bits=key,sequence=sequence,max_queued_bytes=40,max_queued_frames=1)
                with self.assertRaises(ValueError):queue.queue_quest_update(value,source_sha256='0'*64)
                self.assertEqual(queue.sequence,sequence);self.assertEqual(queue.queued_frames,0)
                frame=queue.queue_quest_update(value,source_sha256=CURRENT_PROBE_SOURCE)
                self.assertEqual(len(frame),40)
                clear=xor_transform(frame[3:],key)
                self.assertEqual(clear[4:],struct.pack('<HH',1810,sequence)+body)
                self.assertEqual(struct.unpack('<I',clear[:4])[0],payload_crc32(clear[4:]))
                state=(queue.sequence,queue.queued_frames,queue.queued_bytes)
                with self.assertRaises(BufferError):queue.queue_quest_update(value,source_sha256=CURRENT_PROBE_SOURCE)
                self.assertEqual((queue.sequence,queue.queued_frames,queue.queued_bytes),state)
                self.assertEqual(queue.sequence,(sequence+1)&65535)
                queue.close()
                with self.assertRaises(RuntimeError):queue.queue_quest_update(value,source_sha256=CURRENT_PROBE_SOURCE)


if __name__=='__main__':unittest.main()
