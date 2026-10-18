"""Native send-B/queue ownership vectors and bounded portable outbound state."""
import hashlib
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.ping import PingPayload
from vampir_core.key_change import KeyChangePayload
from vampir_core.send_frame import encode_ping_frame_b,encode_key_changed_frame_b
from vampir_core.outbound import OutboundFrames


class OutboundStateTests(unittest.TestCase):
    def test_ack_uses_old_key_queue_survives_rotation_and_wrap(self):
        state=OutboundFrames(key_bits=1,sequence=65535,max_queued_bytes=100,max_queued_frames=3)
        ack=state.acknowledge_key_change(KeyChangePayload(12345))
        self.assertEqual(ack,encode_key_changed_frame_b(KeyChangePayload(12345),65535,1))
        ping=state.queue_ping(PingPayload(1,2))
        self.assertEqual(ping,encode_ping_frame_b(PingPayload(1,2),0,12345))
        self.assertEqual((state.sequence,state.queued_frames,state.queued_bytes),(1,2,46))
        self.assertIs(state.pop_frame(),ack);self.assertIs(state.pop_frame(),ping)
        self.assertEqual((state.queued_frames,state.queued_bytes),(0,0))
        self.assertIsNone(state.pop_frame());self.assertNotIn('12345',repr(state))

    def test_backpressure_leaves_sequence_and_key_unchanged(self):
        for byte_limit,frame_limit in [(27,10),(100,1)]:
            state=OutboundFrames(key_bits=7,sequence=9,max_queued_bytes=byte_limit,max_queued_frames=frame_limit)
            original=state.queue_ping(PingPayload(1,2))
            with self.assertRaises(BufferError):state.acknowledge_key_change(KeyChangePayload(99))
            self.assertEqual((state.sequence,state.queued_bytes),(10,27))
            self.assertIs(state.pop_frame(),original)
            ack=state.acknowledge_key_change(KeyChangePayload(99))
            self.assertEqual(ack,encode_key_changed_frame_b(KeyChangePayload(99),10,7))
        for key in [False,-1,1<<64]:
            with self.assertRaises(ValueError):
                OutboundFrames(key_bits=key,sequence=0,max_queued_bytes=128,max_queued_frames=4)


class NativeSendBTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))
        path=root/'code-clues/headless-send-b.json'
        if not path.exists():raise unittest.SkipTest('Generate native send-B evidence first')
        cls.report=json.loads(path.read_text('utf-8'));cls.raw=Path(cls.report['source']).read_bytes()

    def test_source_and_queue_copy_provenance(self):
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),self.report['sha256'])
        for f in self.report['fragments']:
            data=self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(data).hexdigest(),f['sha256'])
            self.assertEqual(data,b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']))
        for row in self.report['leaves']+self.report['packet_tables']:
            data=bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset']+len(data)],data)
        rows={i['address']:i for f in self.report['fragments'] for i in f['instructions']}
        self.assertEqual(rows[0x144aacf7d]['direct_target'],0x1445eac20)
        self.assertEqual(rows[0x1445eac30]['direct_target'],0x1445e4a90)

    def test_all_native_frames_match_shared(self):
        self.assertEqual(self.report['statistics']['native_send_b_cases'],40)
        for row in self.report['cases']:
            if row['kind']=='ping':
                value=encode_ping_frame_b(PingPayload(*row['values']),row['sequence'],row['test_key_bits'])
            else:
                value=encode_key_changed_frame_b(KeyChangePayload(row['values'][0]),row['sequence'],row['test_key_bits'])
            self.assertEqual(value.hex(),row['frame_hex'])
            self.assertEqual(row['queued_hex'],row['existing_hex']+row['frame_hex'])
            self.assertTrue(row['queue_owns_bytes'])
            self.assertEqual(row['sequence_after'],(row['sequence']+1)&65535)

    def test_native_replay_prefix_wake_and_key_variants(self):
        path=HERE/'resource-tools/vampir/build-headless-send-b.py'
        spec=importlib.util.spec_from_file_location('send_b_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        emulator=module.SendBEmulator()
        first=emulator.execute_send('key_ack',(12345,),65535,7,wake=True)
        second=emulator.execute_send('ping',(1,2),0,12345,existing=bytes.fromhex(first['queued_hex']))
        self.assertEqual(second['queued_hex'],first['frame_hex']+second['frame_hex'])


if __name__=='__main__':unittest.main()
