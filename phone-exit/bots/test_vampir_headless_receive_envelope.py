"""Native receive probe/envelope audit and bounded shared length inspection."""
import hashlib
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.receive_frame import peek_receive_frame_size


class SharedReceiveLengthTests(unittest.TestCase):
    def test_incomplete_complete_and_coalesced(self):
        frame=(17).to_bytes(3,'little')+bytes(14)
        for length in range(17):
            self.assertIsNone(peek_receive_frame_size(frame[:length],max_frame_size=256))
        self.assertEqual(peek_receive_frame_size(frame,max_frame_size=256),17)
        self.assertEqual(peek_receive_frame_size(frame+frame,max_frame_size=256),17)

    def test_local_bounds_and_exact_memoryview(self):
        for size in range(5):
            with self.assertRaises(ValueError):
                peek_receive_frame_size(size.to_bytes(3,'little')+bytes(2),max_frame_size=256)
        with self.assertRaises(ValueError):peek_receive_frame_size(bytes.fromhex('0101000000'),max_frame_size=256)
        for limit in [0,4,0x1000000,True,1.0]:
            with self.assertRaises(ValueError):peek_receive_frame_size(b'',max_frame_size=limit)
        buffer=bytearray(bytes.fromhex('050000aabb'))
        self.assertEqual(peek_receive_frame_size(memoryview(buffer),max_frame_size=256),5)
        self.assertEqual(buffer,bytes.fromhex('050000aabb'))


class NativeReceiveEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))
        path=root/'code-clues/headless-receive-envelope.json'
        if not path.exists():raise unittest.SkipTest('Generate receive envelope evidence first')
        cls.report=json.loads(path.read_text('utf-8'))
        cls.raw=Path(cls.report['source']).read_bytes()

    def test_original_evidence_and_linkage_scope(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),self.report['sha256'])
        self.assertTrue(self.report['game_callback_target_statically_verified'])
        self.assertFalse(self.report['full_receive_verified'])
        self.assertFalse(self.report['network_ready'])
        for row in [self.report['probe_body']]+self.report['receive_tables']+self.report['connection_proofs']:
            content=bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset']+len(content)],content)
        for f in self.report['fragments']:
            content=self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(content).hexdigest(),f['sha256'])
            self.assertEqual(b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']),content)

    def test_native_probe_vectors_and_stricter_local_policy(self):
        self.assertEqual(len(self.report['probe_cases']),156)
        saw_short_declared=False
        for case in self.report['probe_cases']:
            declared,available=case['declared'],case['available']
            self.assertEqual(case['result'],declared if available>=5 and declared<=available else 0)
            if available<5:self.assertEqual(case['input_reads'],[])
            # Avoid creating huge buffers solely for the audit; small vectors cover the core API.
            if available<=256:
                data=(declared.to_bytes(3,'little')+bytes(max(0,available-3)))[:available]
                if available>=5 and declared<5:
                    saw_short_declared=True
                    with self.assertRaises(ValueError):peek_receive_frame_size(data,max_frame_size=0xffffff)
                else:
                    self.assertEqual(peek_receive_frame_size(data,max_frame_size=0xffffff),case['result'] or None)
        self.assertTrue(saw_short_declared)

    def test_native_wrapper_vectors(self):
        self.assertEqual(len(self.report['wrapper_cases']),13)
        key=bytes.fromhex('a78420d0c978b39a')
        for case in self.report['wrapper_cases']:
            frame=bytes.fromhex(case['frame_hex'])
            expected=frame[:3]+bytes(v^key[i&7] for i,v in enumerate(frame[3:]))
            self.assertEqual(case['output_hex'],expected.hex())
            self.assertEqual(case['callback_reached'],len(frame)>=3)

    def test_native_replays_of_partial_and_malformed(self):
        path=HERE/'resource-tools/vampir/build-headless-receive-envelope.py'
        spec=importlib.util.spec_from_file_location('receive_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        emulator=module.ReceiveEnvelopeEmulator()
        for declared,available in [(17,4),(17,16),(17,17),(1,5),(0xffffff,17)]:
            case=emulator.probe(declared,available)
            self.assertEqual(case['result'],declared if available>=5 and declared<=available else 0)
        self.assertFalse(emulator.unwrap(b'ab')['callback_reached'])
        self.assertTrue(emulator.unwrap(b'abc')['callback_reached'])


if __name__=='__main__':unittest.main()
