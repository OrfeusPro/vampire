"""Native whole-slice frame vectors versus shared offline Ping frame encoder."""
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
from vampir_core.send_frame import encode_ping_frame
from vampir_core.frame_primitives import xor_transform, payload_crc32


class SharedPingFrameTests(unittest.TestCase):
    def test_explicit_layout_and_crc_scope(self):
        payload=PingPayload(0x0102030405060708,0x1112131415161718)
        frame=encode_ping_frame(payload,0x1234)
        self.assertEqual(frame[:3],bytes.fromhex('1b0000'))
        self.assertEqual(len(frame),27)
        clear=xor_transform(frame[3:])
        self.assertEqual(clear[4:8],bytes.fromhex('10003412'))
        self.assertEqual(clear[8:],payload.encode())
        self.assertEqual(int.from_bytes(clear[:4],'little'),payload_crc32(clear[4:]))

    def test_invalid_inputs(self):
        for seq in [-1,65536,True,1.0,'0']:
            with self.assertRaises(ValueError):encode_ping_frame(PingPayload(0,0),seq)
        with self.assertRaises(TypeError):encode_ping_frame(bytes(16),0)


class NativeSendFrameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))
        path=root/'code-clues/headless-send-frame.json'
        if not path.exists():raise unittest.SkipTest('Generate send frame evidence first')
        cls.report=json.loads(path.read_text('utf-8'))
        cls.raw=Path(cls.report['source']).read_bytes()

    def test_original_bytes_and_slice_boundaries(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),self.report['sha256'])
        self.assertTrue(self.report['send_a_layout_verified'])
        self.assertFalse(self.report['receive_validation_verified'])
        self.assertFalse(self.report['network_ready'])
        for f in self.report['fragments']:
            content=self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(content).hexdigest(),f['sha256'])
            self.assertEqual(b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']),content)
        for body in self.report['bodies']:
            content=bytes.fromhex(body['bytes'])
            self.assertEqual(self.raw[body['file_offset']:body['file_offset']+len(content)],content)
            self.assertEqual(hashlib.sha256(content).hexdigest(),body['sha256'])
        rows=self.report['slice_instructions']
        self.assertEqual(rows[0]['address'],self.report['slice_start'])
        self.assertEqual(rows[-1]['address']+len(bytes.fromhex(rows[-1]['bytes'])),self.report['slice_end'])

    def test_shared_encoder_matches_all_native_complete_frames(self):
        self.assertEqual(len(self.report['cases']),20)
        for case in self.report['cases']:
            frame=encode_ping_frame(PingPayload(*case['values']),case['sequence'])
            self.assertEqual(frame.hex(),case['frame_hex'])
            self.assertEqual(case['sequence_after'],(case['sequence']+1)&65535)

    def test_native_assembly_replay(self):
        path=HERE/'resource-tools/vampir/build-headless-send-frame.py'
        spec=importlib.util.spec_from_file_location('send_frame_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        emulator=module.SendFrameEmulator()
        for sequence in [0,65535]:
            values=(2**53+1,0x0102030405060708)
            case=emulator.execute_frame(values,sequence)
            self.assertEqual(case['frame_hex'],encode_ping_frame(PingPayload(*values),sequence).hex())
            self.assertEqual(case['sequence_after'],(sequence+1)&65535)


if __name__=='__main__':unittest.main()
