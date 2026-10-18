"""Audit native frame helper evidence and portable implementations."""
import hashlib
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.frame_primitives import payload_crc32,xor_transform,FALLBACK_XOR_KEY


class PortableFrameHelperTests(unittest.TestCase):
    def test_crc_known_vector(self):
        self.assertEqual(payload_crc32(b''),0)
        self.assertEqual(payload_crc32(b'123456789'),0xcbf43926)

    def test_xor_key_order_fallback_and_involution(self):
        self.assertEqual(xor_transform(bytes(8),0x0102030405060708),bytes.fromhex('0807060504030201'))
        self.assertEqual(xor_transform(bytes(8)),bytes.fromhex('a78420d0c978b39a'))
        self.assertEqual(xor_transform(bytes(8)),xor_transform(bytes(8),FALLBACK_XOR_KEY))
        for key in [0,1,2**64-1]:
            payload=bytes(range(256))+b'end'
            self.assertEqual(xor_transform(xor_transform(payload,key),key),payload)
        for key in [-1,2**64,False,1.0]:
            with self.assertRaises(ValueError):xor_transform(b'x',key)


class NativeFrameHelperEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))
        path=root/'code-clues/headless-frame-primitives.json'
        if not path.exists():raise unittest.SkipTest('Generate frame primitives evidence first')
        cls.report=json.loads(path.read_text('utf-8'))
        cls.raw=Path(cls.report['source']).read_bytes()

    def test_evidence_matches_original_bytes(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),self.report['sha256'])
        self.assertFalse(self.report['full_frame_verified'])
        self.assertFalse(self.report['network_ready'])
        for row in self.report['helper_bodies']+[self.report['crc_table']]:
            data=bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset']+len(data)],data)
            self.assertEqual(hashlib.sha256(data).hexdigest(),row['sha256'])
        for f in self.report['fragments']:
            data=self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(data).hexdigest(),f['sha256'])
            self.assertEqual(b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']),data)

    def test_portable_helpers_match_all_native_vectors(self):
        self.assertEqual(len(self.report['crc_cases']),21)
        self.assertEqual(len(self.report['xor_cases']),210)
        for case in self.report['crc_cases']:
            self.assertEqual(payload_crc32(bytes.fromhex(case['payload_hex'])),case['value'])
        for case in self.report['xor_cases']:
            self.assertEqual(xor_transform(bytes.fromhex(case['payload_hex']),case['key_bits']).hex(),
                             case['output_hex'])
            self.assertEqual(case['returned'],len(bytes.fromhex(case['payload_hex'])))

    def test_native_replay_separate_buffers_and_boundary_lengths(self):
        path=HERE/'resource-tools/vampir/build-headless-frame-primitives.py'
        spec=importlib.util.spec_from_file_location('frame_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        emulator=module.FramePrimitiveEmulator()
        for length in [0,7,8,9,257,512]:
            payload=bytes((i*13+7)&255 for i in range(length))
            self.assertEqual(emulator.crc(payload)['value'],payload_crc32(payload))
            for in_place in [False,True]:
                result=emulator.xor(payload,0x0102030405060708,in_place)
                self.assertEqual(result['output_hex'],xor_transform(payload,0x0102030405060708).hex())


if __name__=='__main__':unittest.main()
