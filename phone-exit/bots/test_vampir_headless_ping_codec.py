"""Compare portable payload codec with actual native IO reference vectors."""
import hashlib
import importlib.util
import json
import os
import struct
import sys
import unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.ping import PingPayload, PingResultPayload, SOURCE_SHA256


class PortablePingTests(unittest.TestCase):
    def test_bit_patterns_and_exact_lengths(self):
        self.assertEqual(PingPayload(0x0102030405060708,0xffffffffffffffff).encode(),
                         bytes.fromhex('0807060504030201ffffffffffffffff'))
        self.assertEqual(PingResultPayload(0x01020304,0x0102030405060708).encode(),
                         bytes.fromhex('040302010807060504030201'))
        for cls,size in [(PingPayload,16),(PingResultPayload,12)]:
            for length in (0,size-1,size+1,100):
                with self.assertRaises(ValueError):cls.decode(bytes(length))
        for first,second in [(-1,0),(0,-1),(1<<64,0),(0,1<<64),(True,0),(0,1.0)]:
            with self.assertRaises(ValueError):PingPayload(first,second)
        for first in (-1,1<<32,False,'0'):
            with self.assertRaises(ValueError):PingResultPayload(first,0)


class NativePingEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))
        path=root/'code-clues/headless-ping-codec.json'
        if not path.exists():raise unittest.SkipTest('Generate headless-ping-codec.json first')
        cls.report=json.loads(path.read_text('utf-8'))
        cls.raw=Path(cls.report['source']).read_bytes()

    def test_source_fragments_and_import(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),self.report['sha256'])
        self.assertEqual(self.report['sha256'],SOURCE_SHA256)
        self.assertEqual(self.report['memcpy_import']['name'],'memcpy')
        self.assertFalse(self.report['primitive_io_stubbed'])
        self.assertFalse(self.report['framing_verified'])
        for f in self.report['fragments']+self.report['dispatch_fragments']+self.report['send_fragments']:
            content=self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(content).hexdigest(),f['sha256'])
            self.assertEqual(b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']),content)
        for a in self.report['leaves']+self.report['data_anchors']:
            content=bytes.fromhex(a['bytes'])
            self.assertEqual(self.raw[a['file_offset']:a['file_offset']+len(content)],content)

    def test_portable_code_matches_all_native_vectors(self):
        self.assertEqual(len(self.report['cases']),45)
        for case in self.report['cases']:
            cls=PingPayload if case['kind']=='ping' else PingResultPayload
            native_bytes=bytes.fromhex(case['writer']['payload_hex'])
            self.assertEqual(cls(*case['values']).encode(),native_bytes)
            self.assertEqual(cls.decode(native_bytes),cls(*case['reader']['values']))
            self.assertTrue(case['writer']['success'])
            self.assertTrue(case['reader']['success'])
            self.assertIn(0x144aa6120,case['writer']['native_io_entries'])
            self.assertIn(0x144aa5ce0,case['reader']['native_io_entries'])

    def test_native_short_buffers_trailing_bytes_and_swap(self):
        for case in self.report['buffer_cases']:
            needed=16 if case['kind']=='ping' else 12
            length=len(bytes.fromhex(case['payload_hex']))
            self.assertEqual(case['success'],length>=needed)
            self.assertEqual(case['consumed'],min(length,needed))
            # Portable API deliberately requires a previously delimited exact payload.
            if length!=needed:
                cls=PingPayload if case['kind']=='ping' else PingResultPayload
                with self.assertRaises(ValueError):cls.decode(bytes.fromhex(case['payload_hex']))
        for case in self.report['swap_cases']:
            fmt='>QQ' if case['kind']=='ping' else '>IQ'
            self.assertEqual(struct.unpack(fmt,bytes.fromhex(case['payload_hex'])),tuple(case['values']))

    def test_reexecute_native_io_for_boundary_and_failure(self):
        path=HERE/'resource-tools/vampir/build-headless-ping-codec.py'
        spec=importlib.util.spec_from_file_location('ping_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        emulator=module.PingEmulator()
        for kind,values in [('ping',(2**64-1,2**53+1)),('result',(2**32-1,2**64-1))]:
            cls=PingPayload if kind=='ping' else PingResultPayload
            payload=cls(*values).encode()
            self.assertEqual(emulator.execute(kind,'write',values)['payload_hex'],payload.hex())
            self.assertEqual(emulator.execute(kind,'read',payload=payload)['values'],list(values))
            failed=emulator.execute(kind,'read',payload=payload[:-1])
            self.assertFalse(failed['success'])
            self.assertEqual(failed['consumed'],len(payload)-1)


if __name__=='__main__':unittest.main()
