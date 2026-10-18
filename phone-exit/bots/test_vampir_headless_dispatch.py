"""Native Dispatch to OnHandler entry, failures and selected shared decoder."""
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
from vampir_core.receive_packet import decode_game_ping_result
from vampir_core.frame_primitives import xor_transform


def frame(payload,packet_id=17):
    body=struct.pack('<H',packet_id)+payload
    return (len(body)+3).to_bytes(3,'little')+xor_transform(body)


class SharedGamePacketTests(unittest.TestCase):
    def test_typed_result_and_strict_local_policy(self):
        payload=struct.pack('<IQ',0xffffffff,0xffffffffffffffff)
        raw=frame(payload)
        value=decode_game_ping_result(raw,max_frame_size=128)
        self.assertEqual(value.result_bits,0xffffffff)
        self.assertEqual(value.value_bits,0xffffffffffffffff)
        for bad in [raw[:-1],raw+raw,frame(payload+b'x'),frame(payload,16),frame(payload[:11])]:
            with self.assertRaises(ValueError):decode_game_ping_result(bad,max_frame_size=128)


class NativeDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))
        path=root/'code-clues/headless-dispatch.json'
        if not path.exists():raise unittest.SkipTest('Generate Dispatch evidence first')
        cls.report=json.loads(path.read_text('utf-8'))
        cls.raw=Path(cls.report['source']).read_bytes()

    def test_provenance_and_handler_wrapper(self):
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),self.report['sha256'])
        for f in self.report['fragments']:
            data=self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(data).hexdigest(),f['sha256'])
            self.assertEqual(b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']),data)
        for row in self.report['leaves']+[self.report['handler_table']]:
            data=bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset']+len(data)],data)
        self.assertEqual(self.report['leaves'][0]['bytes'],'488b0148ff6010')

    def test_native_success_short_unknown_and_trailing_vectors(self):
        self.assertEqual(len(self.report['cases']),24)
        for case in self.report['cases']:
            payload=bytes.fromhex(case['payload_hex'])
            self.assertTrue(case['context_cleared']);self.assertEqual(case['remaining_hex'],'')
            if case['packet_id']!=17:
                self.assertEqual(case['unknown_ids'],[case['packet_id']]);self.assertEqual(case['handler_events'],[])
            elif len(payload)<12:
                self.assertEqual(case['decode_failures'],1);self.assertEqual(case['handler_events'],[])
            elif len(payload)==12:
                decoded=decode_game_ping_result(frame(payload),max_frame_size=2048)
                self.assertEqual(case['handler_events'],[dict(result_bits=decoded.result_bits,value_bits=decoded.value_bits)])
            else:
                self.assertEqual(len(case['handler_events']),1)
                with self.assertRaises(ValueError):decode_game_ping_result(frame(payload),max_frame_size=2048)

    def test_native_replay_mixed_contexts(self):
        path=HERE/'resource-tools/vampir/build-headless-dispatch.py'
        spec=importlib.util.spec_from_file_location('dispatch_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        emulator=module.DispatchEmulator()
        for size,packet_id in [(12,17),(3,17),(12,18),(12,17),(0,17)]:
            case=emulator.execute_dispatch(bytes(range(size)),packet_id)
            self.assertEqual(len(case['handler_events']),int(size>=12 and packet_id==17))
            self.assertTrue(case['context_cleared'])


if __name__=='__main__':unittest.main()
