"""Native keyed receive-B, manager bookkeeping and portable selected codec."""
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
from vampir_core.frame_primitives import xor_transform
from vampir_core.receive_frame import take_receive_b_frame
from vampir_core.receive_packet import decode_game_ping_result_b


def frame(payload,key,packet_id=17):
    body=struct.pack('<H',packet_id)+payload
    return (len(body)+3).to_bytes(3,'little')+xor_transform(body,key)


class SharedReceiveBTests(unittest.TestCase):
    def test_keyed_partial_coalesced_and_input_preserved(self):
        key=0x1020304050607080;payload=struct.pack('<IQ',1,0xffffffffffffffff)
        wire=frame(payload,key)
        for cut in range(len(wire)):
            self.assertIsNone(take_receive_b_frame(wire[:cut],key,max_frame_size=1024))
        original=bytearray(wire+wire)
        self.assertEqual(take_receive_b_frame(original,key,max_frame_size=1024),
                         (wire[:3]+struct.pack('<H',17)+payload,len(wire)))
        self.assertEqual(original,bytearray(wire+wire))
        decoded=decode_game_ping_result_b(wire,key,max_frame_size=1024)
        self.assertEqual((decoded.result_bits,decoded.value_bits),(1,0xffffffffffffffff))
        for key in [-1,1<<64,False,1.5]:
            with self.assertRaises(ValueError):take_receive_b_frame(b'',key,max_frame_size=1024)


class NativeReceiveBTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))
        path=root/'code-clues/headless-receive-b.json'
        if not path.exists():raise unittest.SkipTest('Generate receive-B evidence first')
        cls.report=json.loads(path.read_text('utf-8'));cls.raw=Path(cls.report['source']).read_bytes()

    def test_provenance_and_call_order(self):
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),self.report['sha256'])
        for f in self.report['fragments']:
            data=self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(data).hexdigest(),f['sha256'])
            self.assertEqual(data,b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']))
        for row in [self.report['getter'],self.report['receive_table']]:
            data=bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset']+len(data)],data)
        rows={i['address']:i for f in self.report['fragments'] for i in f['instructions']}
        self.assertEqual(rows[0x144aacb83]['direct_target'],0x144aa6ca0)
        self.assertEqual(rows[0x144aacb88]['operands'],'ebx, word ptr [rbp + 3]')
        self.assertEqual(rows[0x144aacb97]['direct_target'],0x144aa8120)
        self.assertEqual(rows[0x144aacbad]['operands'],'qword ptr [rax + 8]')

    def test_all_native_cases_and_shared_results(self):
        self.assertEqual(self.report['statistics']['native_receive_b_cases'],39)
        for row in self.report['cases']:
            payload=bytes.fromhex(row['payload_hex']);wire=frame(payload,row['test_key_bits'],row['packet_id'])
            self.assertEqual(row['tracked_ids'],[row['packet_id']])
            self.assertTrue(row['context_cleared']);self.assertEqual(row['remaining_hex'],'')
            self.assertEqual(row['free_count'],int(row['manager_mode']=='match'))
            if row['handler_events']:
                decoded=decode_game_ping_result_b(wire,row['test_key_bits'],max_frame_size=2048)
                self.assertEqual(row['handler_events'],[dict(result_bits=decoded.result_bits,value_bits=decoded.value_bits)])
            else:
                with self.assertRaises(ValueError):decode_game_ping_result_b(wire,row['test_key_bits'],max_frame_size=2048)

    def test_native_replay_match_short_then_key_change(self):
        path=HERE/'resource-tools/vampir/build-headless-receive-b.py'
        spec=importlib.util.spec_from_file_location('b_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        emulator=module.ReceiveBEmulator()
        for key,mode,payload in [(0,'empty',bytes(12)),(1,'match',b'short'),
                                 (0xffffffffffffffff,'match',bytes(12)),(17,'miss',bytes(12))]:
            row=emulator.execute_b(payload,key,mode)
            self.assertEqual(len(row['handler_events']),int(len(payload)==12))
            self.assertEqual(row['free_count'],int(mode=='match'))


if __name__=='__main__':unittest.main()
