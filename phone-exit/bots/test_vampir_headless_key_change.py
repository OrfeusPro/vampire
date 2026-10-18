"""Shared key payload versus native IO and acknowledgement-before-update slices."""
import hashlib
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.key_change import KeyChangePayload,KEY_CHANGE_NOTIFY_ID,KEY_CHANGED_ID


class KeyPayloadTests(unittest.TestCase):
    def test_bits_lengths_and_repr(self):
        key=KeyChangePayload(0x0102030405060708)
        self.assertEqual(key.encode(),bytes.fromhex('0807060504030201'))
        self.assertEqual(KeyChangePayload.decode(key.encode()),key)
        self.assertEqual(repr(key),'KeyChangePayload(<redacted>)')
        for value in [-1,2**64,True,'0',1.0]:
            with self.assertRaises(ValueError):KeyChangePayload(value)
        for length in [0,7,9,100]:
            with self.assertRaises(ValueError):KeyChangePayload.decode(bytes(length))
        self.assertEqual((KEY_CHANGE_NOTIFY_ID,KEY_CHANGED_ID),(11,12))


class NativeKeyChangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))
        path=root/'code-clues/headless-key-change.json'
        if not path.exists():raise unittest.SkipTest('Generate key-change evidence first')
        cls.report=json.loads(path.read_text('utf-8'))
        cls.raw=Path(cls.report['source']).read_bytes()

    def test_original_bytes_and_scope(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),self.report['sha256'])
        self.assertFalse(self.report['network_ready'])
        for row in self.report['data_anchors']:
            content=bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset']+len(content)],content)
            self.assertEqual(hashlib.sha256(content).hexdigest(),row['sha256'])
        for f in self.report['fragments']:
            content=self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(content).hexdigest(),f['sha256'])
            self.assertEqual(b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']),content)

    def test_codec_matches_both_native_packet_types(self):
        self.assertEqual(len(self.report['payload_cases']),10)
        for case in self.report['payload_cases']:
            payload=KeyChangePayload(case['bits'])
            self.assertEqual(payload.encode().hex(),case['payload_hex'])
            self.assertEqual(KeyChangePayload.decode(payload.encode()).key_bits,case['decoded'])
            self.assertEqual(case['packet_id'],11 if case['kind']=='notify' else 12)
        for case in self.report['short_cases']:self.assertFalse(case['read_success'])

    def test_native_flow_order_even_when_send_returns_false(self):
        self.assertEqual(len(self.report['flow_cases']),20)
        for case in self.report['flow_cases']:
            self.assertEqual(case['events'],[
                dict(event='send_ack',key_at_send=case['old_key'],ack_bits=case['new_key']),
                dict(event='set_key')])
            self.assertEqual(case['final_key'],case['new_key'])

    def test_native_replay(self):
        path=HERE/'resource-tools/vampir/build-headless-key-change.py'
        spec=importlib.util.spec_from_file_location('key_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        emulator=module.KeyChangeEmulator()
        for send_result in [False,True]:
            result=emulator.flow(0x0102030405060708,0xffffffffffffffff,send_result)
            self.assertEqual(result['events'][0]['key_at_send'],0x0102030405060708)
            self.assertEqual(result['final_key'],0xffffffffffffffff)
        for kind in ['notify','ack']:
            result=emulator.payload(kind,2**53+1)
            self.assertEqual(result['payload_hex'],KeyChangePayload(2**53+1).encode().hex())


if __name__=='__main__':unittest.main()
