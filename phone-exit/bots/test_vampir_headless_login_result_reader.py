"""Native nested LoginResult input and strict portable body decoding."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.login_result import LoginResultBody, decode_login_result, SOURCE_SHA256


class LoginResultReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = HERE/'resource-tools/vampir/replay-login-result-reader.py'
        spec = importlib.util.spec_from_file_location('login_result_test',path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT/'code-clues/login-result-reader-replay.json').read_text('utf-8'))

    def test_native_nested_readers_and_vectors_reproduce(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(self.report['sha256'],SOURCE_SHA256)
        self.assertEqual(self.report['packet_binding']['packet_id'],4)
        self.assertEqual(len(self.report['cases']),21)
        self.assertTrue(self.report['native_execution'])
        self.assertFalse(self.report['network_ready'])

    def test_portable_decode_matches_native_fields(self):
        for case in self.report['cases']:
            body = bytes.fromhex(case['payload_hex'])
            model = decode_login_result(body,max_payload_size=4096)
            fields = case['fields']
            self.assertEqual(model.strings,tuple(fields['strings'][hex(o)] for o in self.tool.STRINGS))
            for key,offsets in (('u32',self.tool.U32),('u16',self.tool.U16),('u64',self.tool.U64)):
                self.assertEqual(getattr(model,key),tuple(fields[key][hex(o)] for o in offsets))
            self.assertEqual(model.flags,tuple(bool(fields['bool'][hex(o)]) for o in self.tool.BOOL))
            self.assertEqual(model.result_code,fields['u32']['0x10'])
            self.assertEqual((case['returned'],case['consumed']),(1,len(body)))
            self.assertNotIn('ASCII',repr(model))

    def test_all_short_inputs_rejected_and_trailing_policy_explicit(self):
        self.assertEqual(len(self.report['truncated']),99)
        self.assertEqual(len(self.report['text_truncated']),233)
        for case in self.report['truncated']+self.report['text_truncated']:
            self.assertEqual(case['returned'],0)
            body = bytes.fromhex(case['payload_hex'])
            self.assertLessEqual(case['consumed'],len(body))
            with self.assertRaises(ValueError):
                decode_login_result(body,max_payload_size=4096)
        case = self.report['trailing']
        self.assertEqual((case['returned'],case['consumed']),(1,99))
        with self.assertRaises(ValueError):
            decode_login_result(bytes.fromhex(case['payload_hex']),max_payload_size=4096)

    def test_local_input_and_text_budgets(self):
        minimal = bytes(99)
        self.assertEqual(decode_login_result(minimal,max_payload_size=99).result_code,0)
        for body in (bytearray(minimal),memoryview(minimal),'',None):
            with self.assertRaises(ValueError): decode_login_result(body,max_payload_size=4096)
        for budget in (True,0,98,-1,1<<24,'1024'):
            with self.assertRaises(ValueError): decode_login_result(minimal,max_payload_size=budget)
        with self.assertRaises(BufferError): decode_login_result(minimal+b'x',max_payload_size=99)
        for data in (b'\xff',b'\0',b'\xed\xa0\x80',b'\xef\xbf\xbe',b'\xef\xbf\xbf'):
            body = minimal[:4]+len(data).to_bytes(2,'little')+data+minimal[6:]
            with self.assertRaises(ValueError): decode_login_result(body,max_payload_size=4096)
        valid = (('',)*7,(0,)*3,(0,)*2,(0,)*8,(False,)*5)
        for index,value in ((0,['']*7),(1,(True,0,0)),(2,(65536,0)),(3,(-1,)*8),(4,(0,)*5)):
            args = list(valid); args[index] = value
            with self.assertRaises(ValueError): LoginResultBody(*args)


if __name__=='__main__':
    unittest.main()
