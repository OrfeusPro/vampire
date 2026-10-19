"""Native VersionResult read/dispatch/result gate routes to the Login routine."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest


class VersionResultHandlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-version-result-handler.py'
        spec=importlib.util.spec_from_file_location('version_result_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/version-result-handler-replay.json').read_text('utf-8'))

    def test_reproducible_packet_handler_and_login_constructor_bindings(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),39)
        self.assertEqual(self.report['packet_name']['name'],'PktVersionResult')
        self.assertEqual(self.report['leaves'][1]['bytes'],'b802000000c3')
        self.assertEqual(struct.unpack_from('<Q',bytes.fromhex(self.report['tables'][0]['bytes']),0x20)[0],0x1456d9b10)
        self.assertEqual(struct.unpack_from('<QQ',bytes.fromhex(self.report['tables'][1]['bytes']),8),(0x141535f20,0x146768360))
        self.assertEqual(self.report['login_packet_binding']['name'],'PktLogin')
        self.assertEqual(self.report['login_packet_binding']['constructor'],0x1456d4c80)

    def test_native_gate_accepts_zero_and_rejects_covered_nonzero_codes(self):
        for c in self.report['cases'][:12]:
            code=struct.unpack_from('<I',bytes.fromhex(c['payload_hex']))[0]
            events=c['events']
            self.assertEqual([e['al'] for e in events if e['action']=='native_result_gate_return'],[int(code==0)])
            self.assertEqual([e['packet_id'] for e in events if e['action']=='native_result_gate'],[2])
            self.assertEqual(sum(e['action']=='login_routine_entry_capture' for e in events),int(code==0))
            expected_error=int(c['state_flag']==0 and code in (1,708,1304,0xffffffff))
            self.assertEqual(sum(e['action']=='result_error_helper_capture' for e in events),expected_error)
            self.assertTrue(c['context_cleared'])

    def test_bool_normalization_trailing_bytes_and_reader_id_gates(self):
        for c in self.report['cases'][12:16]:
            raw=bytes.fromhex(c['payload_hex'])
            values=next(e['values'] for e in c['events'] if e['action']=='native_version_handler')
            expected=list(struct.unpack('<IIBII',raw));expected[2]=int(expected[2]!=0)
            self.assertEqual(values,expected)
            self.assertTrue(any(e['action']=='login_routine_entry_capture' for e in c['events']))
        extra=self.report['cases'][16]
        self.assertTrue(bytes.fromhex(extra['payload_hex']).endswith(b'extra'))
        self.assertTrue(any(e['action']=='login_routine_entry_capture' for e in extra['events']))
        for c in self.report['cases'][17:34]:
            self.assertEqual(c['events'],[])
            self.assertEqual(c['decode_failures'],1)
            self.assertTrue(c['context_cleared'])
        for c in self.report['cases'][34:]:
            self.assertEqual(c['events'],[])
            self.assertEqual(c['unknown_ids'],[c['packet_id']])
            self.assertTrue(c['context_cleared'])


if __name__=='__main__':
    unittest.main()
