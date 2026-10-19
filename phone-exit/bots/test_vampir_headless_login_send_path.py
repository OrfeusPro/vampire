"""Native request handoff to owning Login frame queue, without live sockets."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest
import zlib

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE/'vampir-shared'))
from vampir_core.frame_primitives import xor_transform
from vampir_core.login_packet import LoginPayload, SOURCE_SHA256


class LoginSendPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = HERE/'resource-tools/vampir/replay-login-send-path.py'
        spec = importlib.util.spec_from_file_location('login_send_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT/'code-clues/login-send-path-replay.json').read_text('utf-8'))

    def test_native_report_and_source_bindings_reproduce(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertEqual(self.report['sha256'], SOURCE_SHA256)
        self.assertTrue(self.report['native_execution'])
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']), 34)
        table = bytes.fromhex(self.report['anchors'][0]['bytes'])
        self.assertEqual(struct.unpack_from('<Q', table, 0x38)[0], 0x1467aaa10)
        rows = {r['address']: r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x144aa80d9]['direct_target'], 0x144aa7640)
        self.assertEqual(rows[0x144aa80f3]['direct_target'], 0x144aa7870)
        self.assertEqual(rows[0x144aa8106]['operands'], 'qword ptr [r8 + 0x38]')

    def test_all_29_frames_match_portable_body_crc_sequence_xor(self):
        cases = [c for c in self.report['cases'] if c['frame_hex']]
        self.assertEqual(len(cases), 29)
        for case in cases:
            f, p = case['fixture'], case['packet_fields']
            body = LoginPayload(tuple(p['strings'][hex(o)] for o in self.tool.writer.STRINGS),
                tuple(p['integers'][hex(o)] for o in self.tool.writer.INTEGERS),
                tuple(p['bytes'][hex(o)] for o in self.tool.writer.BYTES), p['qwords']['0x128']).encode(max_payload_size=4096)
            inner = struct.pack('<HH', 3, f['sequence'])+body
            clear = struct.pack('<I', zlib.crc32(inner))+inner
            expected = (len(clear)+3).to_bytes(3, 'little')+xor_transform(clear, f['key'])
            self.assertEqual(case['frame_hex'], expected.hex())
            self.assertEqual((case['sequence_after'], case['queue_calls'], case['wake_calls']),
                ((f['sequence']+1)&65535, 1, int(f['wake'])))
            self.assertTrue(case['queue_owns_bytes'])
            self.assertEqual(case['packet_byte_a'], f['metadata_byte'] if f['metadata_present'] else 0)
            entries = [e['address'] for e in case['events'] if e['action'] == 'native_entry']
            self.assertEqual(entries, [0x144aa8020, 0x144aaa9d0, 0x1467aaa10, 0x144aab2f0, 0x144aaccf0, 0x1456e57c0])

    def test_request_dedup_timeout_and_pre_frame_refusal(self):
        duplicates = {'duplicate-inline', 'duplicate-chain-external'}
        refusals = {'disabled', 'mode-two', 'special'}
        for case in self.report['cases']:
            f = case['fixture']
            inserts = [e for e in case['events'] if e['action'] == 'request_insert_capture']
            notices = [e for e in case['events'] if e['action'] == 'request_notify_capture']
            if f['name'] in duplicates:
                self.assertEqual((inserts, notices, case['queue_calls'], case['frame_hex']), ([], [], 0, ''))
                self.assertEqual([e['address'] for e in case['events'] if e['action'] == 'native_entry'], [0x144aa8020])
            else:
                self.assertEqual(len(inserts), 1)
                self.assertEqual(inserts[0]['kind'], 4)  # Response/request kind is separate from packet ID3.
                self.assertEqual(inserts[0]['timeout'], f['timeout'] if f['timeout'] else f['default_timeout'])
                self.assertEqual(inserts[0]['opaque_argument'], 0x12345678)
                self.assertEqual(notices, [dict(action='request_notify_capture', callback=0x141423088)])
                self.assertLess(case['events'].index(inserts[0]), case['events'].index(notices[0]))
            if f['name'] in duplicates | refusals:
                self.assertEqual((case['sequence_after'], case['queue_calls'], case['wake_calls'], case['frame_hex']),
                    (f['sequence'], 0, 0, ''))
                self.assertFalse(any(e.get('address') == 0x1456e57c0 for e in case['events']))


if __name__ == '__main__':
    unittest.main()
