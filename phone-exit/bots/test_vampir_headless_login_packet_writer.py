"""Native Login body vectors, failure propagation and portable codec bounds."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE/'vampir-shared'))
from vampir_core.login_packet import LoginPayload, SOURCE_SHA256


class LoginPacketWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = HERE/'resource-tools/vampir/replay-login-packet-writer.py'
        spec = importlib.util.spec_from_file_location('login_writer_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT/'code-clues/login-packet-writer-replay.json').read_text('utf-8'))

    def test_native_source_and_vectors_reproduce(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertEqual(self.report['sha256'], SOURCE_SHA256)
        self.assertTrue(self.report['native_execution'])
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']), 25)
        self.assertEqual(self.report['packet_binding']['packet_id'], 3)
        self.assertEqual(int.from_bytes(bytes.fromhex(self.report['packet_writer_anchor']['bytes']), 'little'), self.tool.WRITER)
        self.assertTrue(all(c['packet']['qwords']['0x128'] == 0 for c in self.report['cases'][:16]))
        raw = Path(self.report['source']).read_bytes()
        for f in self.report['fragments']:
            content = raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(content).hexdigest(), f['sha256'])

    def test_all_portable_bytes_match_native_writer(self):
        for case in self.report['cases']:
            p = case['packet']
            payload = LoginPayload(tuple(p['strings'][hex(o)] for o in self.tool.STRINGS),
                tuple(p['integers'][hex(o)] for o in self.tool.INTEGERS),
                tuple(p['bytes'][hex(o)] for o in self.tool.BYTES), p['qwords']['0x128'])
            self.assertEqual(payload.encode(max_payload_size=8192), bytes.fromhex(case['payload_hex']))
            self.assertEqual(case['returned'], 1)
        self.assertEqual(LoginPayload(('',)*15, (0,)*4, (0,)*5, 0).encode(max_payload_size=59), bytes(59))

    def test_native_io_failures_are_not_all_propagated(self):
        failures = self.report['failures']
        self.assertEqual(len(failures), 40)
        ignored = [c for c in failures if c['ignored_by_string_helper']]
        self.assertEqual(len(ignored), 30)
        self.assertTrue(all(c['returned'] == 1 and c['raw_calls'] == 40 for c in ignored))
        self.assertTrue(all(c['returned'] == 0 and c['raw_calls'] == c['fail_at'] for c in failures if not c['ignored_by_string_helper']))

    def test_explicit_immutable_fields_and_local_byte_budget(self):
        valid = (('',)*15, (0,)*4, (0,)*5, 0)
        invalid = [(0, ['']*15), (0, ('',)*14), (0, ('',)*16), (0, (1,)+('',)*14),
            (1, [0]*4), (1, (0,)*3), (1, (True,0,0,0)), (1, (-1,0,0,0)), (1, (1<<32,0,0,0)),
            (2, [0]*5), (2, (0,)*4), (2, (256,0,0,0,0)), (2, (True,0,0,0,0)),
            (3, -1), (3, 1<<64), (3, True)]
        for index, value in invalid:
            args = list(valid); args[index] = value
            with self.assertRaises(ValueError):
                LoginPayload(*args)
        for text in ('a\0b', '\ud800', '\udfff', '\ufffe', '\uffff', 'é'*32768):
            with self.assertRaises(ValueError):
                LoginPayload((text,)+('',)*14, *valid[1:])
        model = LoginPayload(('token-fixture',)+('',)*14, *valid[1:])
        self.assertNotIn('token-fixture', repr(model))
        for budget in (True, 0, 58, -1, 1<<24, '1024'):
            with self.assertRaises(ValueError):
                model.encode(max_payload_size=budget)
        with self.assertRaises(BufferError):
            model.encode(max_payload_size=59)
        maximum = LoginPayload(('a'*65535,)+('',)*14, *valid[1:]).encode(max_payload_size=65594)
        self.assertEqual(maximum[:2], b'\xff\xff')
        self.assertEqual(len(maximum), 65594)


if __name__ == '__main__':
    unittest.main()
