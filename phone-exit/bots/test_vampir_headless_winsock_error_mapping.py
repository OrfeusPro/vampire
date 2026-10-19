"""Actual native WSA mapping is used by connect wrapper; no real WSA calls."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest


class WinsockErrorMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-winsock-error-mapping.py'
        spec=importlib.util.spec_from_file_location('wsa_mapping_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/winsock-error-mapping-replay.json').read_text('utf-8'))
        cls.cases={c['fixture']['wsa_error']:c for c in cls.report['cases']}

    def test_source_switch_vtable_constructor_and_import(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),43)
        self.assertEqual(self.report['wsa_export']['name'],'WSAGetLastError')
        self.assertEqual(self.report['wsa_import']['ordinal'],111)
        self.assertEqual(struct.unpack_from('<Q',bytes.fromhex(self.report['engine_vtable']['bytes']),0x68)[0],0x1445f0680)
        self.assertEqual(len(self.report['switch_table']['targets']),37)
        rows={r['address']:r for r in self.report['code']['instructions']}
        self.assertEqual(rows[0x1445f0684]['rip_references'],[0x148945ad0])
        self.assertEqual(rows[0x1445f0692]['operands'],'0x1445f081c')
        self.assertLess(max(rows),self.report['switch_table']['address'])
        self.assertTrue(all(t in rows for t in self.report['switch_table']['targets']))

    def test_numeric_mapping_and_native_wrapper_acceptance(self):
        expected={10035:37,10036:23,10037:22,10056:2,10057:19,10061:6}
        for error,value in expected.items():
            self.assertEqual(self.cases[error]['mapped_error'],value,error)
        accepted=[e for e,c in self.cases.items() if c['wrapper_result']]
        self.assertEqual(sorted(accepted),[10035,10036,10037])
        for c in self.cases.values():
            self.assertEqual(c['lower_result'],0)
            self.assertEqual([e['value'] for e in c['events'] if e['action']=='WSAGetLastError_fixture'],[c['fixture']['wsa_error']])
            self.assertFalse(any(e['action']=='engine_error_capture' for e in c['events']))
            self.assertEqual([e['value'] for e in c['events'] if e['action']=='native_mapped_error_return'],[c['mapped_error']])

    def test_outside_switch_range_uses_default_not_success(self):
        for error in (0,10004,10013,10034,10072,11001):
            self.assertEqual(self.cases[error]['mapped_error'],30,error)
            self.assertEqual(self.cases[error]['wrapper_result'],0,error)


if __name__=='__main__':
    unittest.main()
