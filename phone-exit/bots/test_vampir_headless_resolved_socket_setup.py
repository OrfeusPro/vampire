"""Resolved address reaches native peer recipient and socket creation, using fake Winsock."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest


class ResolvedSocketSetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-resolved-socket-setup.py'
        spec=importlib.util.spec_from_file_location('resolved_socket_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/resolved-socket-setup-replay.json').read_text('utf-8'))
        cls.cases={c['fixture']['name']:c for c in cls.report['cases']}

    def test_source_recipient_vtables_and_socket_ordinal(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),7)
        self.assertEqual((self.report['socket_import']['dll'].lower(),self.report['socket_import']['ordinal']),('ws2_32.dll',23))
        self.assertEqual(self.report['socket_export']['name'],'socket')
        tables=self.report['tables']
        self.assertEqual(struct.unpack_from('<Q',bytes.fromhex(tables[0]['bytes']),8)[0],0x1445e8400)
        self.assertEqual(struct.unpack_from('<Q',bytes.fromhex(tables[1]['bytes']),8)[0],0x1445e5cb0)
        self.assertEqual(self.report['action_leaf']['bytes'],'488b01ff6008')
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x144aab5b0]['operands'],'qword ptr [rsi + 0x38], rax')
        self.assertEqual(rows[0x1445e2c92]['operands'],'qword ptr [rsi + 0x110], rax')

    def test_address_selection_and_native_socket_arguments(self):
        for name,host,family,tag,remaining in [('v4','192.0.2.1',2,0,0),
            ('v6','2001:db8::1',23,1,0),('mixed','2001:db8::1',23,1,1)]:
            case=self.cases[name];events=case['events']
            self.assertEqual(next(e for e in events if e['action']=='winsock_socket_fixture'),
                dict(action='winsock_socket_fixture',family=family,type=1,protocol=0,returned=42))
            self.assertEqual(next(e for e in events if e['action']=='socket_endpoint_connect_capture'),
                dict(action='socket_endpoint_connect_capture',host=host,port=12345,family_tag=tag,returned=True))
            self.assertEqual(case['socket_handle_dword'],42)
            self.assertEqual(case['queued_candidates'],remaining)
            self.assertEqual([e['selector'] for e in events if e['action']=='socket_option_capture'],[9,6])
            actions=[e['action'] for e in events]
            self.assertLess(actions.index('fixture_completion_drain'),actions.index('native_resolved_recipient_entry'))
            self.assertLess(actions.index('native_resolved_recipient_entry'),actions.index('winsock_socket_fixture'))

    def test_create_mode_connect_and_dns_failures(self):
        for name in ('socket-fail','mode-fail'):
            events=self.cases[name]['events']
            self.assertIn('socket_failure_report_capture',[e['action'] for e in events])
            self.assertFalse(any(e['action']=='socket_endpoint_connect_capture' for e in events))
        self.assertEqual(self.cases['socket-fail']['socket_handle_dword'],0)
        events=self.cases['connect-fail']['events']
        self.assertTrue(any(e['action']=='socket_connect_failure_continuation_capture' for e in events))
        self.assertFalse(any(e['action']=='winsock_socket_fixture' for e in self.cases['dns-fail']['events']))
        for case in self.report['cases']:
            self.assertEqual(case['busy_after_connect'],1)


if __name__=='__main__':
    unittest.main()
