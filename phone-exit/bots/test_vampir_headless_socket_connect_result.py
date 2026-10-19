"""Native connect wrapper acceptance differs from syscall success and readiness."""
import importlib.util
import json
from pathlib import Path
import unittest


class SocketConnectResultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-socket-connect-result.py'
        spec=importlib.util.spec_from_file_location('socket_result_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/socket-connect-result-replay.json').read_text('utf-8'))
        cls.cases={c['fixture']['name']:c for c in cls.report['cases']}

    def test_source_imports_and_wrapper_calls(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),16)
        self.assertEqual({i['export']['name'] for i in self.report['imports']},{'connect','inet_addr','htons'})
        self.assertEqual(self.report['ipv6_import']['name'].lower(),'inet_pton')
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x1445e5c69]['direct_target'],0x1445ecbb0)
        self.assertEqual(rows[0x1445ece21]['rip_references'],[0x148945aa0])
        self.assertEqual(rows[0x1445e5c8f]['operands'],'eax, 0xe')

    def test_sockaddr_layout_and_unchanged_state_marker(self):
        for name,family,host,size,address_hex in [
            ('ipv4-immediate',2,'192.0.2.1',16,'02003039c00002010000000000000000'),
            ('ipv6-immediate',23,'2001:db8::1',28,'170030390000000020010db800000000000000000000000100000000')]:
            case=self.cases[name]
            actual=next(e for e in case['events'] if e['action']=='winsock_connect_fixture')
            self.assertEqual((actual['family'],actual['host'],actual['port'],actual['sockaddr_size'],actual['sockaddr_hex']),
                             (family,host,12345,size,address_hex))
            self.assertEqual((case['lower_result'],case['wrapper_result']),(1,1))
        for case in self.report['cases']:
            self.assertEqual((case['socket_state_50'],case['socket_timeout_58']),(2,30000))
        zero=self.cases['zero-handle']['events']
        self.assertFalse(any(e['action']=='option_get_capture' for e in zero))
        self.assertEqual(next(e['handle'] for e in zero if e['action']=='winsock_connect_fixture'),0)

    def test_raw_error_allowlist_and_wait_boundaries(self):
        for code in (0,21,22,23,24,36,37,38):
            case=self.cases['connect-fail-engine-'+str(code)]
            self.assertEqual(case['lower_result'],0)
            self.assertEqual(case['wrapper_result'],int(code in (22,23,37)))
        ready=self.cases['wait-ready']
        self.assertEqual((ready['lower_result'],ready['wrapper_result']),(1,1))
        self.assertEqual([e['requested'] for e in ready['events'] if e['action']=='mode_engine_capture'],[1,0])
        self.assertEqual(next(e['timeout'] for e in ready['events'] if e['action']=='wait_helper_capture'),30000)
        for name in ('wait-false','wait-empty','mode-enter-fail','mode-restore-fail'):
            self.assertEqual((self.cases[name]['lower_result'],self.cases[name]['wrapper_result']),(0,0),name)
        self.assertFalse(any(e['action']=='winsock_connect_fixture' for e in self.cases['mode-enter-fail']['events']))


if __name__=='__main__':
    unittest.main()
