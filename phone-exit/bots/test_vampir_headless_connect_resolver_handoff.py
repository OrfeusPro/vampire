"""Lower-connect lexical routing and job handoff are distinct from socket readiness."""
import importlib.util
import json
from pathlib import Path
import unittest


class ConnectResolverHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-connect-resolver-handoff.py'
        spec=importlib.util.spec_from_file_location('resolver_handoff_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/connect-resolver-handoff-replay.json').read_text('utf-8'))
        cls.cases={c['fixture']['name']:c for c in cls.report['cases']}

    def test_source_native_peer_fields_and_resolver_job(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),12)
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x1445ea3e0]['operands'],'word ptr [rdi + 0x90], ax')
        self.assertEqual(rows[0x1445ea3ee]['operands'],'dword ptr [rdi + 0x94], eax')
        self.assertEqual(rows[0x1445ea3f4]['operands'],'dword ptr [rdi + 0xc0], r12d')
        self.assertEqual(rows[0x1445ea3fb]['direct_target'],0x1445e6d70)
        self.assertEqual(rows[0x1445e6ef1]['operands'],'qword ptr [rdi + 0x20], rsi')
        self.assertEqual(self.report['hex_leaf']['instructions'][-1]['mnemonic'],'ret')

    def test_lexical_numeric_and_hex_are_not_ip_validation(self):
        numeric=('127.0.0.1','999.999.999.999','1..2','.','::1','ABCDEF')
        for name,case in self.cases.items():
            actions=[e['action'] for e in case['events']]
            if name in numeric:
                self.assertIn('numeric_address_parse_capture',actions,name)
                self.assertNotIn('resolver_job_enqueue_capture',actions,name)
            else:
                self.assertIn('resolver_job_enqueue_capture',actions,name)
                self.assertNotIn('numeric_address_parse_capture',actions,name)
            self.assertEqual(case['peer_host'],case['fixture']['records'][0]['text'])
            self.assertEqual((case['peer_port'],case['peer_endpoint_field'],case['peer_mode']),(12345,0,0))

    def test_registration_insert_skip_and_boolean_handoff(self):
        for name,case in self.cases.items():
            already=case['fixture']['already_listed']
            self.assertEqual(case['registration_counts'],[1,1])
            self.assertEqual(sum(e['action']=='native_registration_insert' for e in case['events']),0 if already else 2)
            self.assertEqual(case['registration_weak_counts'],[5,5])
            returned=[e['al'] for e in case['events'] if e['action']=='native_lower_connect_return']
            self.assertEqual(returned,[0 if name=='enqueue-zero' else 1])
            self.assertEqual(case['busy_after_connect'],1)
        case=self.cases['enqueue-two']
        self.assertEqual(next(e['returned'] for e in case['events'] if e['action']=='resolver_job_enqueue_capture'),2)


if __name__=='__main__':
    unittest.main()
