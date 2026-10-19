"""Winsock fixtures prove native resolver traversal/order/completion, not live DNS."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest


class ResolverJobResultsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-resolver-job-results.py'
        spec=importlib.util.spec_from_file_location('resolver_job_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/resolver-job-results-replay.json').read_text('utf-8'))
        cls.cases={c['fixture']['name']:c for c in cls.report['cases']}

    def test_source_imports_and_job_slots(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),8)
        self.assertEqual(self.report['inet_ntop_thunk']['iat_address'],0x148945b18)
        self.assertEqual({(i['dll'].lower(),i['name']) for i in self.report['imports']},
                         {('ws2_32.dll','getaddrinfo'),('ws2_32.dll','inet_ntop')})
        table=bytes.fromhex(self.report['resolver_vtable']['bytes'])
        self.assertEqual(struct.unpack_from('<QQ',table,0x10),(0x1445e7e00,0x1445e7cf0))
        for case in self.report['cases']:
            dns=next(e for e in case['events'] if e['action']=='getaddrinfo_fixture')
            self.assertEqual(dns['hints'],[0,0,1,6])
            self.assertTrue(dns['service_null'])
            self.assertEqual(dns['host'],'resolver-test.invalid')

    def test_family_traversal_and_native_order_swap(self):
        expected={'v4':['192.0.2.1'],'v6':['2001:db8::1'],
                  'v4-v6':['2001:db8::1','192.0.2.1'],'v6-v4':['2001:db8::1','192.0.2.1'],
                  'v4-v4-v6':['2001:db8::1','192.0.2.2','192.0.2.1']}
        for name,addresses in expected.items():
            case=self.cases[name]
            self.assertEqual(case['result_addresses'],addresses)
            delivered=[e for e in case['events'] if e['action']=='resolved_result_dispatch_capture']
            self.assertEqual(delivered,[dict(action='resolved_result_dispatch_capture',callback=0x141423088,addresses=addresses)])
            actions=[e['action'] for e in case['events']]
            self.assertLess(actions.index('fixture_job_drain'),actions.index('getaddrinfo_fixture'))
            self.assertLess(actions.index('fixture_completion_drain'),actions.index('resolved_result_dispatch_capture'))
            self.assertIn('resolver_payload_destroy_capture',actions)

    def test_error_empty_and_unknown_family_use_failure_callback(self):
        for name in ('dns-error','empty-results','unsupported-family'):
            case=self.cases[name];events=case['events']
            self.assertFalse(any(e['action']=='resolved_result_dispatch_capture' for e in events))
            failure=[e for e in events if e['action']=='resolver_failure_dispatch_capture']
            self.assertEqual(len(failure),1)
            self.assertEqual(case['result_addresses'],None if name=='dns-error' else [])
            self.assertFalse(any(e['action']=='inet_ntop_fixture' for e in events))


if __name__=='__main__':
    unittest.main()
