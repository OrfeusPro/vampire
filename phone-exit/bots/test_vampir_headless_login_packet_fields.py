"""Native Login field sources keep NetmarbleId and SDK token distinct."""
import importlib.util
import json
from pathlib import Path
import unittest


class LoginPacketFieldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-login-packet-fields.py'
        spec=importlib.util.spec_from_file_location('login_fields_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/login-packet-fields-replay.json').read_text('utf-8'))
        cls.cases={c['fixture']['name']:c for c in cls.report['cases']}

    def test_reproducible_source_constructor_and_sdk_getter_chains(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),16)
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x1456d4c8c]['rip_references'],[0x1498d6058])
        self.assertEqual(rows[0x1467a97fd]['operands'],'0x1456d4c80')
        self.assertEqual(rows[0x145604bc6]['operands'],'0x144524940')
        self.assertEqual(rows[0x1445249b6]['operands'],'rdx, [rdi + 0x4a8]')
        self.assertEqual(rows[0x1456039fb]['operands'],'rdx, qword ptr [rdx + 0x78]')
        self.assertEqual(rows[0x1444bb476]['operands'],'0x1444aab90')
        self.assertNotEqual(self.report['globals']['module_cache'],self.report['globals']['settings_cache'])
        self.assertIn('GetNetmarbleId',self.report['diagnostics'][0]['text'])
        self.assertEqual([d['text'] for d in self.report['diagnostics'][1:]],['Android','IOS'])

    def test_raw_fields_platform_selector_and_request_handoff(self):
        for c in self.report['cases']:
            p=c['packet'];f=c['fixture']
            self.assertEqual([p['strings'][hex(o)] for o in (0x10,0x20,0x40,0x78,0x88,0x110)],
                ['wrapper-f0','wrapper-e0','global-text','getter-c63a0','wrapper-100','version-fixture'])
            self.assertEqual(p['integers'],{'0x50':123,'0xb0':42,'0xf8':207,'0x120':2})
            self.assertEqual(p['bytes']['0x99'],{'Android':0,'IOS':1}.get(f['platform'],3))
            self.assertEqual(p['bytes']['0x98'],{0:0,1:1,2:2,3:3,4:5}.get(f['selector'],0))
            self.assertEqual([e['raw_kind'] for e in c['events'] if e['action']=='login_request_handoff_capture'],[4])
            self.assertEqual([e['raw_timeout'] for e in c['events'] if e['action']=='login_request_handoff_capture'],[0])

    def test_sdk_absence_gates_and_old_cache_is_not_fresh_auth(self):
        for name,c in self.cases.items():
            f=c['fixture'];s=c['packet']['strings'];active=f['sdk_enabled'] and f['manager_present'] and f['auth_present']
            expected_id=f['netmarble_id'] if active and f['settings_present'] else ''
            expected_token=(f['sdk_token'] if f['module_present'] else f.get('cached_token','')) if active else ''
            self.assertEqual((s['0x30'],s['0xa0']),(expected_id,expected_token))
            self.assertEqual(s['0xd8'],'collector-fixture' if f['sdk_enabled'] and f['manager_present'] else '')
            entries=[e['address'] for e in c['events'] if e['action']=='native_accessor_entry']
            self.assertIn(0x1456d4c80,entries)
            self.assertEqual(0x145604b90 in entries,bool(active))
            self.assertEqual(0x1456039c0 in entries,bool(active))
        self.assertEqual(self.cases['module-absent']['packet']['strings']['0xa0'],'')
        self.assertEqual(self.cases['module-absent-old-cache']['packet']['strings']['0xa0'],'old-cache-fixture')


if __name__=='__main__':
    unittest.main()
