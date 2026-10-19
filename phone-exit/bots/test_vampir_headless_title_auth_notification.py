"""Source-bound title notification and alternate manager policies."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest


class TitleAuthNotificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-title-auth-notification.py'
        spec=importlib.util.spec_from_file_location('title_notify_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/title-auth-notification-replay.json').read_text('utf-8'))
        cls.cases={c['fixture']['name']:c for c in cls.report['cases']}

    def test_source_slot8_and_call_chain(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),7)
        self.assertEqual(struct.unpack_from('<Q',bytes.fromhex(self.report['title_vtable']['bytes']),8)[0],0x14641d560)
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x14560f836]['direct_target'],0x14560eef0)
        self.assertEqual(rows[0x14560f16f]['direct_target'],0x1445f5330)
        leaf=next(l for l in self.report['leaves'] if l['address']==0x141423088)
        self.assertEqual(leaf['instructions'][-1]['operands'],'qword ptr [rax + 8]')
        self.assertTrue(any('GetChannelTypeForNetmarbleId(' in l['text'] for l in self.report['literals']))

    def test_success_notification_is_conditional(self):
        for name,case in self.cases.items():
            actual=[e['target'] for e in case['events'] if e['action']=='title_notification_capture']
            expected=[0x14641d560] if name=='notify-success' else [0x146418830] if name in ('policy220','idp-present') else []
            self.assertEqual(actual,expected,name)
            self.assertEqual(case['owner_strong_after'],4)
            self.assertTrue(case['response_pair_preserved'])
        channels=[e['value'] for e in self.cases['notify-success']['events'] if e['action']=='nid_channel_getter_fixture']
        self.assertEqual(channels,[33])

    def test_alternate_continuations(self):
        expected={'channel100':[0x14560a160],'policy-adb0':[0x145606ca0],
                  'policy-default':[0x145619550],'no-manager-auth':[]}
        for name,targets in expected.items():
            actual=[e['target'] for e in self.cases[name]['events'] if e['action']=='notification_continuation_capture']
            self.assertEqual(actual,targets,name)
        actions=[e['action'] for e in self.cases['notify-success']['events']]
        self.assertLess(actions.index('player_string_assignment_fixture'),actions.index('title_notification_capture'))


if __name__=='__main__':
    unittest.main()
