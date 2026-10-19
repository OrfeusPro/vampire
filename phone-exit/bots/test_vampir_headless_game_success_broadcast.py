"""Native success fanout: source title slot, stale subscribers and child pointer clear."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest


class GameSuccessBroadcastTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-game-success-broadcast.py'
        spec=importlib.util.spec_from_file_location('game_broadcast_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/game-success-broadcast-replay.json').read_text('utf-8'))

    def test_source_table_and_constructor_links(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),12)
        table=self.report['title_vtable']
        self.assertEqual(struct.unpack_from('<Q',bytes.fromhex(table['bytes']),0x30)[0],0x14641dbc0)
        self.assertEqual(len(self.report['title_constructor_leas']),2)
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x14640a700]['operands'],'qword ptr [rbp + 0xa18], rax')
        self.assertEqual(rows[0x14640f885]['operands'],'qword ptr [rcx + 0xa18], rax')
        self.assertEqual(rows[0x14641dbe6]['operands'],'qword ptr [rbx + 0x228], 0')
        action=next(l for l in self.report['leaves'] if l['address']==0x143b8bf10)
        self.assertEqual(action['instructions'][-1]['operands'],'qword ptr [rax + 0x30]')

    def test_only_live_subscribers_receive_action(self):
        for case in self.report['cases']:
            f=case['fixture'];events=case['events']
            with self.subTest(f):
                live=[n for n,k in enumerate(f['subscribers']) if k=='live']
                self.assertEqual([e['subscriber'] for e in events if e['action']=='native_title_slot30_entry'],live)
                self.assertEqual(sum(e['action']=='subscriber_prune_capture' for e in events),int(any(k!='live' for k in f['subscribers'])))
                self.assertEqual(case['subscriber_strong_after'],[0 if k=='expired' else 4 for k in f['subscribers']])
                self.assertTrue(case['original_delegate_cleared'])
                self.assertTrue(case['response_pair_preserved'])
                self.assertEqual(case['owner_strong_after'],4)
                self.assertEqual(case['response_strong_after_dispatch'],5)

    def test_title_child_virtual_arguments_and_pointer_clear(self):
        for case in self.report['cases']:
            f=case['fixture'];events=case['events']
            live=[n for n,k in enumerate(f['subscribers']) if k=='live']
            actual=[e for e in events if e['action']=='title_child_virtual_capture']
            expected=[dict(action='title_child_virtual_capture',subscriber=n,slot=0x598,arg_edx=2,arg_r8b=1)
                      for n in live] if f['window_present'] else []
            self.assertEqual(actual,expected)
            self.assertEqual(case['title_child_cleared'],[not f['window_present'] or k=='live' for k in f['subscribers']])


if __name__=='__main__':
    unittest.main()
