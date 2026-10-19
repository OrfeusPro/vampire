"""ChannelManager forwards saved player to Auth; neither AL nor callback marker proves login."""
import importlib.util
import json
from pathlib import Path
import unittest


class ChannelSilentHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-channel-silent-handoff.py'
        spec=importlib.util.spec_from_file_location('channel_handoff_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/channel-silent-handoff-replay.json').read_text('utf-8'))

    def test_source_and_native_getters(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(self.report['support_leaf']['instructions'][0]['rip_references'],[0x14b4f13f8])
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x144520a4f]['operands'],'rax, [rbx + 0x150]')
        self.assertEqual(rows[0x1444fee6b]['direct_target'],0x1444fdd00)
        self.assertTrue(any('FAuthImpl::SignInSilently(' in r['text'] for r in self.report['literals']))

    def test_channel_rejects_before_auth_or_forwards_exact_player_and_callback(self):
        self.assertEqual(len(self.report['cases']),8)
        for case in self.report['cases']:
            f=case['fixture'];events=case['events']
            self.assertEqual(events[0],dict(action='callback_binding_capture',offset=0xd0))
            auth=[e for e in events if e['action']=='auth_silent_capture']
            if not f['supported'] or not f['initialized']:
                self.assertEqual(auth,[])
                self.assertIsNone(case['returned_al'])
                self.assertIn(case['stop_address'],self.tool.STOPS)
            else:
                self.assertEqual(case['returned_al'],1)
                self.assertEqual(auth,[dict(action='auth_silent_capture',player_id=f['player_id'],
                                            callback_marker=0x11223344 if f['callback'] else 0)])
                self.assertEqual(sum(e['action']=='function_clone_fixture' for e in events),2 if f['callback'] else 0)
                self.assertEqual(sum(e['action']=='function_release_capture' for e in events),2 if f['callback'] else 0)

    def test_auth_gate_rejects_empty_saved_player(self):
        cases={c['fixture']['name']:c for c in self.report['auth_gate_cases']}
        self.assertEqual(cases['auth-uninitialized']['stop_address'],0x1444fdde4)
        self.assertEqual(cases['auth-empty']['stop_address'],0x1444fdf0d)
        for name in ('auth-single','auth-player'):
            self.assertEqual(cases[name]['stop_address'],0x1444fdfea)
        for case in cases.values():
            self.assertEqual(case['events'][0],dict(action='callback_binding_capture',offset=0xa8))


if __name__=='__main__':
    unittest.main()
