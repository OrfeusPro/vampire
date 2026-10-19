"""Native socket completion reaches source-bound peer and transport listeners."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest


class SocketReadyNotificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-socket-ready-notification.py'
        spec=importlib.util.spec_from_file_location('ready_notification_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/socket-ready-notification-replay.json').read_text('utf-8'))
        cls.cases={c['fixture']['name']:c for c in cls.report['cases']}

    def test_reproducible_source_subscribers_actions_and_vtables(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),10)
        self.assertEqual(len(self.report['subscriber_source_bindings']),15)
        self.assertEqual(self.report['diagnostics'][1]['text'],'NnPeerImpl::OnTcpPeerConnected()')
        tables=self.report['tables']
        self.assertEqual(struct.unpack_from('<Q',bytes.fromhex(tables[0]['bytes']),0x10)[0],0x1445e8900)
        self.assertEqual(struct.unpack_from('<Q',bytes.fromhex(tables[1]['bytes']),0x18)[0],0x144aac520)
        self.assertEqual([r['bytes'] for r in self.report['leaves'][:2]],['488b01ff6010','488b01ff6018'])

    def test_ready_reaches_two_recipients_and_gated_owner_callback(self):
        for name in ('ready-owner','no-owner-count','null-owner','special-flag'):
            c=self.cases[name]
            self.assertEqual((c['state_after'],c['peer_state_after'],c['completion_codes']),(6,1,[1]))
            self.assertEqual((c['transport_word_after'],c['transport_qword_after']),(0,0))
            actions=[e['action'] for e in c['events']]
            self.assertLess(actions.index('native_socket_ready_recipient'),actions.index('native_transport_ready_recipient'))
            callbacks=[e for e in c['events'] if e['action']=='owner_virtual_60_capture']
            self.assertEqual(len(callbacks),int(name in ('ready-owner','special-flag')))
            if callbacks:self.assertEqual(callbacks[0]['string_descriptor'],'00'*16)
            config=next(e for e in c['events'] if e['action']=='socket_configuration_capture')
            self.assertEqual((config['arg_edx'],config['arg_r8d'],config['arg_r9b']),(2,16,1))
            self.assertEqual(c['listener_strong_counts'],[4,4])
        self.assertEqual(self.cases['special-flag']['special_bytes_after'],'0001')
        self.assertTrue(any(e['action']=='special_flag_helper_capture' for e in self.cases['special-flag']['events']))

    def test_empty_expired_and_null_listeners_stop_at_correct_boundary(self):
        for kind in ('socket','peer'):
            for prefix in ('empty-','expired-','null-'):
                name=prefix+kind+('-listener' if prefix=='null-' else '')
                c=self.cases[name]
                self.assertEqual((c['state_after'],c['completion_codes']),(6,[1]))
                self.assertEqual(c['peer_state_after'],2 if kind=='socket' else 1)
                self.assertEqual((c['transport_word_after'],c['transport_qword_after']),(1234,5678))
                self.assertFalse(any(e['action'] in ('native_transport_ready_recipient','owner_virtual_60_capture') for e in c['events']))
                pruned=[e['queue'] for e in c['events'] if e['action']=='listener_prune_capture']
                self.assertEqual(pruned,[] if prefix=='empty-' else [kind])
                self.assertEqual(c['listener_strong_counts'],[0,4] if name=='expired-socket' else [4,0] if name=='expired-peer' else [4,4])


if __name__=='__main__':
    unittest.main()
