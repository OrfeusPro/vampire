"""Current Clock/Lobby/producer package and source guards; no network."""
import json
from pathlib import Path
import unittest
from test_vampir_update_contracts import load,HERE

ROOT=Path('F:/PhoneExit Resources/Vampir')


class LoginPing11318Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.batch=load('run-clock-world-batch-11318').run(ROOT)[1]

    def test_current_clock_and_lobby(self):
        report=self.batch['reports']['clock']
        self.assertEqual((len(report['cases']),len(report['lobby_cases'])),(24,10))
        self.assertEqual(report['system_import']['name'],'GetSystemTime')
        self.assertFalse(report['network_used'] or report['profile_activated'])

    def test_current_producer_and_packet(self):
        report=self.batch['reports']['producer']
        self.assertEqual(len(report['cases']),36)
        self.assertEqual(report['packet_id'],16)
        self.assertTrue(any(c['recovery'] for c in report['cases']))
        self.assertFalse(report['network_used'] or report['profile_activated'])

    def test_changed_export_rejects_native_harness(self):
        context=json.loads((HERE/'knowledge/native-contexts/clock-replays-11318.json').read_bytes())
        with self.assertRaisesRegex(ValueError,'export SHA'):
            load('replay-login-ping-11318').verify({k:'0'*64 for k in context['exports']})


if __name__=='__main__':unittest.main()
