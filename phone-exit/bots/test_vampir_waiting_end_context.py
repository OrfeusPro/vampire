import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/waiting-end-11316.json'


class WaitingEndContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_native_request_and_selection_gates(self):
        report = load('verify-waiting-end-context').verify(self.context(), ROOT)
        self.assertEqual((len(report['cases']), len(report['fallback'])), (16, 8))
        sent = [case for case in report['cases'] if any(e['action'] == 'send' for e in case['events'])]
        self.assertEqual(len(sent), 2)
        self.assertTrue(all(case['peer_flag'] and case['policy_value'] == 1 for case in sent))
        self.assertFalse(any(e['action'] == 'send' for case in report['fallback'] for e in case['events']))
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])

    def test_changed_handler_registration_rejected(self):
        context = self.context()
        context['bindings']['handler_table'] = '0x149dc6690'
        with self.assertRaisesRegex(ValueError, 'handler slot differs'):
            load('verify-waiting-end-context').verify(context, ROOT)

    def test_changed_packet_id_rejected(self):
        context = self.context()
        context['bindings']['request_id'] = context['bindings']['notify_id']
        with self.assertRaisesRegex(ValueError, 'packet ID differs'):
            load('verify-waiting-end-context').verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
