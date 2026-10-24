import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/version-result-handler-11316.json'


class VersionResultHandlerContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_native_gate_and_login_handoff(self):
        report = load('verify-version-result-handler-context').verify(self.context(), ROOT)
        self.assertEqual(len(report['cases']), 14)
        for case in report['cases']:
            self.assertEqual('login_prepare' in case['events'], case['code'] == 0)
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])

    def test_changed_registration_rejected(self):
        context = self.context()
        context['handler_table'] = '0x149dc65b8'
        with self.assertRaisesRegex(ValueError, 'handler registration link differs'):
            load('verify-version-result-handler-context').verify(context, ROOT)

    def test_changed_login_handoff_rejected(self):
        context = self.context()
        context['login_prepare'] = '0x1467ce6a0'
        with self.assertRaisesRegex(ValueError, 'Login tail handoff differs'):
            load('verify-version-result-handler-context').verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
