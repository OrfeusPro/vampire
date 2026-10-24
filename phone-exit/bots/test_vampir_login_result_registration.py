import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')


class LoginResultRegistrationTests(unittest.TestCase):
    def context(self):
        return json.loads((HERE / 'knowledge/native-contexts/login-result-registration-11316.json').read_text('utf-8'))

    def test_id_four_constructor_registration_handler_chain(self):
        report = load('verify-login-result-registration').verify(self.context(), ROOT)
        self.assertEqual(report['bindings']['handler'], '0x14679aec0')
        self.assertEqual(len(report['evidence']), 2)
        self.assertFalse(report['network_used'])
        self.assertFalse(report['native_execution'])
        self.assertFalse(report['profile_activated'])

    def test_changed_slot_or_argument_binding_rejected(self):
        for name, value, error in (
            ('handler', '0x14679aec1', 'handler slot differs'),
            ('handler_table', '0x149dc65c0', 'handler table link differs'),
            ('packet_constructor', '0x1456d7570', 'argument/control-flow shape differs'),
            ('packet_table', '0x1499263d0', 'packet ID slot differs'),
        ):
            context = self.context()
            context['bindings'][name] = value
            with self.assertRaisesRegex(ValueError, error):
                load('verify-login-result-registration').verify(context, ROOT)

    def test_changed_export_or_handler_call_rejected(self):
        context = self.context()
        context['exports']['run-83255b6c29bc'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'export SHA differs'):
            load('verify-login-result-registration').verify(context, ROOT)
        context = self.context()
        at = next(at for at, target in context['call_sites']['handler'].items() if target == '0x1467cd7b0')
        context['call_sites']['handler'][at] = '0x1467cd7b1'
        with self.assertRaisesRegex(ValueError, 'callees differ'):
            load('verify-login-result-registration').verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
