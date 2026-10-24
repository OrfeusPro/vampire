import json
from pathlib import Path
import sys
import unittest

from test_vampir_update_contracts import load, HERE

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.login_result import decode_login_result

ROOT = Path('F:/PhoneExit Resources/Vampir')


class LoginResultBodyHandlerContextTests(unittest.TestCase):
    def context(self):
        return json.loads((HERE / 'knowledge/native-contexts/login-result-body-handler-11316.json').read_text('utf-8'))

    def test_same_packet_reader_handler_and_incomplete_gate(self):
        report = load('verify-login-result-context').verify(self.context(), ROOT)
        self.assertTrue(report['native_string_used'])
        self.assertEqual(len(report['construction_cases']), 72)
        self.assertEqual(len(report['evidence']), 9)
        handler = report['handler']
        self.assertTrue(handler['same_packet_reader_used'])
        self.assertEqual((len(handler['cases']), len(handler['rejected'])), (44, 131))
        self.assertFalse(report['network_used'] or report['profile_activated'])
        for case in handler['cases']:
            decoded = case['decoded']
            self.assertEqual(decoded['returned'], 1)
            self.assertEqual(decoded['input_entries']['string'], 7)
            model = decode_login_result(bytes.fromhex(decoded['body_hex']), max_payload_size=4096)
            for key in ('strings', 'u16', 'u32', 'u64', 'flags'):
                self.assertEqual(list(getattr(model, key)), decoded['fields'][key])
            fields = decoded['fields']
            self.assertEqual((fields['u32'][0], fields['u16'][0], fields['u16'][1]),
                             (case['code'], case['field48'], case['raw16']))
            actions = [e['action'] for e in case['events']]
            early = case['settings'].get('peer_flag') and 0 < case['field48'] < 32768
            successful = case['code'] == 0 and not early
            if successful:
                self.assertEqual(case['state']['text'], fields['strings'][0])
                expected = dict(zip(('0x38', '0x88', '0xb0', '0xc0', '0xd0', '0xe0'),
                                    (fields['u64'][1], fields['u64'][1], *fields['u64'][4:])))
                self.assertEqual(case['state']['qwords'], expected)
                self.assertEqual(case['state']['flags'], {'0xa0': fields['flags'][2], '0xe8': fields['flags'][3]})
                self.assertEqual(len([w for w in case['writes'] if w['region'] == 'state']), 8)
                self.assertIn('post_state', actions)
            else:
                self.assertEqual(case['state']['text'], 'before')
                self.assertFalse([w for w in case['writes'] if w['region'] in ('state', 'controller')])
                self.assertNotIn('post_state', actions)
            self.assertTrue(case['handler_invoked'] and case['guards'])
        for case in handler['rejected']:
            self.assertEqual(case['decoded']['returned'], 0)
            self.assertFalse(case['handler_invoked'] or case['events'] or case['writes'])

    def test_expansion_requires_exact_reviewed_scope(self):
        tool = load('verify-login-result-context')
        for budget, scope in ((22, None), (22, 'login-result-buffer'), (23, 'login-result-body-handler'), (32, 'login-result-body-handler')):
            context = self.context()
            context.update(function_budget=budget, budget_scope=scope)
            with self.assertRaisesRegex(ValueError, 'function/export budget exceeded'):
                tool.verify(context, ROOT)

    def test_handler_source_and_gate_export_must_match(self):
        context = self.context()
        context['native_handler']['source_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'handler source differs'):
            load('verify-login-result-context').verify(context, ROOT)
        context = self.context()
        context['native_handler']['exports']['run-eff5f37ca91c'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'export SHA changed'):
            load('verify-login-result-context').verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
