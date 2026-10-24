import importlib.util
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))


def load(name):
    path = HERE / 'resource-tools/vampir' / (name + '.py')
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


class MessageComponentTests(unittest.TestCase):
    def test_current_named_components_preserve_buttons_but_not_text(self):
        report = load('verify-message-components').verify()
        self.assertEqual(len(report['components']), 4)
        self.assertEqual(sum(len(c['exports']) for c in report['components']), 86)
        changed = [x for c in report['components'] for x in c['exports'] if not x['unchanged']]
        self.assertEqual(len(changed), 9)
        self.assertTrue(all(x['type'] in ('NkTextBlock', 'NkRichTextBlock') for x in changed))
        self.assertTrue(all(x['unchanged'] for c in report['components'] for x in c['exports']
                            if x['name'] in ('ButtonOk', 'ButtonCancel')))
        self.assertFalse(report['network_used'])

    def test_header_change_and_truncated_export_are_rejected(self):
        tool = load('verify-message-components')
        import hashlib
        value = dict(asset_sha256=hashlib.sha256(b'header').hexdigest(),
            root_export=dict(name='root', type='Class', offset=6, size=2,
                             sha256=hashlib.sha256(b'ab').hexdigest()), controls=[])
        with self.assertRaisesRegex(ValueError, 'header changed'):
            tool.compare_exports(value, b'changed', b'ab')
        with self.assertRaisesRegex(ValueError, 'exceeds body'):
            tool.compare_exports(value, b'header', b'a')

    def test_current_numeric_pairs_and_localizations(self):
        report = load('verify-login-error-texts').verify()
        rows = {row['code']: row for row in report['errors']}
        self.assertEqual(rows[37]['key'], 'CreateRestrictedServer')
        self.assertEqual(rows[37]['ru'], 'Создание персонажа недоступно на этом сервере.')
        self.assertEqual(rows[16]['key'], 'InvalidState')
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])

    def test_missing_or_duplicate_translation_cannot_be_selected(self):
        tool = load('verify-login-error-texts')
        for rows in ([], [{'Key': 'key', 'Value': ''}], [{'Key': 'key', 'Value': 'a'}] * 2):
            with self.assertRaises(ValueError):
                tool.select_text(rows, 'key')

    def test_wrong_numeric_name_pair_is_rejected(self):
        tool = load('inspect-release-result-names')
        with self.assertRaisesRegex(ValueError, 'literal mismatch'):
            tool.run(source_sha256='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960',
                owner_address=0x1457d9210, values={37: 'BlockedIp'}, constructor=0x141426950)

    def test_runtime_label_does_not_turn_error_into_success(self):
        from vampir_core.game_login_error import describe_game_login_error
        self.assertEqual(describe_game_login_error(37),
            ('CreateRestrictedServer', 'Создание персонажа недоступно на этом сервере.'))
        self.assertIsNone(describe_game_login_error(123456))
