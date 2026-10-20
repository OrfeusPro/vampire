import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.game_login_error import describe_game_login_error


class ResultErrorTextTests(unittest.TestCase):
    def test_new_result16_mapper_and_localization_reproduce(self):
        path = HERE / 'resource-tools/vampir/replay-result-error-16.py'
        spec = importlib.util.spec_from_file_location('test_result16_error_text', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        report = json.loads((tool.mapper.native.ROOT / 'code-clues/result-error-16-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        cases = {c['code']: c for c in report['cases']}
        self.assertEqual(cases[16]['key'], 'InvalidState')
        self.assertEqual(cases[58]['key'], 'BlockedIp')
        self.assertEqual(report['localization']['row']['Key'], 'InvalidState')
        self.assertEqual(report['localization']['row']['Value'], 'Invalid state')

    def test_native_mapper_and_extracted_localization_reproduce(self):
        path = HERE / 'resource-tools/vampir/replay-result-error-text.py'
        spec = importlib.util.spec_from_file_location('test_result_error_text', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        report = json.loads((tool.native.ROOT / 'code-clues/result-error-text-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        cases = {case['code']: case for case in report['cases']}
        self.assertEqual(cases[58]['key'], 'BlockedIp')
        self.assertEqual(cases[57]['key'], 'NotExistCharacter')
        self.assertEqual(cases[59]['key'], 'BlockedInfo')
        self.assertEqual(cases[58]['literal']['address'], 0x1498ff2b0)
        self.assertEqual(report['localization']['row']['Key'], 'BlockedIp')
        self.assertIn('Access from this IP is restricted.', report['localization']['row']['Value'])

    def test_runtime_labels_only_verified_code_and_never_decides_remedy(self):
        self.assertEqual(describe_game_login_error(58), ('BlockedIp', 'Доступ с этого IP ограничен сервером.'))
        self.assertEqual(describe_game_login_error(16), ('InvalidState', 'Недопустимое состояние при входе.'))
        for code in (0, 1, 57, 59, 12345, 0xffffffff): self.assertIsNone(describe_game_login_error(code))
        for invalid in (True, -1, 0x100000000, '58'):
            with self.assertRaises(ValueError): describe_game_login_error(invalid)
