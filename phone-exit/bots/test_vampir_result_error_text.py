import importlib.util
import json
import hashlib
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
        snapshot = tool.mapper.native.ROOT / 'client-code-snapshots' / report['source_sha256'] / 'ProjectRED-Win64-Shipping.exe'
        expected = dict(report, source=str(snapshot), tool_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            mapper_tool_sha256=hashlib.sha256((path.parent / 'replay-result-error-text.py').read_bytes()).hexdigest())
        self.assertEqual(tool.build(source_snapshot=snapshot), expected)
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
        snapshot = tool.native.ROOT / 'client-code-snapshots' / report['source_sha256'] / 'ProjectRED-Win64-Shipping.exe'
        expected = dict(report, source=str(snapshot), tool_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(tool.build(source_snapshot=snapshot), expected)
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
        self.assertEqual(describe_game_login_error(1), ('InvalidPacketVersion', 'Несовместимая версия игровых пакетов.'))
        self.assertEqual(describe_game_login_error(59), ('BlockedInfo', 'Доступ к игровому сервису ограничен сервером.'))
        for code in (0, 57, 12345, 0xffffffff): self.assertIsNone(describe_game_login_error(code))
        for invalid in (True, -1, 0x100000000, '58'):
            with self.assertRaises(ValueError): describe_game_login_error(invalid)
