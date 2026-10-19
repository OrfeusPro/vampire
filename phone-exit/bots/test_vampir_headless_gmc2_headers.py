"""GMC2 native header gates and explicit offline request plan."""
from dataclasses import FrozenInstanceError
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.gmc2_request import plan_gmc2_get_request

TOOL = HERE / 'resource-tools/vampir/build-headless-gmc2-headers.py'
spec = importlib.util.spec_from_file_location('gmc2_headers_test', TOOL)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Gmc2HeaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads((module.url.values.native.ROOT / 'code-clues/headless-gmc2-headers.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()

    def test_source_constructor_names_and_conditional_offsets(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(TOOL.read_bytes()).hexdigest(), self.report['tool_sha256'])
        rows = {x['address']: x for f in self.report['fragments'] for x in f['instructions']}
        for fragment in self.report['fragments']:
            data = b''.join(bytes.fromhex(x['bytes']) for x in fragment['instructions'])
            self.assertEqual(hashlib.sha256(data).hexdigest(), fragment['sha256'])
            self.assertEqual(self.raw[fragment['file_offset']:fragment['file_offset'] + len(data)], data)
        self.assertEqual(rows[0x1444f56c7]['operands'], 'dword ptr [r12 + 8], 1')
        self.assertEqual(rows[0x1444f5708]['operands'], 'dword ptr [rdi + 0x80], 1')
        self.assertEqual(rows[0x1444f56a8]['direct_target'], module.DEVICE)
        self.assertEqual(rows[0x1444f5745]['direct_target'], module.PLAYER)

    def test_native_captures_match_common_header_plan(self):
        image = module.url.values.native.Image(self.raw)
        self.assertEqual(len(self.report['cases']), 16)
        for case in self.report['cases']:
            replay = module.Emulator(self.raw, image, self.report['fragments']).capture(case['fixture'])
            self.assertEqual(replay, case)
            plan = plan_gmc2_get_request(**case['fixture'])
            self.assertEqual(plan.url, case['request']['url'])
            self.assertEqual(plan.method, case['request']['method'])
            self.assertEqual(list(plan.headers), [(h['name'], h['value']) for h in case['headers']])
            self.assertNotIn('token-fixture', repr(plan))
            self.assertNotIn('device-fixture', repr(plan))
            self.assertFalse(case['network_used'])
        self.assertFalse(self.report['active_values_verified'])
        self.assertFalse(self.report['network_ready'])

    def test_local_input_policy_and_secret_safe_errors(self):
        args = dict(self.report['cases'][0]['fixture'])
        for key in ('service_code', 'game_code', 'device_key', 'etag', 'player_id', 'access_token'):
            for value in (None, True, 'secret\r\nX: attack', 'secret\0', 'секрет', 'x' * 4097):
                with self.subTest(key=key, kind=type(value).__name__), self.assertRaises(ValueError) as error:
                    plan_gmc2_get_request(**{**args, key: value})
                self.assertNotIn('secret', str(error.exception))
        for url in ('http://config.invalid', 'https://user:secret@config.invalid/', 'https://config.invalid/#fragment',
                    'https://config.invalid:0/', 'https://config.invalid:65536/', 'https:///empty'):
            with self.assertRaises(ValueError):
                plan_gmc2_get_request(**{**args, 'url': url})
        plan = plan_gmc2_get_request(**{**args, 'player_id': 'player-without-token'})
        self.assertNotIn('playerId', dict(plan.headers))
        with self.assertRaises(FrozenInstanceError):
            plan.url = 'changed'

    def test_reproducible_report(self):
        self.assertEqual(module.build(), self.report)


if __name__ == '__main__':
    unittest.main()
