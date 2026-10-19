"""Native GMC2 URL assembly and portable explicit-fragment model."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.sdk_config import assemble_gmc2_config_url_ascii

TOOL = HERE / 'resource-tools/vampir/build-headless-gmc2-url.py'
spec = importlib.util.spec_from_file_location('gmc2_url_test', TOOL)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Gmc2UrlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads((module.values.native.ROOT / 'code-clues/headless-gmc2-url.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()

    def test_source_builder_and_native_append_provenance(self):
        r = self.report
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), r['sha256'])
        self.assertEqual(hashlib.sha256(TOOL.read_bytes()).hexdigest(), r['tool_sha256'])
        for fragment in r['fragments']:
            data = b''.join(bytes.fromhex(x['bytes']) for x in fragment['instructions'])
            self.assertEqual(hashlib.sha256(data).hexdigest(), fragment['sha256'])
            self.assertEqual(self.raw[fragment['file_offset']:fragment['file_offset'] + len(data)], data)
        rows = {x['address']: x for f in r['fragments'] for x in f['instructions']}
        self.assertEqual(rows[0x1444f3bb3]['direct_target'], module.values.VERSION)
        self.assertEqual(rows[0x1444f3c70]['direct_target'], module.values.BUILD)
        self.assertEqual(rows[0x1444f3b20]['direct_target'], module.APPEND)
        self.assertIn(module.APPEND, rows)

    def test_native_replay_and_common_assembly_for_all_fixtures(self):
        image = module.values.native.Image(self.raw)
        self.assertEqual(len(self.report['cases']), 26)
        for case in self.report['cases']:
            args = {key: case[key] for key in ('base', 'group', 'build_code', 'market')}
            replay = module.Emulator(self.raw, image, self.report['fragments']).assemble(**args)
            self.assertEqual(replay, case)
            self.assertEqual(assemble_gmc2_config_url_ascii(**args, sdk_version='5.2.11'), case['result'])
            self.assertFalse(case['network_used'])
        self.assertTrue(any(e['kind'] == 'builder_growth_shim' for e in self.report['cases'][-2]['calls']))
        self.assertTrue(self.report['cases'][8]['result'].startswith('https://config.invalid//template-groups/'))
        self.assertTrue(self.report['cases'][-1]['result'].endswith('market=a b&c=1'))
        self.assertFalse(self.report['active_values_verified'])
        self.assertFalse(self.report['network_ready'])

    def test_explicit_ascii_type_and_output_budgets(self):
        args = dict(base='https://config.invalid', group='netmarbles-v5', sdk_version='5.2.11', build_code=0, market='nmp')
        for key in ('base', 'group', 'sdk_version', 'market'):
            for value in (None, 1, 'a\0b', '\r\n', 'é', 'x' * 4097):
                with self.subTest(key=key, value_type=type(value).__name__), self.assertRaises(ValueError):
                    assemble_gmc2_config_url_ascii(**{**args, key: value})
        with self.assertRaises(ValueError):
            assemble_gmc2_config_url_ascii(**{**args, 'base': 'x' * 4096})
        with self.assertRaises(ValueError):
            assemble_gmc2_config_url_ascii(**{**args, 'build_code': True})

    def test_reproducible_report(self):
        self.assertEqual(module.build(), self.report)


if __name__ == '__main__':
    unittest.main()
