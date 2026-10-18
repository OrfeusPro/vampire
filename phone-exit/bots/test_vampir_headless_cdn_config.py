"""CDN environment source evidence, without assuming live config or endpoints."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


class CdnConfigEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = HERE / 'resource-tools/vampir/build-headless-cdn-config.py'
        spec = importlib.util.spec_from_file_location('cdn_config_test_tool', cls.tool)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        cls.report = json.loads((root / 'code-clues/headless-cdn-config.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()
        cls.image = cls.module.settings.config.native.Image(cls.raw)
        cls.rows = {i['address']: i for f in cls.report['fragments'] for i in f['instructions']}

    def test_provenance_and_source_bytes(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(self.tool.read_bytes()).hexdigest(), self.report['tool_sha256'])
        for anchor in self.report['anchors']:
            data = bytes.fromhex(anchor['bytes'])
            self.assertEqual(hashlib.sha256(data).hexdigest(), anchor['sha256'])
            self.assertEqual(self.raw[anchor['file_offset']:anchor['file_offset'] + len(data)], data)
        for row in self.rows.values():
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        self.assertFalse(self.report['active_environment_proven'])
        self.assertFalse(self.report['network_ready'])

    def test_native_zone_field_flow_present_and_missing(self):
        self.assertEqual(len(self.report['cases']), 7)
        for case in self.report['cases']:
            actual = self.module.replay_zone_load(self.raw, self.image, case['zone_fixture'])
            self.assertEqual(actual, case)
            self.assertEqual(actual['lookups'], [dict(section='NetmarbleS', key='Zone')])
            self.assertFalse(actual['parser_executed'])
            if case['zone_fixture'] is None:
                self.assertTrue(actual['missing_branch'])
                self.assertEqual(actual['assignments'], [])
                self.assertEqual(actual['final_value'], 'unchanged')
            else:
                self.assertFalse(actual['missing_branch'])
                self.assertEqual(actual['final_value'], case['zone_fixture'])
                self.assertEqual(actual['assignments'], [dict(offset=0x48, value=case['zone_fixture'])])

    def test_static_callback_default_and_network_settings_anchors(self):
        literals = {l['instruction']: l['text'] for l in self.report['literals']}
        self.assertEqual(literals[0x145647dd7], 'dev')
        self.assertEqual(literals[0x14565a753], 'Zone')
        self.assertEqual(literals[0x14565a766], 'NetmarbleS')
        self.assertEqual(literals[0x144aa7025], 'CdnConfigUrl')
        self.assertEqual(literals[0x144aa7042], 'CdnConfigUrlQA')
        self.assertEqual(literals[0x144aa702c], 'NetworkSetting')
        self.assertEqual(literals[0x144aa70f0], 'ConfigPrefix')
        self.assertEqual(self.rows[0x145643110]['direct_target'], 0x14565a5d0)
        self.assertEqual(self.rows[0x14561898d]['direct_target'], 0x14561a930)
        self.assertEqual(self.rows[0x14565a790]['direct_target'], 0x14565f540)
        self.assertEqual(self.rows[0x14565a7a8]['operands'], 'rcx, [rbx + 0x48]')


if __name__ == '__main__':
    unittest.main()
