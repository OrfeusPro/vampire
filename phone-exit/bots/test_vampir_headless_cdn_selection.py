"""CDN prefix substring rule must remain separate from SDK zone equality."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.sdk_config import select_cdn_config_base, select_game_sdk_zone


class CdnSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = HERE / 'resource-tools/vampir/build-headless-cdn-selection.py'
        spec = importlib.util.spec_from_file_location('cdn_selection_test_tool', cls.tool)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        cls.report = json.loads((root / 'code-clues/headless-cdn-selection.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()
        cls.image = cls.module.settings.config.native.Image(cls.raw)

    def test_source_and_fixture_provenance(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(self.tool.read_bytes()).hexdigest(), self.report['tool_sha256'])
        for fragment in self.report['fragments']:
            for row in fragment['instructions']:
                data = bytes.fromhex(row['bytes'])
                self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        for row in self.report['data_anchors']:
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(hashlib.sha256(data).hexdigest(), row['sha256'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        self.assertFalse(self.report['active_settings_proven'])
        self.assertFalse(self.report['network_ready'])

    def test_native_find_branch_and_shared_rule(self):
        self.assertEqual(len(self.report['cases']), 16)
        for case in self.report['cases']:
            actual = self.module.replay(self.raw, self.image, self.report['fragments'], case['prefix'])
            self.assertEqual(actual, case)
            selected = select_cdn_config_base(prefix=case['prefix'], normal='https://normal.invalid/config',
                                               qa='https://qa.invalid/config')
            self.assertEqual(selected, case['selected_fixture'])
            self.assertEqual(case['selected_length'], len(selected))
        emoji = next(c for c in self.report['cases'] if c['prefix'] == '😀real')
        self.assertEqual(emoji['find_index_utf16'], 2)

    def test_exact_sdk_zone_and_cdn_substring_are_distinct(self):
        self.assertEqual(select_game_sdk_zone('unreal'), 1)
        self.assertEqual(select_cdn_config_base(prefix='unreal', normal='normal', qa='qa'), 'normal')
        self.assertEqual(select_cdn_config_base(prefix='réal', normal='normal', qa='qa'), 'qa')
        self.assertEqual(select_cdn_config_base(prefix='', normal='', qa=''), '')
        # Values are copied as strings; this function does not validate URLs.
        self.assertEqual(select_cdn_config_base(prefix='real', normal='a?b#c', qa='qa'), 'a?b#c')

    def test_local_budgets_and_explicit_values(self):
        for key, values in [('prefix', [None, b'real', 'x' * 129, '😀' * 65, 'real\0']),
                            ('normal', [None, 'x' * 4097, '😀' * 2049, '\0']),
                            ('qa', [None, 'x' * 4097, '\0'])]:
            for value in values:
                args = dict(prefix='real', normal='normal', qa='qa')
                args[key] = value
                with self.subTest(key=key, type=type(value).__name__), self.assertRaises(ValueError):
                    select_cdn_config_base(**args)
        self.assertEqual(select_cdn_config_base(prefix='😀' * 64, normal='normal', qa='x' * 4096), 'x' * 4096)
        with self.assertRaises(TypeError):
            select_cdn_config_base(prefix='real', normal='normal')

    def test_game_config_file_name_static_initialization(self):
        literals = {l['instruction']: l['text'] for l in self.report['literals']}
        self.assertEqual(literals[0x14152ca91], 'Game')
        rows = {i['address']: i for f in self.report['fragments'] for i in f['instructions']}
        self.assertEqual(rows[0x1445bc0ad]['rip_references'], [0x14b2743f8])
        self.assertEqual(rows[0x14152caa4]['rip_references'], [0x14b2743f8])
        self.assertEqual(rows[0x14152cac4]['rip_references'], [0x14b2743f8])
        self.assertEqual(rows[0x1445bc24a]['direct_target'], 0x1445bb3a0)

    def test_fresh_public_archive_scan_provenance_and_scope(self):
        scan = self.report['public_scan']
        self.assertFalse(scan['full_config_search'])
        self.assertEqual(scan['counts'], dict(decoded=6912, encrypted_skipped=75, size_skipped=10, errors=0))
        self.assertEqual(scan['hits'], [])
        actual = self.module.scan_public_records(Path(scan['record_index']))
        self.assertEqual(actual, scan)


if __name__ == '__main__':
    unittest.main()
