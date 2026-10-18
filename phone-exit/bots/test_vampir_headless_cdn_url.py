"""Native CDN URL tail, separate from unknown fragment acquisition/conversion."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.sdk_config import assemble_cdn_config_url_ascii, select_cdn_config_base


class CdnUrlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = HERE / 'resource-tools/vampir/build-headless-cdn-url.py'
        spec = importlib.util.spec_from_file_location('cdn_url_test_tool', cls.tool)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        cls.report = json.loads((root / 'code-clues/headless-cdn-url.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()
        cls.image = cls.module.settings.config.native.Image(cls.raw)

    def test_provenance_and_filename_pointer(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(self.tool.read_bytes()).hexdigest(), self.report['tool_sha256'])
        for f in self.report['fragments']:
            for row in f['instructions']:
                data = bytes.fromhex(row['bytes'])
                self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        pointer = self.report['filename_pointer']
        data = bytes.fromhex(pointer['bytes'])
        self.assertEqual(self.raw[pointer['file_offset']:pointer['file_offset'] + 8], data)
        self.assertEqual(struct.unpack('<Q', data)[0], self.report['filename']['address'])
        self.assertEqual(self.report['filename']['text'], 'config.json')
        self.assertFalse(self.report['network_ready'])

    def test_native_assembly_replay_and_shared_code(self):
        self.assertEqual(len(self.report['cases']), 16)
        kinds = set()
        for case in self.report['cases']:
            args = {key: case[key] for key in ['base', 'platform', 'prefix', 'version_fragment']}
            actual = self.module.replay(self.raw, self.image, self.report['fragments'], **args,
                                        filename=case['filename'], spare=case['spare_capacity'])
            self.assertEqual(actual, case)
            self.assertEqual(assemble_cdn_config_url_ascii(**args), case['result'])
            kinds.update(call['kind'] for call in case['calls'])
        self.assertTrue({'allocate', 'free', 'memcpy', 'memmove'} <= kinds)

    def test_selection_to_assembly_preserves_literal_separators(self):
        base = select_cdn_config_base(prefix='unreal', normal='https://normal.invalid/', qa='https://qa.invalid/')
        result = assemble_cdn_config_url_ascii(base=base, platform='window', prefix='unreal', version_fragment='1_2')
        self.assertEqual(result, 'https://normal.invalid/window/unreal/1_2/config.json')
        self.assertEqual(assemble_cdn_config_url_ascii(base='base', platform='platform', prefix='', version_fragment=''),
                         'baseplatform///config.json')
        self.assertEqual(assemble_cdn_config_url_ascii(base='b/', platform='/p', prefix='/real/', version_fragment='/v/'),
                         'b//p//real///v//config.json')

    def test_ascii_policy_local_budget_and_no_implicit_preprocessing(self):
        args = dict(base='b/', platform='window', prefix='real', version_fragment='1.2.3')
        self.assertEqual(assemble_cdn_config_url_ascii(**args), 'b/window/real/1.2.3/config.json')
        for key in args:
            for value in [None, b'part', '\0', '\n', '\x7f', 'версия', 'é', 'x' * 4097]:
                bad = dict(args, **{key: value})
                with self.subTest(key=key, type=type(value).__name__), self.assertRaises(ValueError):
                    assemble_cdn_config_url_ascii(**bad)
        with self.assertRaises(ValueError):
            assemble_cdn_config_url_ascii(base='a' * 4096, platform='', prefix='', version_fragment='')
        result = assemble_cdn_config_url_ascii(base='a' * (4096 - len('///config.json')), platform='', prefix='', version_fragment='')
        self.assertEqual(len(result), 4096)


if __name__ == '__main__':
    unittest.main()
