"""SDK version and BuildCode provenance/native branch replay/portable mapping."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.sdk_config import select_sdk_build_code

TOOL = HERE / 'resource-tools/vampir/build-headless-sdk-bootstrap-values.py'
spec = importlib.util.spec_from_file_location('bootstrap_values_test', TOOL)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BootstrapValuesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads((module.native.ROOT / 'code-clues/headless-sdk-bootstrap-values.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()

    def test_source_and_callsite_settings_offsets(self):
        r = self.report
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), r['sha256'])
        self.assertEqual(hashlib.sha256(TOOL.read_bytes()).hexdigest(), r['tool_sha256'])
        for row in r['literals'] + [x for f in r['fragments'] for x in f['instructions']]:
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        rows = {x['address']: x for f in r['fragments'] for x in f['instructions']}
        self.assertEqual(rows[0x1444f3bb3]['direct_target'], module.VERSION)
        self.assertEqual(rows[0x1444f3c70]['direct_target'], module.BUILD)
        self.assertEqual(rows[0x1444f5675]['direct_target'], module.BUILD)
        self.assertEqual(rows[0x1444f3c6c]['operands'], 'edx, byte ptr [rdx + 0x48]')
        self.assertEqual(rows[0x1444f5671]['operands'], 'edx, byte ptr [rdx + 0x48]')

    def test_native_initializers_and_all_byte_getters(self):
        replay = module.replay(self.raw, module.native.Image(self.raw), self.report['fragments'])
        self.assertEqual(replay, self.report['replay'])
        self.assertEqual(replay['sdk_version'], '5.2.11')
        self.assertEqual([x['value'] for x in replay['initialized_globals']], ['A', 'B', 'C'])
        self.assertEqual(len(replay['cases']), 256)
        for case in replay['cases']:
            self.assertEqual(select_sdk_build_code(case['build_code']), case['value'])
            self.assertTrue(case['guards_unchanged'])
        self.assertFalse(self.report['active_build_code_verified'])
        self.assertFalse(self.report['network_ready'])

    def test_invalid_explicit_build_code_inputs(self):
        for value in (-1, 256, 1.0, True, False, None, '0', 'real'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                select_sdk_build_code(value)
        self.assertEqual(select_sdk_build_code(0), 'A')
        self.assertEqual(select_sdk_build_code(1), 'B')
        self.assertEqual(select_sdk_build_code(2), 'C')
        self.assertEqual(select_sdk_build_code(255), 'A')

    def test_reproducible_report_and_changed_source_rejection(self):
        self.assertEqual(module.build(), self.report)
        source, original = Path(self.report['source']), Path.read_bytes
        with patch.object(Path, 'read_bytes', lambda p: b'changed' if p == source else original(p)), \
                patch.object(module.native, 'Image') as image:
            with self.assertRaisesRegex(ValueError, 'source changed'):
                module.build()
            image.assert_not_called()


if __name__ == '__main__':
    unittest.main()
