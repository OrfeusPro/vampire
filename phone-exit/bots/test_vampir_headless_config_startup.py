"""Validate native callback timing without claiming a full game startup."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

TOOL = Path(__file__).parent / 'resource-tools/vampir/build-headless-config-startup.py'
spec = importlib.util.spec_from_file_location('config_startup_test', TOOL)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ConfigStartupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report_path = module.native.ROOT / 'code-clues/headless-config-startup.json'
        cls.report = json.loads(cls.report_path.read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()

    def test_source_bytes_and_owner_callback_edges(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(TOOL.read_bytes()).hexdigest(), self.report['tool_sha256'])
        rows = self.report['anchors'] + [r for f in self.report['fragments'] for r in f['instructions']]
        rows.append(self.report['callback_name'])
        for row in rows:
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        instructions = {r['address']: r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(self.report['callback_name']['text'], 'FNnNetworkVar')
        self.assertEqual(instructions[0x144aa4886]['direct_target'], 0x144aa6e70)
        self.assertEqual(instructions[0x144aa6ecc]['direct_target'], 0x1445cd6c0)
        self.assertEqual(instructions[0x144aa6ea0]['rip_references'], [module.THUNK])
        self.assertEqual(instructions[0x144aa5828]['rip_references'], [0x14961a318])

    def test_native_order_and_context_replay(self):
        image = module.native.Image(self.raw)
        self.assertEqual(len(self.report['cases']), 8)
        for case in self.report['cases']:
            replay = module.replay(self.raw, image, self.report['fragments'], case['context_storage'] == 'external', case['marker'])
            self.assertEqual(replay, case)
            self.assertEqual([event['kind'] for event in case['events']], ['loader_capture', 'registry_insert_capture'])
            self.assertEqual(case['events'][0]['marker'], case['marker'])
            self.assertFalse(case['full_loader_executed'])
        self.assertTrue(self.report['callback_invoked_before_registry_insert'])
        for flag in ('config_precedence_verified', 'active_runtime_settings_verified', 'network_ready'):
            self.assertFalse(self.report[flag])

    def test_reproducible_report(self):
        self.assertEqual(module.build(), self.report)

    def test_changed_executable_rejected_before_analysis(self):
        original = Path.read_bytes
        source = Path(self.report['source'])
        with patch.object(Path, 'read_bytes', lambda p: b'changed' if p == source else original(p)), \
                patch.object(module.native, 'Image') as image:
            with self.assertRaisesRegex(ValueError, 'source changed'):
                module.build()
            image.assert_not_called()


if __name__ == '__main__':
    unittest.main()
