"""Base/patch evidence must stay distinct until runtime precedence is proven."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

TOOL = Path(__file__).parent / 'resource-tools/vampir/recover-base-game-config.py'
spec = importlib.util.spec_from_file_location('base_config_test_tool', TOOL)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BaseConfigTests(unittest.TestCase):
    def test_recovery_reproduces_immutable_snapshot_and_layer_difference(self):
        pointer = json.loads((module.core.ROOT / 'code-clues/base-game-config-recovery.json').read_text('utf-8'))
        manifest = Path(pointer['manifest'])
        self.assertEqual(module.core.sha256(manifest), pointer['sha256'])
        report, files = module.recover()
        self.assertEqual(report, json.loads(manifest.read_text('utf-8')))
        self.assertEqual(module.core.sha256(TOOL), report['tool_sha256'])
        for name, data in files.items():
            self.assertEqual(data, (manifest.parent / name).read_bytes())
        directory = json.loads(files['directory.json'])
        self.assertEqual(directory['file_count'], 12425)
        self.assertEqual(directory['file_count'], report['main_metadata']['entry_count'])
        values = {v['key']: (v['base'], v['patch']) for v in report['patch_comparison'][0]['values']}
        self.assertEqual(values['AppVersion'], ('1.12.14', '0.1.1'))
        self.assertEqual(values['ConfigPrefix'], ('real', 'dev'))
        self.assertEqual(values['CdnConfig'], ('True', 'False'))
        windows = report['patch_comparison'][1]
        self.assertEqual(windows['base_sha256'], windows['patch_sha256'])
        self.assertEqual(windows['values'], [])
        self.assertTrue(report['authoritative_directory_for_archive'])
        for flag in ('config_precedence_verified', 'active_runtime_settings_verified', 'network_ready'):
            self.assertFalse(report[flag])

    def test_unexpected_archive_stops_before_native_dependency_load(self):
        original = module.core.sha256
        with patch.object(module.core, 'sha256', side_effect=lambda p: 'changed' if p == module.ARCHIVE else original(p)), \
                patch.object(module.core, 'load') as load:
            with self.assertRaisesRegex(ValueError, 'Base archive'):
                module.recover()
            load.assert_not_called()

    def test_modified_patch_reference_stops_before_archive_access(self):
        with patch.object(module.core, 'sha256', return_value='changed'), \
                patch.object(module.core, 'load') as load:
            with self.assertRaisesRegex(ValueError, 'Patch reference'):
                module.recover()
            load.assert_not_called()


if __name__ == '__main__':
    unittest.main()
