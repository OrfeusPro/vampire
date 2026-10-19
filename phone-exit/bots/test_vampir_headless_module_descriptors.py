"""Module declarations are source evidence, not runtime module ordering."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

TOOL = Path(__file__).parent / 'resource-tools/vampir/recover-module-descriptors.py'
spec = importlib.util.spec_from_file_location('module_descriptors_test', TOOL)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ModuleDescriptorTests(unittest.TestCase):
    def test_verified_base_patch_descriptors_reproduce_snapshot(self):
        pointer = json.loads((module.core.ROOT / 'code-clues/module-descriptor-recovery.json').read_text('utf-8'))
        manifest = Path(pointer['manifest'])
        self.assertEqual(module.core.sha256(manifest), pointer['sha256'])
        report, files = module.recover()
        self.assertEqual(report, json.loads(manifest.read_text('utf-8')))
        self.assertEqual(module.core.sha256(TOOL), report['tool_sha256'])
        self.assertEqual(len(files), 4)
        for name, data in files.items():
            self.assertEqual(data, (manifest.parent / name).read_bytes())
        base, patch_archive = report['archives']
        for archive in (base, patch_archive):
            project, plugin = archive['entries']
            network = next(m for m in project['modules'] if m['declaration']['Name'] == 'NnNetwork')
            self.assertEqual(network['json_pointer'], '/Modules/4')
            self.assertEqual(network['declaration']['LoadingPhase'], 'Default')
            self.assertEqual(project['nkpatch_plugin'][0]['declaration'], {'Name': 'NkPatch', 'Enabled': True})
            self.assertEqual(project['nkpatch_plugin'][0]['json_pointer'], '/Plugins/23')
            self.assertEqual(plugin['modules'][0]['declaration'], {'Name': 'NkPatchRuntime', 'Type': 'Runtime', 'LoadingPhase': 'Default'})
        for left, right in zip(base['entries'], patch_archive['entries']):
            self.assertEqual(left['payload_sha256'], right['payload_sha256'])
        self.assertTrue(report['declared_loading_phases_only'])
        for flag in ('runtime_module_order_verified', 'config_precedence_verified', 'active_runtime_settings_verified', 'network_ready'):
            self.assertFalse(report[flag])

    def test_invalid_declaration_shapes_are_rejected(self):
        for obj in ([], {}, {'Modules': {}}, {'Modules': [None]}, {'Modules': [{'Name': 'N', 'Type': 'Runtime'}]}, {'Modules': [{}] * 129}):
            with self.assertRaises(ValueError):
                module.summarize(json.dumps(obj).encode())

    def test_snapshot_allowlist_and_immutability(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(module.core, 'ROOT', Path(temp)):
            files = {'base.ProjectRED.uproject': b'{}'}
            path, identity = module.save({'schema': 1}, files)
            self.assertEqual((path, identity), module.save({'schema': 1}, files))
            with self.assertRaisesRegex(ValueError, 'filename'):
                module.save({}, {'../escape': b'x'})
            (path.parent / 'base.ProjectRED.uproject').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'snapshot differs'):
                module.save({'schema': 1}, files)

    def test_changed_reference_stops_before_native_key_recovery(self):
        with patch.object(module.core, 'sha256', return_value='changed'), patch.object(module.core, 'load') as load:
            with self.assertRaisesRegex(ValueError, 'reference snapshot'):
                module.recover()
            load.assert_not_called()


if __name__ == '__main__':
    unittest.main()
