"""Local map data publishing and view projection; never starts an owner or game IO."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
TOOL = HERE / 'resource-tools/vampir/ui_local_map_projection.py'
ROOT = Path('F:/PhoneExit Resources/Vampir')
spec = importlib.util.spec_from_file_location('local_atlas_projection_test',TOOL)
module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class LocalAtlasProjection11318Tests(unittest.TestCase):
    def test_actual_unchanged_pak_data_publishes_local_scope_without_native_claim(self):
        value,inputs=module.prepare(ROOT)
        self.assertEqual(value['worlds']['10012'],'10')
        self.assertEqual(value['size'],[10240,10240])
        self.assertEqual(value['center'],[0,0])
        self.assertEqual(value['ground_distance'],615000)
        self.assertTrue(value['archive_data_verified'])
        self.assertFalse(value['current_native_widget_math_verified'])
        self.assertEqual(value['client_context_sha256'],module.CLIENT_SHA)
        self.assertEqual(value['data_evidence']['sha256'],module.AUDIT_SHA)
        self.assertEqual({k:v['sha256'] for k,v in value['data_evidence']['tables'].items()},module.TABLES)
        self.assertIn('maps/atlas/projection.json',inputs)
        self.assertIn('maps/nocturne-world.json',inputs)

    def test_changed_archive_stops_before_publishing_metadata(self):
        real=module.sha
        def changed(path):
            return '0'*64 if Path(path).suffix=='.pak' else real(path)
        with patch.object(module,'sha',side_effect=changed),self.assertRaisesRegex(ValueError,'PAK'):
            module.prepare(ROOT)

    def test_mutated_immutable_data_evidence_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/module.AUDIT;path.parent.mkdir(parents=True)
            path.write_bytes((ROOT/module.AUDIT).read_bytes()+b' ')
            with self.assertRaisesRegex(ValueError,'источник локального атласа'):
                module.prepare(Path(directory))

    def test_shared_view_and_existing_map_viewport_invariants(self):
        for name in ('local-map-projection.test.cjs','prototype-live-model.test.cjs','map-bridge.test.cjs'):
            with self.subTest(name=name):
                result=subprocess.run(['node',str(HERE/'vampir/ui-prototype'/name)],capture_output=True,
                    text=True,encoding='utf-8',timeout=30)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)


if __name__=='__main__':unittest.main()
