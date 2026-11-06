"""Current Clock/Ping proof reuse and fail-closed cached component boundaries."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent / 'resource-tools/vampir'


class CurrentClockWorldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('current_clock_world_fixture', HERE / 'run-clock-world-current.py')
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)

    def test_unchanged_package_reuses_without_native_replay(self):
        original = self.tool.load

        def load(name):
            if name.startswith('replay-'):
                self.fail('Unchanged package attempted native replay: ' + name)
            return original(name)

        with patch.object(self.tool, 'load', side_effect=load):
            _, report, reused = self.tool.run()
        self.assertTrue(reused)
        self.assertEqual((report['cases'], report['short_prefixes']), (297, 12))
        self.assertFalse(report['runtime_admitted'])
        self.assertFalse(report['network_used'])

    def fixture(self, root, *, runtime_admitted=False):
        t = self.tool
        workflow = t.load('research-workflow')
        components = {}
        for name, (_, count) in t.COMPONENTS.items():
            part = dict(source_sha256=t.SHA, cases=[{}] * count, network_used=False,
                        profile_activated=False, limits=['Explicit test fixture'])
            if name == 'clock':
                part['lobby_cases'] = []
            if name == 'result':
                part['short'] = [{}] * 12
            path = t.load('audit-client-release').save_snapshot(root / 'code-clues' / name, part)
            components[name] = dict(path=str(path), sha256=t.digest(path))
        report = dict(source_sha256=t.SHA, definition={'fixture': True}, components=components,
                      network_used=False, profile_activated=False, runtime_admitted=runtime_admitted)
        path = workflow.snapshot(root, 'clock-world-current-verified', report)
        return path, report

    def test_corrupted_component_is_rejected_before_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, report = self.fixture(root)
            component = Path(report['components']['producer']['path'])
            component.write_bytes(component.read_bytes() + b' ')
            with self.assertRaisesRegex(ValueError, 'component report changed'):
                self.tool.verify_report(path, self.tool.digest(path), report['definition'], root)

    def test_native_proof_cannot_promote_itself_to_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, report = self.fixture(root, runtime_admitted=True)
            with self.assertRaisesRegex(ValueError, 'composition changed'):
                self.tool.verify_report(path, self.tool.digest(path), report['definition'], root)

    def test_old_lobby_cases_cannot_be_counted_as_current_clock(self):
        component = dict(source_sha256=self.tool.SHA, network_used=False, profile_activated=False,
                         limits=['fixture'], cases=[{}] * 24, lobby_cases=[{'old_handler': True}])
        with self.assertRaisesRegex(ValueError, 'Old lobby handler'):
            self.tool.validate_component('clock', component)

    def test_missing_native_ping_short_case_is_rejected(self):
        component = dict(source_sha256=self.tool.SHA, network_used=False, profile_activated=False,
                         limits=['fixture'], cases=[{}] * 36, short=[{}] * 11)
        with self.assertRaisesRegex(ValueError, 'truncated coverage'):
            self.tool.validate_component('result', component)


if __name__ == '__main__':
    unittest.main()
