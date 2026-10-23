"""Fetch first-game gate requires both fields; no live auth or terms."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


class ReleaseFetchResultTests(unittest.TestCase):
    def tool(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-fetch-result.py'
        spec = importlib.util.spec_from_file_location('release_fetch_test', path)
        value = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(value)
        return value

    def test_exact_gate_and_current_enums(self):
        report = self.tool().replay()
        self.assertEqual(len(report['cases']), 27)
        terms = [c for c in report['cases'] if any(e['kind'] == 'terms' for e in c['events'])]
        self.assertEqual([(c['success'], c['code'], c['context']) for c in terms], [(False, 30050027, 1203)])
        self.assertEqual(report['network_requests'], 0)
        successes = [c for c in report['cases'] if c.get('success')]
        self.assertEqual(len(successes), 12)
        self.assertTrue(all(c['events'][1]['channel'] == 33 and c['events'][1]['step'] == 15 for c in successes))
        self.assertEqual(len(report['enums']['ENetmarbleSDKStep']), 5)

    def test_changed_export_rejected(self):
        read = Path.read_bytes
        def changed(path):
            payload = read(path)
            return payload + b' ' if path.parent.name == 'run-313ff5f10ab1' else payload
        with patch.object(Path, 'read_bytes', changed):
            with self.assertRaisesRegex(ValueError, 'Fetch export changed'):
                self.tool().replay()


if __name__ == '__main__': unittest.main()
