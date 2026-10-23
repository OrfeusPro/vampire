"""Source-bound queued terms forwarding; no network or account operations."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


class TermsDispatchTests(unittest.TestCase):
    def tool(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-terms-dispatch.py'
        spec = importlib.util.spec_from_file_location('terms_dispatch_test', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_whole_dispatch_and_thunk_keep_original_result(self):
        report = self.tool().replay()
        self.assertEqual(len(report['cases']), 96)
        no_data = [row for row in report['cases'] if row['state'] == 2 and row['result_code'] != 0]
        self.assertEqual(len(no_data), 8)
        self.assertTrue(any(row['forwarded'] for row in no_data))
        self.assertTrue(all(row['visible'] == 0 for row in no_data))
        self.assertEqual(report['method'], 'bounded_native')
        self.assertTrue(report['limits'])

    def test_corrupt_export_stops_before_replay(self):
        read = Path.read_bytes
        def corrupt(path):
            data = read(path)
            return data + b' ' if path.parent.name == 'run-61bf93179385' else data
        with patch.object(Path, 'read_bytes', corrupt):
            with self.assertRaisesRegex(ValueError, 'Dispatch export changed'):
                self.tool().replay()


if __name__ == '__main__': unittest.main()
