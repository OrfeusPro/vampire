"""Real nonzero terms branch and game continuation with explicit offline fixtures."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


class IndividualTermsResponseTests(unittest.TestCase):
    def tool(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-individual-terms-response.py'
        spec = importlib.util.spec_from_file_location('individual_terms_response_test', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_error_layout_and_no_data_continuation(self):
        report = self.tool().replay()
        self.assertEqual(len(report['cases']), 40)
        self.assertEqual(report['network_requests'], 0)
        self.assertEqual(sum(row['sign_up_handoff'] for row in report['cases']), 4)
        for row in report['cases']:
            self.assertEqual(row['aggregate_code'], 30057209)
            self.assertEqual(row['context'], row['result_code'])
            self.assertEqual(row['ui_state'], 2 if row['result_code'] == -1 else 3)
            self.assertEqual(row['sign_up_handoff'], row['bound'] and row['result_code'] == -1)
        self.assertTrue(report['fixtures'])
        self.assertTrue(report['limits'])

    def test_changed_constructor_export_stops(self):
        read = Path.read_bytes
        def changed(path):
            data = read(path)
            return data + b' ' if path.parent.name == 'run-8c0479e8b8bd' else data
        with patch.object(Path, 'read_bytes', changed):
            with self.assertRaisesRegex(ValueError, 'Individual terms export changed'):
                self.tool().replay()


if __name__ == '__main__': unittest.main()
