import importlib.util
from pathlib import Path
import unittest


class EmptyCharacterEntryTests(unittest.TestCase):
    def test_native_refusals_and_empty_list_have_separate_continuations(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-empty-character-entry.py'
        spec = importlib.util.spec_from_file_location('empty_entry_replay', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertEqual(len(report['empty_cases']), 16)
        self.assertEqual(len(report['refusal_cases']), 18)
        self.assertFalse(report['network_used'])
        self.assertTrue(report['native_execution'])
        for row in report['empty_cases']:
            self.assertEqual(row['state']['count'], 0)
            self.assertNotIn('selection_exit_capture', [event['action'] for event in row['events']])


if __name__ == '__main__':
    unittest.main()
