import importlib.util
from pathlib import Path
import unittest


class AppearanceJsonEntryTests(unittest.TestCase):
    def test_missing_definition_skips_and_found_uses_converted_key(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-appearance-json-entry.py'
        spec = importlib.util.spec_from_file_location('appearance_entry_replay', path)
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertEqual(len(report['cases']), 24)
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        for row in report['cases']:
            writes = [event for event in row['events'] if event['kind'] == 'json_number']
            self.assertEqual(len(writes), int(row['found']))
            if writes:
                self.assertEqual(writes[0]['key'], 'converted_fixture_key')
                if row['input_float_hex'] == '00000080':
                    self.assertEqual(writes[0]['value_hex'], '0000000000000080')


if __name__ == '__main__': unittest.main()
