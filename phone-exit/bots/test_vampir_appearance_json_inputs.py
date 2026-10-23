import importlib.util
from pathlib import Path
import unittest


class AppearanceJsonInputsTests(unittest.TestCase):
    def test_whole_helper_always_passes_voice_and_only_occupied_entries(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-appearance-json-inputs.py'
        spec = importlib.util.spec_from_file_location('appearance_input_replay', path)
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 12)
        for row in report['cases']:
            self.assertEqual([event['key'] for event in row['events'] if event['kind'] == 'entry'],
                ['fixture_' + str(index) for index in row['occupied']])
            self.assertEqual([event for event in row['events'] if event['kind'] == 'number'],
                [dict(kind='number', key='VoiceType', value=float(row['voice']))])
            self.assertEqual(row['events'][-1], dict(kind='serialize', raw_flag=1))


if __name__ == '__main__': unittest.main()
