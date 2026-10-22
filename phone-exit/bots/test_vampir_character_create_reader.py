import importlib.util
from pathlib import Path
import unittest


class CharacterCreateReaderTests(unittest.TestCase):
    def test_whole_current_reader_and_all_short_prefixes(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-character-create-reader.py'
        spec = importlib.util.spec_from_file_location('creation_reader_replay', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 36)
        self.assertGreater(len(report['short_prefixes']), 1000)
        self.assertTrue(all(row['accepted'] == 0 for row in report['short_prefixes']))
        self.assertEqual({row['raw_class'] for row in report['cases']}, {0, 0x12345678, 0xffffffff})
        self.assertEqual({row['name'] for row in report['cases']}, {'', 'NightRaven', 'Ж界🙂'})
        self.assertTrue(any(len(row['items']) == 2 for row in report['cases']))


if __name__ == '__main__': unittest.main()
