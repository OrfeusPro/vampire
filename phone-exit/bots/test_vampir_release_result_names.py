import importlib.util
from pathlib import Path
import unittest


class CurrentResultNameTests(unittest.TestCase):
    def test_current_instruction_pairs_remain_separate(self):
        path = Path(__file__).parent / 'resource-tools/vampir/inspect-release-result-names.py'
        spec = importlib.util.spec_from_file_location('current_result_names', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertEqual({p['value']: p['name'] for p in report['pairs']},
            {0: 'Success', 58: 'BlockedIp', 59: 'BlockedInfo', 100: 'CharacterNotSelected'})
        self.assertEqual(report['source_sha256'], tool.SHA)


if __name__ == '__main__':
    unittest.main()
