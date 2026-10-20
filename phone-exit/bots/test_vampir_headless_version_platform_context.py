import importlib.util
import json
from pathlib import Path
import unittest


class PlatformContextTests(unittest.TestCase):
    def test_descriptor_and_native_selector_lookup_reproduce_scoped_variants(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-version-platform-context.py'
        spec = importlib.util.spec_from_file_location('platform_context_native_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        report = tool.build()
        self.assertEqual(report, json.loads((tool.native.ROOT / 'code-clues/version-platform-context-replay.json').read_text('utf-8')))
        self.assertEqual(report['record']['name'], 'ENnOsType')
        self.assertEqual(report['record']['count'], 5)
        members = {row['value']: row['name'] for row in report['members']}
        self.assertEqual(members[3], 'ENnOsType::Windows')
        self.assertEqual(len(report['cases']), 12)
        for case in report['cases']:
            self.assertEqual(case['selector'], 3)
            expected = members.get(case['key'], '')
            if case['scoped_fixture']: expected = expected.split('::')[-1]
            self.assertEqual(case['output'], expected)


if __name__ == '__main__': unittest.main()
