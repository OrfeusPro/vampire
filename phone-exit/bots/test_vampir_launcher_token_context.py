import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'


def tool():
    spec = importlib.util.spec_from_file_location('launcher_token_context_test', HERE / 'replay-launcher-token-context.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LauncherTokenContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = tool()
        cls.report = cls.module.build()

    def test_source_bound_key_and_header_reproduce(self):
        path = self.module.ROOT / 'code-clues/launcher-token-context-replay.json'
        self.assertEqual(self.report, json.loads(path.read_text('utf-8')))
        for row in self.report['headers']:
            self.assertEqual(row['key'], 'launcherToken')
            self.assertEqual(row['header'], ['launcherToken', row['token_fixture']])
        self.assertFalse(self.report['network_used'])

    def test_launcher_channel_is_separate_from_credential_code(self):
        self.assertEqual(len(self.report['channels']), 10)
        for row in self.report['channels']:
            self.assertEqual(row['credential_channel_code'], 200)
            expected = row['credential_channel_68'] if row['credential_present'] else row['prior_module_channel']
            self.assertEqual(row['module_channel'], expected)
        self.assertEqual([row['target'] for row in self.report['callback_thunks']], ['0x1444c5910', '0x1444cce90'])
        self.assertEqual(self.report['callers']['unresolved'], [])
        self.assertEqual({row['root'] for row in self.report['callers']['calls']}, {'0x1444e5560', '0x1444fc5f0'})


if __name__ == '__main__':
    unittest.main()
