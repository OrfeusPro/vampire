import importlib.util
from pathlib import Path
import unittest


class SignUpKeyTests(unittest.TestCase):
    def test_current_whole_initializers_bind_body_and_response_keys(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-sign-up-keys.py'
        spec = importlib.util.spec_from_file_location('sign_up_keys_test', path)
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 28)
        self.assertEqual({row['text'] for row in report['cases']},
            {'countryCode', 'credential', 'deviceKey', 'errorCode', 'nmDeviceKey', 'os', 'resultData'})
        for row in report['cases']:
            self.assertEqual([event['kind'] for event in row['events']], ['fstring_fixture', 'atexit_fixture'])


if __name__ == '__main__': unittest.main()
