import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'


class LauncherChannelRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('launcher_routing_test', HERE / 'replay-launcher-channel-routing.py')
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = cls.tool.build()

    def test_source_bound_report_reproduces(self):
        path = self.tool.ROOT / 'code-clues/launcher-channel-routing-replay.json'
        self.assertEqual(self.report, json.loads(path.read_text('utf-8')))
        self.assertEqual(len(self.report['cases']), 26)
        self.assertFalse(self.report['network_used'])
        self.assertIn('FChannelManagerImpl::GetLauncherToken', self.report['diagnostic_literals'][1]['text'])

    def test_sign_in_and_token_are_separate_operations(self):
        for row in self.report['cases']:
            f, result = row['fixture'], row['result']
            if not f['service_present']:
                self.assertEqual(result['boundary'], 'before_error_allocation')
                continue
            if f['prior_channel'] == 100:
                continue
            if not f['credential_present']:
                expected = 'create_launcher_credential' if (f['operation'], f['channel']) == ('sign_in', 200) else 'before_error_allocation'
            elif f['operation'] == 'token':
                expected = 'launcher_token'
            elif f['channel'] == 200:
                expected = 'launcher_sign_in'
            else:
                expected = 'ordinary_sign_in'
            self.assertEqual(result['boundary'], expected)
            if expected in ('launcher_sign_in', 'launcher_token'):
                self.assertTrue(result['auth_matches'])
                self.assertTrue(result['credential_matches'])
            if expected == 'ordinary_sign_in':
                self.assertTrue(result['auth_wrapper_matches'])
                self.assertTrue(result['credential_matches'])
                self.assertEqual(result['player'], '')

    def test_previous_channel_100_requires_support_and_saved_player(self):
        rows = [r for r in self.report['cases'] if r['fixture']['prior_channel'] == 100]
        self.assertEqual(len(rows), 8)
        for row in rows:
            f, result = row['fixture'], row['result']
            if f['supported'] and f['saved_player']:
                self.assertEqual(result['boundary'], 'ordinary_sign_in')
                self.assertEqual(result['player'], f['saved_player'])
                self.assertTrue(result['credential_null'])
            else:
                self.assertEqual(result['boundary'], 'before_error_allocation')


if __name__ == '__main__':
    unittest.main()
