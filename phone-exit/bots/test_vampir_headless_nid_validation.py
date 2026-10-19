"""Native OnResult gates with explicit integer/channel/map return fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent


class NidValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = HERE / 'resource-tools/vampir/replay-nid-result-validation.py'
        spec = importlib.util.spec_from_file_location('nid_validation_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.bootstrap.native.ROOT / 'code-clues/nid-result-validation-replay.json').read_text('utf-8'))
        cls.cases = {c['name']: c for c in cls.report['cases']}

    def test_replay_rebuilds_from_pinned_compiled_bytes(self):
        self.assertEqual(self.tool.build(), self.report)
        raw = Path(self.report['source']).read_bytes()
        for f in self.report['fragments'] + self.report['settings_fragments_static']:
            for row in f['instructions']:
                data = bytes.fromhex(row['bytes'])
                offset = row['file_offset']
                self.assertEqual(raw[offset:offset + len(data)], data)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), self.report['sha256'])
        self.assertFalse(self.report['network_ready'])

    def test_adoption_captures_keep_access_refresh_id_and_country_distinct(self):
        case = self.cases['complete']
        self.assertEqual(case['outcome'], 'adoption_calls_reached')
        captures = {e['target']: e['value'] for e in case['events'] if e['kind'] == 'settings_call_capture'}
        self.assertEqual(captures, {0x14454a480: 'access-fixture', 0x14454ba20: 'user-fixture',
                                    0x14454c470: 'refresh-fixture'})
        self.assertIn({'kind': 'country_assignment_capture', 'value': 'UA'}, case['events'])
        self.assertIn({'kind': 'channel_settings_capture', 'value': 20}, case['events'])
        diagnostics = [row['text'] for row in self.report['settings_diagnostics']]
        for method in ('SetAccessTokenForNetmarbleId', 'SetNetmarbleId', 'SetChannelTypeForNetmarbleId',
                       'SetSilentlySignInTokenForNetmarbleId'):
            self.assertTrue(any(method in text for text in diagnostics), method)

    def test_absent_fields_are_distinct_from_empty_values(self):
        self.assertEqual(self.cases['missing_resultCode']['outcome'], 'missing_resultCode')
        self.assertEqual(self.cases['empty_resultCode']['outcome'], 'empty_resultCode')
        for key in ('accessToken', 'refreshToken', 'channelKey', 'netmarbleId', 'joinedCountryCode'):
            missing = self.cases['missing_' + key]
            self.assertEqual(missing['outcome'], 'unmapped_null_access')
            faults = [e for e in missing['events'] if e['kind'] == 'unmapped_null_access']
            self.assertEqual(len(faults), 1)
            self.assertEqual(faults[0]['address'], 24)
            empty = self.cases['empty_' + key]
            self.assertEqual(empty['outcome'], 'adoption_calls_reached' if key == 'refreshToken' else 'empty_' + key)
        refresh = self.cases['empty_refreshToken']
        self.assertIn({'kind': 'settings_call_capture', 'target': 0x14454c470, 'value': '', 'r8': 1}, refresh['events'])

    def test_native_caller_checks_parser_channel_and_auth_mode_results(self):
        self.assertEqual(len(self.cases), 22)
        for name in ('parse_failure', 'nonzero_result'):
            self.assertEqual(self.cases[name]['outcome'], 'invalid_or_nonzero_result')
        self.assertEqual(self.cases['unknown_channel']['outcome'], 'unknown_channel')
        for value in (1, 2, 4, 5, 6, 255):
            expected = 'adoption_calls_reached' if value in (1, 4, 5) else 'auth_type_gate'
            self.assertEqual(self.cases['auth_type_' + str(value)]['outcome'], expected)
        # Numeric spelling and channel enum are not established by these return fixtures.
        self.assertTrue(any('not accepted number syntax' in s for s in self.report['limitations']))


if __name__ == '__main__':
    unittest.main()
