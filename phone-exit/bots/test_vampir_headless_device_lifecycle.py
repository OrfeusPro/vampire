"""Verify native caller branch outcomes, explicitly excluding real storage."""
import importlib.util
import json
from pathlib import Path
import unittest


class DeviceLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-device-key-lifecycle.py'
        spec = importlib.util.spec_from_file_location('device_lifecycle_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.guid.source.config.native.ROOT /
                                 'code-clues/device-key-lifecycle-replay.json').read_text('utf-8'))

    def test_evidence_reproduces(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertFalse(self.report['user_identity_read'])

    def test_nm_cache_and_ignored_failure_returns(self):
        cases = {c['fixture']['name']: c for c in self.report['nm_cases']}
        self.assertEqual(len(cases), 8)
        self.assertEqual(cases['cached']['first_events'], [])
        self.assertEqual(cases['stored-original']['first'], 'original-case-fixture')
        self.assertEqual(cases['read-failure-value']['first'], 'retained-value-fixture')
        generated = '0123456789ABCDEFFEDCBA9876543210'
        for name in ('parse-failure', 'zero-guid', 'write-failure', 'read-failure'):
            self.assertEqual(cases[name]['first'], generated)
            writes = [e for e in cases[name]['first_events'] if e['action'] == 'stored_write_capture']
            self.assertEqual(len(writes), 1)
            self.assertEqual(writes[0]['path'], ['Netmarble', 'NetmarbleSDK', 'NMDeviceKey'])
        self.assertFalse([e for e in cases['write-failure']['first_events']
                          if e['action'] == 'stored_write_capture'][0]['returned'])
        self.assertEqual(cases['guid-failure']['first'], '0' * 32)
        for case in cases.values():
            self.assertEqual(case['first'], case['second'])
            self.assertEqual(case['second_events'], [])

    def test_device_source_precedence_and_save_gate(self):
        self.assertEqual(len(self.report['device_cases']), 12)
        for case in self.report['device_cases']:
            fixture = case['fixture']
            actions = [e['action'] for e in case['events']]
            from_store = fixture['platform'] == 3 and fixture['state'] == 'stored'
            generated = not from_store and fixture['state'] != 'settings'
            self.assertEqual('stored_read_fixture' in actions, fixture['platform'] == 3)
            self.assertEqual('CoCreateGuid_fixture' in actions, generated)
            self.assertEqual('SetDeviceKey_capture' in actions, not from_store)
            self.assertEqual('Save_capture' in actions, generated and fixture['save_flag'])
            expected = ('stored-device-fixture' if from_store else 'settings-device-fixture'
                        if fixture['state'] == 'settings' else '0123456789ABCDEFFEDCBA9876543210')
            self.assertEqual(case['output'], expected)
            for event in case['events']:
                if event['action'] == 'SetDeviceKey_capture':
                    self.assertFalse(event['flag'])
                if event['action'] == 'Save_capture':
                    self.assertFalse(event['returned'])


if __name__ == '__main__':
    unittest.main()
