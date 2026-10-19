"""Native SetDeviceKey comparisons and write-failure/getter integration evidence."""
import importlib.util
import json
from pathlib import Path
import unittest


class DeviceSetterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-device-key-setter.py'
        spec = importlib.util.spec_from_file_location('device_setter_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.lifecycle.guid.source.config.native.ROOT /
                                 'code-clues/device-key-setter-replay.json').read_text('utf-8'))

    def test_source_bound_report_reproduces(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertFalse(self.report['user_identity_read'])
        roots = {f['root_begin_rva'] for f in self.report['save_static_fragments']}
        self.assertTrue({0x453cdf0, 0x4520bd0} <= roots)

    def test_native_force_comparison_and_write_failure(self):
        self.assertEqual(len(self.report['cases']), 56)
        for case in self.report['cases']:
            fixture = case['fixture']
            writes = [e for e in case['events'] if e['action'] == 'stored_write_capture']
            should_write = fixture['platform'] == 3 and (
                fixture['force'] or fixture['value'].lower() != fixture['stored'].lower())
            self.assertEqual(len(writes), int(should_write), fixture)
            self.assertEqual(case['output'], fixture['value'])
            for event in writes:
                self.assertEqual(event['value'], fixture['value'])
                self.assertEqual(event['returned'], fixture['write_ok'])
                self.assertEqual(event['path'], ['store-fixture', 'game-fixture', 'DeviceKey'])
            self.assertEqual(sum(e['action'] == 'stored_read_fixture' for e in case['events']),
                             int(fixture['platform'] == 3))

    def test_native_getter_setter_integration(self):
        self.assertEqual(len(self.report['getter_integration']), 12)
        for case in self.report['getter_integration']:
            fixture = case['fixture']
            actions = [e['action'] for e in case['events']]
            from_store = fixture['platform'] == 3 and fixture['state'] == 'stored'
            generated = not from_store and fixture['state'] != 'settings'
            self.assertEqual('SetDeviceKey_native_entry' in actions, not from_store)
            self.assertNotIn('SetDeviceKey_capture', actions)
            self.assertEqual('stored_write_capture' in actions, fixture['platform'] == 3 and not from_store)
            self.assertEqual('Save_capture' in actions, generated and fixture['save_flag'])
            for event in case['events']:
                if event['action'] == 'SetDeviceKey_native_entry':
                    self.assertFalse(event['flag'])
                if event['action'] == 'stored_write_capture':
                    self.assertFalse(event['returned'])
            self.assertTrue(case['output'])


if __name__ == '__main__':
    unittest.main()
