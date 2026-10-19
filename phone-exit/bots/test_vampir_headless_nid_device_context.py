"""Distinct NID web/OAuth device-key source, with native pair assembly."""
import importlib.util
import json
from pathlib import Path
import unittest


class NidDeviceContextTests(unittest.TestCase):
    def test_native_nid_pairs_reproduce_and_use_separate_getter(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-nid-device-context.py'
        spec = importlib.util.spec_from_file_location('nid_device_context_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        report = json.loads((tool.native.ROOT / 'code-clues/nid-device-context-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        self.assertEqual([c['key'] for c in report['cases']], ['deviceKey', 'device_key', 'device_key'])
        for case in report['cases']:
            self.assertEqual(case['value'], 'nid-device-fixture')
            self.assertEqual(case['events'], [dict(action='GetDeviceKeyForNetmarbleId_fixture', save_flag=True)])
        rows = {r['address']: r for f in report['fragments'] for r in f['instructions']}
        for address in (0x1450dea50, 0x1450e2c92, 0x1450e35f3):
            self.assertEqual(rows[address]['direct_target'], 0x144522b50)
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_ready'])


if __name__ == '__main__':
    unittest.main()
