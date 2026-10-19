"""Native Load device field mapping and source-bound constructor filename defaults."""
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


class SdkLoadDevicesTests(unittest.TestCase):
    def test_load_restoration_and_post_restore_dispatch(self):
        tool = load('sdk_load_devices_test', 'replay-sdk-load-device-fields.py')
        report = json.loads((tool.native.ROOT / 'code-clues/sdk-load-device-fields-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        self.assertEqual(len(report['cases']), 16)
        for case in report['cases']:
            fixture = case['fixture']
            self.assertEqual(case['sdk_key'], fixture['sdk_key'])
            self.assertEqual(case['nid_key'], fixture['nid_key'])
            actions = [e['action'] for e in case['events']]
            if not fixture['post_restore_gate']:
                self.assertEqual(actions, [])
            elif fixture['saved_tag'] == 0xc41f:
                self.assertEqual(actions, ['SetDeviceKey_capture', 'SetDeviceKeyForNetmarbleId_capture', 'Save_capture'])
                self.assertFalse(case['events'][0]['flag'])
                self.assertFalse(case['events'][1]['flag'])
                self.assertFalse(case['events'][2]['returned'])
            else:
                self.assertEqual(actions, ['GetDeviceKey_capture', 'GetDeviceKeyForNetmarbleId_capture'])
                self.assertTrue(all(e['save_flag'] for e in case['events']))
        self.assertFalse(report['user_storage_read'])

    def test_filename_defaults_are_distinct_and_joined_by_load(self):
        tool = load('sdk_filename_test', 'replay-sdk-storage-filename.py')
        report = json.loads((tool.native.ROOT / 'code-clues/sdk-storage-filename-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        self.assertEqual(len(report['cases']), 3)
        for case in report['cases']:
            self.assertEqual(case['defaults'], dict(field_2e8='ServiceSettings.bin', field_2f8='ServiceSetting.bin'))
            prefix = case['persistent_directory'].rstrip('/')
            expected = (prefix + '/' if prefix else '') + 'NetmarbleSDK/ServiceSetting.bin'
            self.assertEqual(case['load_filename'], expected)
        rows = {r['address']: r for f in report['fragments'] for r in f['instructions']}
        self.assertIn(0x1444ac6c0, rows[0x1444aad10]['rip_references'])
        self.assertFalse(report['user_storage_read'])


if __name__ == '__main__':
    unittest.main()
