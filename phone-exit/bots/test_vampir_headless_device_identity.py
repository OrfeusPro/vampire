"""Source and native-format regression evidence without live device identity."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DeviceIdentityEvidenceTests(unittest.TestCase):
    def test_source_storage_bindings_and_imports(self):
        tool = load('device_source_test', 'build-headless-device-identity.py')
        report = json.loads((tool.config.native.ROOT / 'code-clues/headless-device-identity.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        raw = Path(report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), report['sha256'])
        names = {b['global_address']: [v['text'] for v in b['literals']] for b in report['bindings']}
        self.assertEqual(names[0x14b4f1030], ['Netmarble'])
        self.assertEqual(names[0x14b4f1040], ['NetmarbleSDK'])
        self.assertEqual(names[0x14b4f1070], ['NMDeviceKey'])
        self.assertEqual(names[0x14b4f1a88], ['DeviceKey'])
        self.assertEqual(report['guid_import']['name'], 'CoCreateGuid')
        imports = {i['name'] for i in report['named_imports']}
        self.assertTrue({'RegOpenKeyExW', 'RegQueryValueExW', 'RegSetValueExW'} <= imports)
        rows = {i['address']: i for f in report['fragments'] for i in f['instructions']}
        self.assertEqual(rows[0x144522a95]['direct_target'], 0x14453cdf0)
        self.assertEqual(rows[0x14452297b]['direct_target'], 0x141424870)
        for span in report['spans']:
            data = bytes.fromhex(span['bytes'])
            self.assertEqual(raw[span['file_offset']:span['file_offset'] + len(data)], data)
        self.assertFalse(report['native_execution'])
        self.assertFalse(report['user_identity_read'])

    def test_native_default_guid_formatter(self):
        tool = load('device_format_test', 'replay-device-guid-format.py')
        report = json.loads((tool.source.config.native.ROOT / 'code-clues/device-guid-format-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        self.assertEqual([c['formatted'] for c in report['cases']], [
            '0' * 32, 'F' * 32, '0123456789ABCDEFFEDCBA9876543210'])
        self.assertTrue(all(c['count'] == 33 for c in report['cases']))
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['user_identity_read'])


if __name__ == '__main__':
    unittest.main()
