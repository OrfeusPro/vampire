"""Source-bound storage index and native directory join; no account files."""
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


class SdkStorageTests(unittest.TestCase):
    def test_storage_sources_reproduce_and_keys_are_distinct(self):
        tool = load('sdk_storage_test', 'build-headless-sdk-storage.py')
        report = json.loads((tool.source.config.native.ROOT / 'code-clues/headless-sdk-storage.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        bindings = {b['global_address']: [v['text'] for v in b['literals']] for b in report['bindings']}
        self.assertEqual(bindings[0x14b4f1408], ['NetmarbleSDK'])
        self.assertEqual(bindings[0x14b4f1a98], ['DeviceKeyForNetmarbleId'])
        rows = {i['address']: i for f in report['fragments'] for i in f['instructions']}
        self.assertEqual(rows[0x14452a5b9]['direct_target'], 0x14452c6e0)
        self.assertEqual(rows[0x144522d6a]['operands'], 'rdx, [rsi + 0x628]')
        self.assertEqual(rows[0x14452dfb9]['direct_target'], 0x14454b5c0)
        self.assertEqual(report['path_predicate']['bytes'], 'b001c3')
        self.assertFalse(report['native_execution'])
        self.assertFalse(report['user_storage_read'])

    def test_native_path_join_and_source_predicate(self):
        tool = load('sdk_storage_path_test', 'replay-sdk-storage-path.py')
        report = json.loads((tool.storage.source.config.native.ROOT / 'code-clues/sdk-storage-path-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        self.assertEqual(len(report['cases']), 6)
        expected = [
            'C:/fixture/Saved/PersistentDownloadDir/NetmarbleSDK',
            'C:/fixture/Saved/PersistentDownloadDir/NetmarbleSDK',
            'C:\\fixture\\Saved\\PersistentDownloadDir\\NetmarbleSDK',
            'C:/пример/Saved/PersistentDownloadDir/NetmarbleSDK',
            'NetmarbleSDK',
            'C:\\fixture\\Saved\\PersistentDownloadDir/NetmarbleSDK',
        ]
        self.assertEqual([c['directory'] for c in report['cases']], expected)
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['user_storage_read'])


if __name__ == '__main__':
    unittest.main()
