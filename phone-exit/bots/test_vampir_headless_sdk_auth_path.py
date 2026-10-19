"""Native auth path gate, path join and persistent post-restore flag evidence."""
import importlib.util
import json
from pathlib import Path
import unittest


class SdkAuthPathTests(unittest.TestCase):
    def test_auth_path_source_and_native_cases(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-sdk-storage-auth-path.py'
        spec = importlib.util.spec_from_file_location('sdk_auth_path_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        report = json.loads((tool.native.ROOT / 'code-clues/sdk-storage-auth-path-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        self.assertEqual(len(report['cases']), 8)
        for case in report['cases']:
            fixture = case['fixture']
            accepts = fixture['context_ok'] and fixture['auth_type'].lower() == 'netmarble'
            self.assertEqual(case['gate_return'], accepts)
            self.assertEqual(case['post_restore_gate'], int(accepts or fixture['prior_post_restore_gate']))
            suffix = 'nid-profile-fixture/' if accepts else ''
            self.assertEqual(case['path'], 'C:/fixture/PersistentDownloadDir/NetmarbleSDK/' + suffix + 'ServiceSetting.bin')
            self.assertEqual(sum(e['action'] == 'auth_context_fixture' for e in case['events']), 1)
        texts = {v['text'] for v in report['literals']}
        self.assertTrue({'NMAUTH_TYPE=', 'NMAUTH_TOKEN=', 'AUTH_TYPE=', 'AUTH_TOKEN=', 'netmarble'} <= texts)
        self.assertTrue(any('SetupServiceSettingPath' in t for t in texts))
        rows = {r['address']: r for f in report['fragments'] for r in f['instructions']}
        self.assertIn(0x14b4f13fd, rows[0x14452aeea]['rip_references'])
        self.assertIn(0x14b4f1ee0, rows[0x14454cc7c]['rip_references'])
        self.assertEqual([r['rip_references'] for r in report['shared_state_references']], [[0x14b4f13fd]] * 3)
        self.assertFalse(report['user_storage_read'])


if __name__ == '__main__':
    unittest.main()
