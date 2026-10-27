import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load,HERE

ROOT=Path('F:/PhoneExit Resources/Vampir')


class VersionNmDeviceContextTests(unittest.TestCase):
    def test_11318_source_contexts(self):
        context=json.loads((HERE/'knowledge/native-contexts/version-nm-device-11318.json').read_text('utf-8'))
        report=load('verify-version-nm-device-context').verify(context,ROOT)
        self.assertEqual(len(report['cases']),36)
        self.assertFalse(report['network_used']);self.assertFalse(report['profile_activated'])
        context=json.loads((HERE/'knowledge/native-contexts/version-prepare-nm-11318.json').read_text('utf-8'))
        report=load('verify-version-prepare-context').verify(context,ROOT)
        self.assertEqual(len(report['cases']),64)
        self.assertFalse(report['network_used']);self.assertFalse(report['profile_activated'])

    def context(self,name='version-nm-device-11316.json'):
        return json.loads((HERE/'knowledge/native-contexts'/name).read_text('utf-8'))

    def test_getter_storage_and_repeat_cache(self):
        report=load('verify-version-nm-device-context').verify(self.context(),ROOT)
        self.assertEqual(len(report['cases']),36)
        self.assertFalse(report['user_identity_read'])
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])
        for case in report['cases']:
            self.assertTrue(case['guards'])
            self.assertTrue(case['repeated_cache_only'])
        cached=next(c for c in report['cases'] if c['profile']=='cached-space')
        self.assertEqual(cached['events'],[])
        self.assertEqual(cached['value'],' ')
        retained=next(c for c in report['cases'] if c['profile']=='read-failure-value')
        self.assertEqual(retained['events'],['read','parse'])
        self.assertEqual(retained['value'],'retained-fixture')
        write_failed=next(c for c in report['cases'] if c['profile']=='write-failure')
        self.assertEqual(write_failed['events'],['read','parse','generate','format','write'])

    def test_integrated_version_uses_native_nm_provider(self):
        report=load('verify-version-prepare-context').verify(self.context('version-prepare-nm-11316.json'),ROOT)
        self.assertTrue(report['native_nm_used'])
        self.assertEqual(len(report['cases']),64)
        self.assertTrue(all(c['native_nm_calls']==2 for c in report['cases']))
        self.assertTrue(all(c['strings'][3]=='nm-cache-Ж🙂' for c in report['cases']))
        self.assertFalse(report['network_used'])

    def test_corrupt_export_and_changed_getter_link_rejected(self):
        tool=load('verify-version-nm-device-context')
        context=self.context();context['exports']['run-09b30ec921d8']='0'*64
        with self.assertRaisesRegex(ValueError,'export SHA changed'):
            tool.verify(context,ROOT)
        context=self.context();context['call_sites'][next(iter(context['call_sites']))]='0x0'
        with self.assertRaisesRegex(ValueError,'call sites differ'):
            tool.verify(context,ROOT)
        context=self.context();context['source_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'source path differs'):
            tool.verify(context,ROOT)


if __name__=='__main__':
    unittest.main()
