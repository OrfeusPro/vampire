import json
from pathlib import Path
import unittest
from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')


class VersionCombinerContextTests(unittest.TestCase):
    def context(self, name='version-combiner-11316.json'):
        return json.loads((HERE/'knowledge/native-contexts'/name).read_text('utf-8'))

    def test_whole_combiners_project_text_and_transfer_ownership(self):
        report=load('verify-version-combiner-context').verify(self.context(),ROOT)
        self.assertEqual(len(report['cases']),256)
        self.assertEqual(report['overflow_cases'],2)
        self.assertFalse(report['network_used'])
        self.assertTrue(any('resize' in c['events'] for c in report['cases']))
        self.assertTrue(any('allocator' in c['events'] for c in report['cases']))
        self.assertTrue(any(c['left_consumed'] for c in report['cases']))
        self.assertTrue(any(c['right_consumed'] for c in report['cases']))
        self.assertTrue(any(c['result']=='a\0bc\0d' for c in report['cases']))

    def test_whole_version_includes_actual_concatenation_and_system_helpers(self):
        report=load('verify-version-prepare-context').verify(self.context('version-prepare-combiner-11316.json'),ROOT)
        self.assertEqual(len(report['cases']),64)
        self.assertTrue(report['native_combiners_used'])
        self.assertTrue(report['native_system_used'])
        for c in report['cases']:
            self.assertEqual(c['strings'][1],('контекст' if c['context_present'] else '')+'_'+
                             ('' if c['empty'] else '10.0.26100.1.256.64bit'))
            self.assertEqual(c['native_combiner_calls']['first'],1)
            self.assertEqual(c['native_combiner_calls']['second'],1)
            self.assertEqual(c['native_combiner_calls']['append'],1+int(c['context_present']))
            self.assertTrue(c['guards'])
        self.assertFalse(report['profile_activated'])

    def test_corrupt_exports_or_changed_callee_are_rejected(self):
        context=self.context();context['exports']['run-ba23b5dcaf08']='0'*64
        with self.assertRaisesRegex(ValueError,'export SHA changed'):
            load('verify-version-combiner-context').verify(context,ROOT)
        context=self.context();context['call_sites'][next(iter(context['call_sites']))]='0x0'
        with self.assertRaisesRegex(ValueError,'Combiner call sites differ'):
            load('verify-version-combiner-context').verify(context,ROOT)
        context=self.context('version-prepare-combiner-11316.json')
        context['fixtures']['combine_first']='0x0'
        with self.assertRaisesRegex(ValueError,'Version combiner links differ'):
            load('verify-version-prepare-context').verify(context,ROOT)


if __name__=='__main__':unittest.main()
