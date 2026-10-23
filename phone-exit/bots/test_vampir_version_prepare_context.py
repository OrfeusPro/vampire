import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT=Path('F:/PhoneExit Resources/Vampir')
CONTEXT=HERE/'knowledge/native-contexts/version-prepare-11316.json'


class VersionPrepareContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_whole_prepare_projection_and_cleanup(self):
        report=load('verify-version-prepare-context').verify(self.context(),ROOT)
        self.assertEqual(len(report['cases']),64)
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])
        self.assertTrue(all(c['guards'] for c in report['cases']))
        self.assertEqual({c['context_present'] for c in report['cases']},{False,True})
        self.assertEqual({c['send_return'] for c in report['cases']},{0,1})
        for case in report['cases']:
            self.assertEqual(case['integers'],[0,207,case['raw_enum']])
            self.assertEqual(case['strings'][5:9],['']*4)
            self.assertEqual(case['strings'][9],'32283C4C6485307BCF524765A84409C3')
            self.assertEqual(case['strings'][4],'' if case['empty'] else 'input-🙂')

    def test_corrupt_source_and_exports_rejected(self):
        tool=load('verify-version-prepare-context')
        context=self.context()
        context['source_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'source path differs'):
            tool.verify(context,ROOT)
        context=self.context()
        context['exports']['run-571e3ba7330a']='0'*64
        with self.assertRaisesRegex(ValueError,'export SHA changed'):
            tool.verify(context,ROOT)

    def test_changed_callee_or_send_slot_rejected(self):
        tool=load('verify-version-prepare-context')
        context=self.context()
        context['call_sites'][next(iter(context['call_sites']))]['target']='0x141403b71'
        with self.assertRaisesRegex(ValueError,'call sites differ'):
            tool.verify(context,ROOT)
        context=self.context()
        context['send']='0x1467cf3e1'
        with self.assertRaisesRegex(ValueError,'wrapper table links differ'):
            tool.verify(context,ROOT)


if __name__=='__main__':
    unittest.main()
