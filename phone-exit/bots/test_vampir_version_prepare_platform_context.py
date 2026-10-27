import json
from pathlib import Path
import unittest
from test_vampir_update_contracts import load,HERE

ROOT=Path('F:/PhoneExit Resources/Vampir')


class VersionPreparePlatformTests(unittest.TestCase):
    def test_11318_source_contexts(self):
        context=json.loads((HERE/'knowledge/native-contexts/version-prepare-platform-11318.json').read_text('utf-8'))
        report=load('verify-version-prepare-context').verify(context,ROOT)
        self.assertEqual(len(report['cases']),288)
        self.assertFalse(report['network_used']);self.assertFalse(report['profile_activated'])

    def context(self):
        return json.loads((HERE/'knowledge/native-contexts/version-prepare-platform-11316.json').read_text('utf-8'))

    def test_whole_chain_executes_platform_store_lookup_with_shared_memory(self):
        report=load('verify-version-prepare-context').verify(self.context(),ROOT)
        self.assertEqual(len(report['cases']),288)
        self.assertTrue(report['native_platform_used'])
        self.assertTrue(report['native_system_used'])
        self.assertTrue(report['native_combiners_used'])
        self.assertTrue(report['native_nm_used'])
        for c in report['cases']:
            scenario=c['platform_scenario']
            prefix=('Android' if scenario=='android-cold' else 'IOS' if scenario=='ios-cold' else 'Windows'
                    if scenario in ('windows-cached','windows-cold','windows-duplicate') else '')
            self.assertEqual(c['strings'][1],prefix+'_'+('' if c['empty'] else '10.0.26100.1.256.64bit'))
            self.assertEqual(c['native_platform_calls'],dict(selector=1,store=1,
                **({'lookup':1} if c['context_present'] else {})))
            if scenario in ('windows-missing','windows-negative-count','unknown-cold'):
                self.assertEqual(c['platform_index'],0xffffffff)
            if scenario=='windows-duplicate':self.assertEqual(c['platform_index'],0)
            self.assertTrue(c['guards'])
        self.assertFalse(report['network_used']);self.assertFalse(report['profile_activated'])

    def test_changed_callsite_or_binding_is_rejected(self):
        tool=load('verify-version-prepare-context')
        context=self.context();context['native_platform']['call_sites']['0x1416dd69f']='0x0'
        with self.assertRaisesRegex(ValueError,'platform call sites differ'):tool.verify(context,ROOT)
        context=self.context();context['fixtures']['context_store']='0x0'
        with self.assertRaisesRegex(ValueError,'platform helper links differ'):tool.verify(context,ROOT)

    def test_integration_needs_explicit_reviewed_budget_and_cannot_expand_further(self):
        tool=load('verify-version-prepare-context')
        for value in (None,20,32,True):
            context=self.context()
            if value is None:context.pop('function_budget')
            else:context['function_budget']=value
            with self.assertRaisesRegex(ValueError,'function/export budget exceeded'):tool.verify(context,ROOT)


if __name__=='__main__':unittest.main()
