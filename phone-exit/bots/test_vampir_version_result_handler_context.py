import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/version-result-handler-11316.json'


class VersionResultHandlerContextTests(unittest.TestCase):
    def test_11318_native_reader_handler_and_all_switch_indices(self):
        context=json.loads((HERE/'knowledge/native-contexts/version-result-handler-11318.json').read_text('utf-8'))
        report=load('verify-version-result-handler-context').verify(context,ROOT)
        self.assertEqual(len(report['cases']),16);self.assertEqual(len(report['input_cases']),16)
        self.assertEqual(len(report['input_construction_cases']),72)
        self.assertEqual(len(report['switch_cases']),227)
        self.assertEqual({r['index'] for r in report['switch_cases']},{0,1,2,3})
        for case in report['cases']:
            allowed=case['code']==0 or (case['code']==0x1197 and case['state_flag']==0)
            self.assertEqual('login_prepare' in case['events'],allowed)
        special=next(c for c in report['cases'] if c['code']==0x1197 and c['state_flag']==0)
        self.assertEqual(special['events'],['gate','error','peer','login_prepare'])
        self.assertFalse(report['network_used']);self.assertFalse(report['profile_activated'])

    def test_11318_registration_and_source_isolation(self):
        context=json.loads((HERE/'knowledge/native-contexts/version-result-handler-11318.json').read_text('utf-8'))
        tool=load('verify-version-result-handler-context')
        context['handler_table']='0x149dc8028'
        with self.assertRaisesRegex(ValueError,'handler registration link'):tool.verify(context,ROOT)
        context['native_result']['source_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'pipeline source'):tool.verify(context,ROOT)

    def test_11318_switch_tables_and_missing_export_instruction_are_rejected(self):
        from types import SimpleNamespace
        switch=load('version-gate-switch-11318');native=load('build-native-entry-code')
        source=ROOT/'client-code-snapshots'/switch.SHA/'ProjectRED-Win64-Shipping.exe'
        raw=source.read_bytes();image=native.Image(raw)
        export=json.loads((ROOT/'ghidra/request-exports'/switch.SHA/'run-450b89173dc1/details.json').read_text('utf-8'))
        h=SimpleNamespace(sha=switch.SHA,image=image,raw=raw,fragments=export['functions'])
        self.assertEqual(switch.validate(native,h)['code_instructions'],251)
        for address,reason in ((switch.TABLE,'RVA table'),(switch.INDEX,'index table')):
            changed=bytearray(raw);off=image.offset(address-image.pe.base);changed[off]^=1;h.raw=changed
            with self.assertRaisesRegex(ValueError,reason):switch.validate(native,h)
        h.raw=raw
        next(f for f in h.fragments if f['address']=='0x1467cdc80')['instructions'].pop()
        with self.assertRaisesRegex(ValueError,'code/data separation'):switch.validate(native,h)

    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_native_gate_and_login_handoff(self):
        report = load('verify-version-result-handler-context').verify(self.context(), ROOT)
        self.assertEqual(len(report['cases']), 14)
        for case in report['cases']:
            self.assertEqual('login_prepare' in case['events'], case['code'] == 0)
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])

    def test_changed_registration_rejected(self):
        context = self.context()
        context['handler_table'] = '0x149dc65b8'
        with self.assertRaisesRegex(ValueError, 'handler registration link differs'):
            load('verify-version-result-handler-context').verify(context, ROOT)

    def test_changed_login_handoff_rejected(self):
        context = self.context()
        context['login_prepare'] = '0x1467ce6a0'
        with self.assertRaisesRegex(ValueError, 'Login tail handoff differs'):
            load('verify-version-result-handler-context').verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
