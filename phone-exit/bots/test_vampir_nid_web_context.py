import importlib.util
import json
from pathlib import Path
import sys
import unittest
from dataclasses import replace

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.device_registry import DeviceBinding
from vampir_core.nid_web_context import prepare_nid_sign_in_context, nid_webview_type


class NidWebContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = HERE / 'resource-tools/vampir/replay-nid-web-context.py'
        spec = importlib.util.spec_from_file_location('nid_web_context_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT / 'code-clues/nid-web-context-replay.json').read_text('utf-8'))

    def binding(self, nm='nm-fixture', nid='nid-fixture'):
        return DeviceBinding('test@example.invalid', 'profile-fixture', 'real', True,
            'separate-sdk-fixture', nm, 'observed-fixture', 'unknown', '', nid, 'observed-fixture')

    def prepare(self, **kwargs):
        args = dict(binding=self.binding(), game_code='thered', build_code=0, country_code='KR',
                    language='en-US', os_type='windows', os_version='os-fixture', client_id='client-fixture', raw_webview_type=0)
        args.update(kwargs)
        return prepare_nid_sign_in_context(**args)

    def test_native_base_pairs_and_all_webview_types_reproduce(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertEqual(len(self.report['cases']), 8)
        self.assertFalse(self.report['network_ready'])
        for case in self.report['cases']:
            f = case['fixture']
            plan = self.prepare(binding=self.binding(f['nm_device_key'], f['nid_device_key']), game_code=f['game_code'],
                build_code=f['build_code'], country_code=f['country'], language=f['language'], os_type=f['os'],
                os_version=f['os_version'], client_id=f['client_id'])
            self.assertEqual([list(p) for p in plan.parameters[:10]], case['pairs'])
        self.assertEqual(len(self.report['type_cases']), 256)
        for case in self.report['type_cases']:
            self.assertEqual(nid_webview_type(case['raw_type']), case['value'])

    def test_nid_key_is_separate_from_sdk_key_and_repr_hidden(self):
        plan = self.prepare()
        pairs = dict(plan.parameters)
        self.assertEqual((pairs['deviceKey'], pairs['nmDeviceKey'], pairs['nidV'], pairs['authType']),
                         ('nid-fixture', 'nm-fixture', '3', 'signin'))
        self.assertNotIn('separate-sdk-fixture', pairs.values())
        self.assertNotIn('fixture', repr(plan))
        self.assertNotIn('accessToken', pairs)
        self.assertNotIn('credential', pairs)

    def test_confirmation_and_missing_context_gates(self):
        with self.assertRaises(PermissionError): self.prepare(binding=replace(self.binding(), confirmation='required'))
        for change in (dict(kind='planned'), dict(nid_device_key=''), dict(identity_source='')):
            with self.assertRaises(ValueError): self.prepare(binding=replace(self.binding(), **change))
        for change in (dict(client_id=''), dict(build_code=True), dict(language='bad\0text'), dict(raw_webview_type=256)):
            with self.assertRaises(ValueError): self.prepare(**change)
        with self.assertRaises(BufferError):
            self.prepare(language='Ж' * 8192, os_version='Ж' * 8192)


if __name__ == '__main__': unittest.main()
