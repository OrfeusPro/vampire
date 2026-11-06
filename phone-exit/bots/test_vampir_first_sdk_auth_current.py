"""Current static auth contracts and rejection of missing source argument evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'


class CurrentFirstSdkAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('current_first_auth_fixture', HERE/'inspect-first-sdk-auth-current.py')
        cls.tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.tool)
        cls.report = cls.tool.audit()
        cls.path = cls.tool.load('audit-client-release').save_snapshot(cls.tool.ROOT/'code-clues'/cls.tool.RECIPE, cls.report)

    def invalid_context(self, change, expected):
        value = json.loads(self.tool.CONTEXT.read_bytes()); change(value)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'context.json'; path.write_text(json.dumps(value), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, expected): self.tool.audit(path)

    def test_complete_current_auth_subset_and_retained_report(self):
        self.assertEqual(self.tool.verify_report(self.path), self.report)
        self.assertTrue(self.report['contract_subset_verified']); self.assertFalse(self.report['native_execution'])
        self.assertFalse(self.report['network_used']); self.assertFalse(self.report['runtime_admitted'])
        self.assertEqual(self.report['body_keys'],['nmDeviceKey','deviceKey','countryCode','os','credential'])
        self.assertEqual({x['text'] for x in self.report['owner_keys']},set(self.tool.OWNER_KEYS.values()))

    def test_signup_cannot_borrow_signin_response(self):
        self.invalid_context(lambda c:c['requests']['signup'].update(callback=c['requests']['signin']['callback']), 'callback')

    def test_access_token_initializer_cannot_borrow_another_global(self):
        self.invalid_context(lambda c:c['access_token_initializer'].update(**{'global':'0x14b564ba0'}), 'constructor arguments')

    def test_argument_windows_cannot_be_omitted(self):
        self.invalid_context(lambda c:c.update(windows={}), 'coverage is incomplete')


if __name__=='__main__':unittest.main()
