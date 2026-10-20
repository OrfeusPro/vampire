import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'


class SdkSignInLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('signin_log_test', HERE / 'replay-sdk-sign-in-log.py')
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.saved = json.loads((cls.tool.native.ROOT / 'code-clues/sdk-sign-in-log-replay.json').read_text('utf-8'))

    def test_native_chain_and_absent_service_branch_reproduce(self):
        self.assertEqual(self.tool.build(), self.saved)
        self.assertEqual([case['fill'] for case in self.saved['cases']], [0, 0x55, 0xff])
        for case in self.saved['cases']:
            self.assertEqual(case['component_offset'], '0x78')
            self.assertEqual(case['impl_offset_in_owner'], '0x88')
            self.assertTrue(case['owner_unchanged'])
            self.assertFalse(case['service_available'])
            self.assertEqual(case['events'][0], 'native_impl_entered')

    def test_diagnostic_identifies_send_sign_in_without_guessing_payload(self):
        literals = {row['literal']['address']: row['literal']['text'] for row in self.saved['diagnostic_literals']}
        self.assertIn('FPlatformLogImpl::SendSignIn', literals[0x1494ebba0])
        self.assertEqual(literals[0x1494ebbe8], 'ChannelCode')
        self.assertEqual(literals[0x1494c5ea8], 'GameCode')
        self.assertIn('Service-present event payload', ' '.join(self.saved['limitations']))


if __name__ == '__main__':
    unittest.main()
