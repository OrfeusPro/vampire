import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


class NidBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'vampir-headless/nid-browser.py'
        spec = importlib.util.spec_from_file_location('nid_browser_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)

    def plan(self):
        return self.tool.NidWebUrl('https://members.netmarble.com/auth?gameCode=thered&webViewType=sdk&authType=signin')

    def test_captured_callback_is_validated_and_not_retained(self):
        result = dict(status='callback', callback='nmthered://nmidprovider/result?resultCode=0&accessToken=synthetic-token&refreshToken=&channelKey=mailUserKey&netmarbleId=synthetic-id&joinedCountryCode=KR')
        with patch.object(self.tool, '_run', return_value=result):
            credential = self.tool.capture_nid_credential(self.plan(), expected_game_code='thered', data_directory='unused')
        self.assertEqual(credential.access_token, 'synthetic-token')
        self.assertEqual(result, {})
        self.assertNotIn('synthetic-token', repr(credential))

    def test_unknown_game_or_wrong_mode_never_starts_browser(self):
        for url in ('https://members.netmarble.com/auth?gameCode=other&webViewType=sdk&authType=signin',
                    'https://elsewhere.invalid/auth?gameCode=thered&webViewType=sdk&authType=signin',
                    'https://members.netmarble.com/auth?gameCode=thered&webViewType=steam&authType=signin'):
            with patch.object(self.tool, '_run') as run:
                with self.assertRaises(ValueError):
                    self.tool.capture_nid_credential(self.tool.NidWebUrl(url), expected_game_code='thered', data_directory='unused')
                run.assert_not_called()

    def test_wrong_route_and_error_result_are_rejected(self):
        for callback in ('nmother://nmidprovider/result?resultCode=0',
                         'nmthered://nmidprovider/result?resultCode=1'):
            with patch.object(self.tool, '_run', return_value=dict(status='callback', callback=callback)):
                with self.assertRaisesRegex(ValueError, '^NID browser result was not an accepted email sign-in$'):
                    self.tool.capture_nid_credential(self.plan(), expected_game_code='thered', data_directory='unused')

    def test_password_is_forwarded_only_in_helper_request(self):
        result = dict(status='callback', callback='nmthered://nmidprovider/result?resultCode=0&accessToken=synthetic-token&refreshToken=&channelKey=mailUserKey&netmarbleId=synthetic-id&joinedCountryCode=KR')
        with patch.object(self.tool, '_run', return_value=result) as run:
            self.tool.capture_nid_credential(self.plan(), expected_game_code='thered', data_directory='unused',
                                            expected_email='fixture@example.invalid', sign_in_password='fixture-password')
        self.assertEqual(run.call_args.kwargs['sign_in_password'], 'fixture-password')
        self.assertEqual(run.call_args.kwargs['account_hint'], 'fixture@example.invalid')


if __name__ == '__main__': unittest.main()
