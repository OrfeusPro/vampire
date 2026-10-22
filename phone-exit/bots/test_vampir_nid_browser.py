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

    def test_registration_requires_password_and_mail_provider_before_process_start(self):
        with patch.object(self.tool.subprocess, 'Popen') as start:
            for options in ({}, {'socks_port': 17948}):
                with self.assertRaises(ValueError):
                    self.tool._run(url=self.plan().url, game_code='thered', timeout=30,
                        data_directory='unused', smoke=False, account_hint='fixture@vampir.top',
                        sign_in_password='fixture-password', register_account=True, **options)
            start.assert_not_called()

    def test_non_callback_reports_only_fixed_status_and_step(self):
        for status, step, expected in (('timeout', 'submitted', ('timeout', 'submitted')),
                ('private-remote-text', 'secret-token', ('unknown', 'unknown'))):
            result = dict(status=status, sign_in_step=step, callback='secret-callback')
            with patch.object(self.tool, '_run', return_value=result):
                with self.assertRaises(self.tool.NidBrowserStatusError) as captured:
                    self.tool.capture_nid_credential(self.plan(), expected_game_code='thered', data_directory='unused')
            self.assertEqual((captured.exception.browser_status, captured.exception.sign_in_step), expected)
            self.assertEqual(result, {})
            self.assertNotIn('secret', str(captured.exception))

    def test_nid_failure_diagnostic_numbers_are_bounded_and_callback_is_cleared(self):
        for status, code, expected in ((400, 123, (400, 123)),
                ('private-status', 'private-code', (None, None)), (True, 2**40, (None, None))):
            result = dict(status='login_failed', sign_in_step='submitted', callback='secret-callback',
                nid_http_status=status, nid_error_code=code)
            with patch.object(self.tool, '_run', return_value=result):
                with self.assertRaises(self.tool.NidBrowserStatusError) as captured:
                    self.tool.capture_nid_credential(self.plan(), expected_game_code='thered', data_directory='unused')
            self.assertEqual(captured.exception.browser_status, 'login_failed')
            self.assertEqual((captured.exception.nid_http_status, captured.exception.nid_error_code), expected)
            self.assertEqual(result, {})
            self.assertNotIn('secret', str(captured.exception))


if __name__ == '__main__': unittest.main()
