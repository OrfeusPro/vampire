import importlib.util
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch


class RegistrationCompletionTests(unittest.TestCase):
    def test_sdk_callback_requires_all_signup_steps_without_completion_page(self):
        path = Path(__file__).parent / 'vampir-headless/register-nid-account.py'
        spec = importlib.util.spec_from_file_location('registration_completion_test', path)
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        required = ('terms_submitted', 'email_sent', 'code_submitted', 'password_submitted')
        for missing in (None, *required):
            runner, browser = MagicMock(), MagicMock()
            runner.load_inputs.return_value = (object(), {'game_code': 'thered'}, {})
            def capture(*args, **kwargs):
                for key in required:
                    if key != missing: kwargs['progress']({key: True})
                return 'fixture-validated-callback'
            browser.capture_nid_credential.side_effect = capture
            with self.subTest(missing=missing), patch.object(tool, 'module', side_effect=lambda name, file:
                    {'run-nid-sdk-sign-in.py': runner, 'nid-browser.py': browser, 'nid-mail-code.py': MagicMock()}[file]), \
                    patch.object(tool, 'prepare_observed_profile'):
                def run():
                    return tool.run('fixture@vampir.top', password='fixture', mail_password=None,
                        accept_required_terms=True, _code_provider=lambda: '12345', _progress=lambda state: None)
                if missing is None:
                    self.assertEqual(run(), 'fixture-validated-callback')
                else:
                    with self.assertRaises(RuntimeError): run()


if __name__ == '__main__': unittest.main()
