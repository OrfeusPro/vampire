import importlib.util
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.account_store import AccountStore
from vampir_core.account_sdk_preparation import validate_sdk_preparation
from vampir_core.sdk_first_login import FirstSdkLoginStopped
from vampir_core.sdk_sign_in_response import SdkSignInData
from test_vampir_account_console import FixtureVault


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / 'vampir-headless' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class SdkPreparationTests(unittest.TestCase):
    def test_requires_explicit_query_and_rejects_confirmed_profile_or_assigned_character(self):
        account = dict(registration_status='registered', character_key=None, character_index=None)
        for values in (dict(country=None, locale='en-US', mode='all'),
                       dict(country='UA', locale='', mode='all'),
                       dict(country='UA', locale='en-US', mode=None)):
            with self.assertRaises(ValueError): validate_sdk_preparation(account, **values)
        for change in (dict(registration_status='sdk_created'), dict(character_index=0), dict(character_key='123')):
            with self.assertRaises(ValueError):
                validate_sdk_preparation(dict(account, **change), country='UA', locale='en-US', mode='all')
        self.assertFalse(validate_sdk_preparation(account, country='UA', locale='en-US', mode='all'))

    def test_manager_launches_only_explicit_operation_and_passes_no_credentials(self):
        manager = module('sdk_preparation_manager', 'account-manager.py')
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('sdk@unit.invalid', password='fixture-password', assignment={})
            jobs = manager.Jobs(store)
            with patch.object(manager.subprocess, 'Popen') as popen, patch.object(manager.threading, 'Thread'):
                with self.assertRaises(ValueError): jobs.start(identifier, 'prepare-sdk')
                with self.assertRaises(ValueError): jobs.start(identifier, 'characters', terms_country='UA')
                popen.assert_not_called()
                jobs.start(identifier, 'prepare-sdk', terms_country='UA', terms_locale='en-US',
                           basic_terms_mode='all', manual_sign_in=True)
                command = popen.call_args.args[0]
                self.assertIn('--manual-sign-in', command)
                self.assertEqual(command[-6:], ['--terms-country', 'UA', '--terms-locale', 'en-US', '--basic-terms-mode', 'all'])
                self.assertNotIn('fixture-password', command)
                self.assertNotIn('sdk@unit.invalid', command)
                with self.assertRaises(ValueError):
                    jobs.start(identifier, 'prepare-sdk', terms_country='UA', terms_locale='en-US', basic_terms_mode='all')

    def test_worker_confirms_only_validated_signin_and_does_not_load_game_or_cdn(self):
        worker = module('sdk_preparation_worker', 'account-worker.py')
        for manual, outcome in ((False, 'success'), (True, 'success'), (False, 'terms'), (False, 'unknown')):
            with self.subTest(manual=manual, outcome=outcome):
                store, registry, runner = MagicMock(), MagicMock(), MagicMock()
                store.credential.return_value = ('sdk@unit.invalid', 'fixture-password', dict(enabled=True, server_id=None))
                store.accounts.return_value = [dict(id='id', registration_status='registered', character_key=None, character_index=None)]
                runner.run.return_value = SdkSignInData('fixture-token', 'fixture-player', None, None, 1) if outcome == 'success' else object()
                if outcome == 'terms': runner.run.side_effect = FirstSdkLoginStopped('basic_terms_require_review')
                def load(name, path):
                    self.assertEqual(path.name, 'run-nid-sdk-sign-in.py')
                    return runner
                args = SimpleNamespace(store=Path('fixture.sqlite3'), account='id', operation='prepare-sdk',
                    manual_sign_in=manual, terms_country='UA', terms_locale='en-US', basic_terms_mode='all')
                with patch.object(worker, 'AccountStore', return_value=store), patch.object(worker, 'DeviceRegistry', return_value=registry), \
                     patch.object(worker, 'load', side_effect=load), patch.object(worker, 'emit') as emit:
                    if outcome == 'success':
                        worker.run(args)
                        store.registration_status.assert_called_once_with('id', 'sdk_created')
                    else:
                        with self.assertRaises(FirstSdkLoginStopped): worker.run(args)
                        store.registration_status.assert_not_called()
                    self.assertNotIn('fixture-token', str(emit.call_args_list))
                values = runner.run.call_args.kwargs
                self.assertEqual(values['password'], '' if manual else 'fixture-password')
                self.assertTrue(values['first_sdk_login'])
                self.assertEqual(values['selected_profile'], 'recovered-release')
                self.assertEqual(values['auth_flow'], 'nid')
                store.save_catalog.assert_not_called()
                store.save_characters.assert_not_called()

    def test_terms_stop_has_fixed_message_without_error_payload(self):
        worker = module('sdk_preparation_error', 'account-worker.py')
        known = worker.failure(FirstSdkLoginStopped('individual_terms_require_review'))
        self.assertIn('требуется просмотр', known['message'])
        unknown = worker.failure(FirstSdkLoginStopped('private-token'))
        self.assertNotIn('private-token', unknown['message'])


if __name__ == '__main__':
    unittest.main()
