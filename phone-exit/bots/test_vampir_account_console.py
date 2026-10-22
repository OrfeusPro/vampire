import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, MagicMock
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.account_store import AccountStore, WindowsVault


class FixtureVault:
    def encrypt(self, value):
        return b'fixture:' + hashlib.sha256(value.encode()).digest()
    def decrypt(self, value):
        raise AssertionError('UI / storage tests must not request a live credential')


class AccountConsoleTests(unittest.TestCase):
    def test_two_owned_workers_are_isolated_and_third_start_is_rejected(self):
        spec = importlib.util.spec_from_file_location('console_process_test', HERE / 'vampir-headless/account-manager.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'account-worker.py').write_text('import time\ntime.sleep(30)\n', encoding='utf-8')
            store = AccountStore(root / 'console.sqlite3', FixtureVault())
            ids = [store.save(f'worker{i}@unit.invalid', password='fixture', assignment={}) for i in range(3)]
            jobs = tool.Jobs(store)
            try:
                with patch.object(tool, 'HERE', root):
                    jobs.start(ids[0], 'start'); jobs.start(ids[1], 'start')
                    with self.assertRaises(ValueError): jobs.start(ids[2], 'start')
                self.assertNotEqual(jobs.jobs[ids[0]]['process'].pid, jobs.jobs[ids[1]]['process'].pid)
                jobs.stop(ids[0])
                self.assertIsNotNone(jobs.jobs[ids[0]]['process'].poll())
                self.assertIsNone(jobs.jobs[ids[1]]['process'].poll())
            finally:
                jobs.close()
                deadline = time.monotonic() + 3
                while any(j['running'] for j in jobs.snapshot().values()) and time.monotonic() < deadline:
                    time.sleep(.01)
            self.assertTrue(all(j['process'].poll() is not None for j in jobs.jobs.values()))

    def test_encrypted_password_is_never_returned_or_replaced_by_blank_form(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'console.sqlite3'
            store = AccountStore(path, FixtureVault())
            identifier = store.save('Bot@unit.invalid', password='private-password-fixture', assignment={'region': 'EU', 'server_id': 384})
            before = path.read_bytes()
            self.assertNotIn(b'private-password-fixture', before)
            self.assertEqual(store.save('bot@unit.invalid', assignment={'label': 'Основной'}), identifier)
            self.assertNotIn('private-password-fixture', json.dumps(store.accounts()))
            self.assertNotIn('password', {k for k in store.accounts()[0] if k != 'password_saved'})
            self.assertEqual(len(AccountStore(path, FixtureVault()).accounts()), 1)

    def test_assignments_validate_types_and_do_not_generate_identity(self):
        for value in ({'server_id': True}, {'character_index': -1}, {'device_profile': 'random-fingerprint'},
                      {'region': 'unknown'}, {'create_nickname': 'bad\nname'}, {'enabled': 1},
                      {'character_key': '999999999999999999999'}, {'character_key': '1'}, {'character_index': 0}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                AccountStore.assignment(value)
        self.assertEqual(AccountStore.assignment({})['device_profile'], 'current-pc')

    def test_mail_password_and_registration_state_survive_blank_save(self):
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('fixture@vampir.top', password='game-fixture', mail_password='mail-fixture', assignment={})
            store.registration_status(identifier, 'registered')
            store.save('fixture@vampir.top', assignment={'enabled': False})
            row = store.accounts()[0]
            self.assertTrue(row['mail_password_saved'])
            self.assertFalse(row['enabled'])
            self.assertEqual(row['registration_status'], 'registered')
            self.assertNotIn(b'mail-fixture', store.path.read_bytes())

    def test_disabled_account_and_unapproved_registration_never_start_process(self):
        spec = importlib.util.spec_from_file_location('console_job_test', HERE / 'vampir-headless/account-manager.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('fixture@vampir.top', password='fixture', mail_password='fixture', assignment={'enabled': False})
            jobs = tool.Jobs(store)
            with patch.object(tool.subprocess, 'Popen') as popen:
                with self.assertRaises(ValueError): jobs.start(identifier, 'start')
                store.save('fixture@vampir.top', assignment={'enabled': True})
                with self.assertRaises(ValueError): jobs.start(identifier, 'register')
                store.registration_status(identifier, 'registered')
                with self.assertRaises(ValueError): jobs.start(identifier, 'register', accept_required_terms=True)
                popen.assert_not_called()

    def test_registration_direct_release_requires_completion_and_closes_mailbox(self):
        spec = importlib.util.spec_from_file_location('registration_adapter_test', HERE / 'vampir-headless/register-nid-account.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        runner, browser, mailbox = MagicMock(), MagicMock(), MagicMock()
        runner.load_inputs.return_value = (object(), {'game_code': 'thered'}, {})
        modules = {'run-nid-sdk-sign-in.py': runner, 'nid-browser.py': browser,
                   'nid-mail-code.py': SimpleNamespace(RegistrationMailbox=lambda *args: mailbox)}
        for completed in (False, True):
            def capture(*args, **kwargs):
                kwargs['progress']({'complete': completed})
                return 'fixture-provider'
            browser.capture_nid_credential.side_effect = capture
            with patch.object(tool, 'module', side_effect=lambda name, filename: modules[filename]), \
                 patch.object(tool, 'prepare_observed_profile') as prepare:
                options = dict(password='game-fixture', mail_password='mail-fixture', selected_profile='recovered-release',
                    socks_port=None, accept_required_terms=True, _progress=lambda state: None)
                if completed:
                    self.assertEqual(tool.run('fixture@vampir.top', **options), 'fixture-provider')
                else:
                    with self.assertRaises(RuntimeError): tool.run('fixture@vampir.top', **options)
                prepare.assert_called_once_with(runner, 'fixture@vampir.top', selected_profile='recovered-release')
                self.assertIsNone(runner.load_inputs.call_args.kwargs['route'])
                self.assertIsNone(browser.capture_nid_credential.call_args.kwargs['socks_port'])
        self.assertEqual(mailbox.close.call_count, 2)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows DPAPI')
    def test_real_dpapi_round_trip_and_wrong_ciphertext_fail(self):
        vault = WindowsVault()
        encrypted = vault.encrypt('fixture-only-Ж42')
        self.assertNotIn(b'fixture-only', encrypted)
        self.assertEqual(vault.decrypt(encrypted), 'fixture-only-Ж42')
        with self.assertRaises(RuntimeError):
            vault.decrypt(b'invalid-DPAPI-fixture')

    def test_http_token_origin_and_host_gate_with_fixture_data_only(self):
        spec = importlib.util.spec_from_file_location('account_console_test', HERE / 'vampir-headless/account-manager.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'accounts.sqlite3', FixtureVault())
            store.save('one@unit.invalid', password='fixture', assignment={})
            http, jobs = tool.server(store, port=0)
            worker = threading.Thread(target=http.serve_forever, daemon=True)
            worker.start()
            base = 'http://127.0.0.1:' + str(http.server_port)
            try:
                with urlopen(base) as response:
                    page = response.read().decode()
                    self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])
                token = re.search(r'name="console-token" content="([^"]+)"', page)[1]
                for headers in ({}, {'X-Console-Token': token, 'Origin': 'https://unit.invalid'},
                                {'X-Console-Token': token, 'Host': 'unit.invalid'}):
                    with self.subTest(headers=list(headers)), self.assertRaises(HTTPError) as error:
                        urlopen(Request(base + '/api/state', headers=headers))
                    self.assertEqual(error.exception.code, 403)
                    error.exception.close()
                with urlopen(Request(base + '/api/state', headers={'X-Console-Token': token})) as response:
                    data = json.load(response)
                self.assertEqual(data['accounts'][0]['email'], 'one@unit.invalid')
                self.assertEqual(data['jobs'], {})
                self.assertNotIn('password', data['accounts'][0])
            finally:
                jobs.close(); http.shutdown(); http.server_close(); worker.join(3)


if __name__ == '__main__':
    unittest.main()
