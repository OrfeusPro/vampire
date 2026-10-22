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
    def test_creation_nickname_reuses_persisted_proposal_and_changes_only_after_confirmed_collision(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'console.sqlite3'
            store = AccountStore(path, FixtureVault())
            identifier = store.save('one@unit.invalid', password='fixture', assignment={'region': 'EU', 'server_id': 384})
            self.assertEqual(store.accounts()[0]['create_class'], 'Gunner')
            with self.assertRaises(ValueError): store.creation_nickname(identifier, region='EU', server_id=384)
            store.save_characters(identifier, region='EU', server_id=384, characters=[], observed_utc='2026-10-22T20:00:00+00:00')
            first = store.creation_nickname(identifier, region='EU', server_id=384)
            self.assertRegex(first, r'^[A-Z][a-z]{9}$')
            store = AccountStore(path, FixtureVault())
            self.assertEqual(first, store.creation_nickname(identifier, region='EU', server_id=384))
            for outcome in ('timeout', 'unknown', 'connection_closed'):
                with self.assertRaises(ValueError):
                    store.creation_nickname(identifier, region='EU', server_id=384, result=outcome, rejected_name=first)
                self.assertEqual(store.accounts()[0]['create_nickname'], first)
            with self.assertRaises(ValueError):
                store.creation_nickname(identifier, region='EU', server_id=384, result='name_taken', rejected_name='other')
            second = store.creation_nickname(identifier, region='EU', server_id=384, result='name_taken', rejected_name=first)
            self.assertNotEqual(first, second)
            self.assertEqual(store.accounts()[0]['create_class'], 'Gunner')
            for _ in range(3):
                second = store.creation_nickname(identifier, region='EU', server_id=384, result='name_taken', rejected_name=second)
            with self.assertRaises(ValueError):
                store.creation_nickname(identifier, region='EU', server_id=384, result='name_taken', rejected_name=second)
            self.assertEqual(store.accounts()[0]['create_nickname'], second)

    def test_creation_name_requires_empty_list_for_same_account_and_target(self):
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('one@unit.invalid', password='fixture', assignment={'region': 'EU', 'server_id': 384,
                'create_class': 'Fighter', 'create_nickname': 'ManualName', 'create_random_nickname': False})
            second = store.save('two@unit.invalid', password='fixture', assignment={'region': 'EU', 'server_id': 384})
            store.save_characters(identifier, region='EU', server_id=384, characters=[], observed_utc='2026-10-22T20:00:00+00:00')
            for account, region, server in ((second, 'EU', 384), (identifier, 'JP', 384), (identifier, 'EU', 385)):
                with self.assertRaises(ValueError): store.creation_nickname(account, region=region, server_id=server)
            self.assertEqual('ManualName', store.creation_nickname(identifier, region='EU', server_id=384))
            with self.assertRaises(ValueError):
                store.creation_nickname(identifier, region='EU', server_id=384, result='name_taken', rejected_name='ManualName')
            self.assertEqual(store.accounts()[0]['create_class'], 'Fighter')
            store.save_characters(identifier, region='EU', server_id=384,
                characters=[dict(index=0, key='123', name='Existing')], observed_utc='2026-10-22T20:01:00+00:00')
            with self.assertRaises(ValueError): store.creation_nickname(identifier, region='EU', server_id=384)

    def test_sdk_creation_requires_verified_nid_and_fresh_missing_player_result(self):
        spec = importlib.util.spec_from_file_location('sdk_job_test', HERE / 'vampir-headless/account-manager.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('fixture@unit.invalid', password='fixture', assignment={})
            jobs = tool.Jobs(store)
            with patch.object(tool.subprocess, 'Popen') as popen, patch.object(tool.threading, 'Thread'):
                for state, code in (('unconfirmed', 1203), ('nid_verified', None), ('nid_verified', 100), ('sdk_created', 1203)):
                    store.registration_status(identifier, state)
                    jobs.jobs[identifier] = dict(running=False, sdk_error=dict(code=code))
                    with self.subTest(state=state, code=code), self.assertRaises(ValueError):
                        jobs.start(identifier, 'sdk_register')
                popen.assert_not_called()
                store.registration_status(identifier, 'nid_verified')
                jobs.start(identifier, 'sdk_register')
                self.assertEqual(popen.call_count, 1)
                self.assertEqual(popen.call_args.args[0][-2:], ['--operation', 'sdk_register'])
                self.assertNotIn('fixture@unit.invalid', popen.call_args.args[0])

    def test_sdk_creation_is_separate_from_lobby_and_preserves_state_on_failure(self):
        spec = importlib.util.spec_from_file_location('sdk_worker_test', HERE / 'vampir-headless/account-worker.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        store, registry, runner = MagicMock(), MagicMock(), MagicMock()
        store.credential.return_value = ('fixture@unit.invalid', 'fixture-secret', {'enabled': True, 'server_id': None})
        store.accounts.return_value = [{'id': 'fixture-id', 'registration_status': 'nid_verified'}]
        args = SimpleNamespace(store=Path('fixture.sqlite3'), account='fixture-id', operation='sdk_register')
        with patch.object(tool, 'AccountStore', return_value=store), \
             patch.object(tool, 'DeviceRegistry', return_value=registry), \
             patch.object(tool, 'load', return_value=runner) as load, patch.object(tool, 'emit') as emit:
            runner.run.side_effect = RuntimeError('private-error')
            with self.assertRaises(RuntimeError): tool.run(args)
            store.registration_status.assert_not_called()
            runner.run.side_effect = None
            tool.run(args)
            self.assertTrue(all(call.args[1].name == 'run-nid-sdk-sign-in.py' for call in load.call_args_list))
            self.assertEqual(runner.run.call_args.kwargs, dict(password='fixture-secret', selected_profile='recovered-release',
                socks_port=None, create_sdk_player=True, auth_flow='nid', timeout=300))
            store.registration_status.assert_called_once_with('fixture-id', 'sdk_created')
            self.assertEqual(emit.call_args.kwargs['status'], 'stopped')

    def test_sdk_failure_keeps_only_numeric_status_and_code(self):
        spec = importlib.util.spec_from_file_location('worker_error_test', HERE / 'vampir-headless/account-worker.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        value = tool.failure(tool.SdkSignInHttpError('secret-server-text', 403, 123))
        self.assertEqual(value['sdk_error'], {'http_status': 403, 'code': 123})
        self.assertNotIn('secret', json.dumps(value))
        value = tool.failure(tool.SdkSignInHttpError('secret', 'private-status', 'private-code'))
        self.assertEqual(value['sdk_error'], {'http_status': None, 'code': None})
        self.assertNotIn('private', json.dumps(value))
        timeout = RuntimeError('private-browser-details')
        timeout.browser_status = 'timeout'
        value = tool.failure(timeout)
        self.assertIn('Истекло время входа Netmarble', value['message'])
        self.assertNotIn('private', json.dumps(value))

    def test_manual_registration_code_is_scoped_single_use_and_not_in_snapshot(self):
        import io
        spec = importlib.util.spec_from_file_location('console_code_test', HERE / 'vampir-headless/account-manager.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        process = MagicMock(); process.stdin = io.BytesIO(); process.poll.return_value = None
        jobs = tool.Jobs(None)
        jobs.jobs['fixture'] = dict(process=process, running=True, manual_mail_code=True,
            code_sent=False, stage='registration_code')
        for identifier, code in (('other', '12345'), ('fixture', '1234'), ('fixture', '１２３４５')):
            with self.assertRaises(ValueError): jobs.submit_code(identifier, code)
        jobs.submit_code('fixture', '12345')
        self.assertEqual(process.stdin.getvalue(), b'12345\n')
        self.assertNotIn('12345', json.dumps(jobs.snapshot()))
        with self.assertRaises(ValueError): jobs.submit_code('fixture', '54321')
        jobs.jobs['fixture'].update(code_sent=False, stage='registration_form')
        with self.assertRaises(ValueError): jobs.submit_code('fixture', '12345')

    def test_manual_registration_provider_does_not_open_imap(self):
        spec = importlib.util.spec_from_file_location('manual_registration_test', HERE / 'vampir-headless/register-nid-account.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        runner, browser, mail = MagicMock(), MagicMock(), MagicMock()
        runner.load_inputs.return_value = (object(), {'game_code': 'thered'}, {})
        modules = {'run-nid-sdk-sign-in.py': runner, 'nid-browser.py': browser, 'nid-mail-code.py': mail}
        provider = lambda: '12345'
        def capture(*args, **kwargs):
            self.assertIs(kwargs['code_provider'], provider)
            kwargs['progress']({'complete': True})
            return 'fixture-provider'
        browser.capture_nid_credential.side_effect = capture
        with patch.object(tool, 'module', side_effect=lambda name, filename: modules[filename]), \
             patch.object(tool, 'prepare_observed_profile'):
            self.assertEqual(tool.run('fixture@vampir.top', password='fixture', mail_password=None,
                selected_profile='recovered-release', accept_required_terms=True,
                _code_provider=provider, _progress=lambda state: None), 'fixture-provider')
        mail.RegistrationMailbox.assert_not_called()

    def test_character_lists_survive_restart_and_are_isolated_by_account_and_server(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'console.sqlite3'
            store = AccountStore(path, FixtureVault())
            first, second = [store.save(address, password='fixture', assignment={})
                for address in ('one@unit.invalid', 'two@unit.invalid')]
            for identifier, server, name in ((first, 384, 'One'), (second, 384, 'Two'), (first, 382, 'Another server')):
                store.save_characters(identifier, region='EU', server_id=server,
                    characters=[dict(index=0, key='628556622121157889', name=name)], observed_utc='2026-10-22T19:00:00+00:00')
            lists = AccountStore(path, FixtureVault()).character_lists()
            self.assertEqual(len(lists), 3)
            self.assertEqual(lists[first+'|EU|384']['characters'][0]['name'], 'One')
            self.assertEqual(lists[second+'|EU|384']['characters'][0]['name'], 'Two')
            self.assertEqual(lists[first+'|EU|382']['characters'][0]['key'], '628556622121157889')

    def test_only_accepted_list_replaces_cached_characters_and_empty_is_a_real_update(self):
        spec = importlib.util.spec_from_file_location('account_worker_cache_test', HERE / 'vampir-headless/account-worker.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('one@unit.invalid', password='fixture', assignment={})
            settings = dict(region='EU', server_id=384)
            accepted = dict(login_result_code=0, character_list_received=True, character_list_result_code=0,
                characters=[dict(index=0, key='11', name='One')])
            tool.remember_characters(store, identifier, settings, accepted)
            original = store.character_lists()
            for failed in ({}, dict(accepted, login_result_code=59), dict(accepted, character_list_received=False),
                           dict(accepted, character_list_result_code=9)):
                tool.remember_characters(store, identifier, settings, failed)
                self.assertEqual(store.character_lists(), original)
            tool.remember_characters(store, identifier, settings, dict(accepted, characters=[]))
            self.assertEqual(store.character_lists()[identifier+'|EU|384']['characters'], [])

    def test_invalid_character_update_preserves_previous_data(self):
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('one@unit.invalid', password='fixture', assignment={})
            record = dict(index=0, key='11', name='One')
            options = dict(region='EU', server_id=384, observed_utc='2026-10-22T19:00:00+00:00')
            store.save_characters(identifier, characters=[record], **options)
            original = store.character_lists()
            for rows in ([record, dict(record, index=1)], [dict(record, key=11)], [dict(record, index=True)],
                         [dict(record, name='bad\nlabel')]):
                with self.assertRaises(ValueError): store.save_characters(identifier, characters=rows, **options)
                self.assertEqual(store.character_lists(), original)

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
                      {'character_key': '999999999999999999999'}, {'character_key': '1'}, {'character_index': 0},
                      {'create_class': 'random'}, {'create_class': 3}, {'create_class': []}, {'create_random_nickname': 1}):
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
