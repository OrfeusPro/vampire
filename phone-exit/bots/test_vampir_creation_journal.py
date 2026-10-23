"""Durable creation attempts, restart recovery and worker ordering without auth."""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.account_store import AccountStore
from vampir_core.world_move_start import SOURCE_SHA256


class Vault:
    def encrypt(self, value): return value.encode()
    def decrypt(self, value): return bytes(value).decode()


class CreationJournalTests(unittest.TestCase):
    def store(self, folder):
        store = AccountStore(Path(folder) / 'accounts.sqlite3', Vault())
        identifier = store.save('fixture@unit.invalid', password='fixture', assignment=dict(region='EU',
            server_id=384, create_class='Gunner', create_nickname='Hero'))
        return store, identifier

    def listing(self, store, identifier, characters=(), *, fresh=False):
        stamp = datetime.now(timezone.utc) + (timedelta(seconds=1) if fresh else -timedelta(seconds=1))
        store.save_characters(identifier, region='EU', server_id=384, characters=list(characters), observed_utc=stamp.isoformat())

    def test_persistent_unknown_requires_separate_fresh_list(self):
        with tempfile.TemporaryDirectory() as folder:
            store, identifier = self.store(folder)
            def begin(): return store.begin_creation(identifier, region='EU', server_id=384, nickname='Hero', source_sha256=SOURCE_SHA256)
            with self.assertRaises(ValueError): begin()
            self.listing(store, identifier); token = begin()
            store = AccountStore(store.path, Vault())
            with self.assertRaises(RuntimeError): begin()
            store.finish_creation(token, state='unknown')
            self.assertEqual(store.creation_attempts()[0]['state'], 'unknown')
            with self.assertRaises(RuntimeError): begin()
            with self.assertRaises(ValueError): store.reconcile_creation(identifier, region='EU', server_id=384)
            self.listing(store, identifier, fresh=True)
            self.assertEqual(store.reconcile_creation(identifier, region='EU', server_id=384), 'empty_verified')
            next_token = begin(); self.assertNotEqual(next_token, token)
            self.assertEqual(len(store.creation_attempts()), 2)

    def test_created_identity_survives_cleanup_and_existing_blocks_creation(self):
        with tempfile.TemporaryDirectory() as folder:
            store, identifier = self.store(folder); self.listing(store, identifier)
            token = store.begin_creation(identifier, region='EU', server_id=384, nickname='Hero', source_sha256=SOURCE_SHA256)
            self.assertTrue(store.finish_creation(token, state='created', result_code=0, key='123', name='ServerHero'))
            self.assertFalse(store.finish_creation(token, state='unknown'))
            self.assertEqual(store.creation_attempts()[0]['character_name'], 'ServerHero')
            self.assertIsNone(store.accounts()[0]['character_index'])
            self.listing(store, identifier, [dict(index=0, key='123', name='ServerHero')], fresh=True)
            self.assertEqual(store.reconcile_creation(identifier, region='EU', server_id=384), 'existing_verified')
            self.assertEqual((store.accounts()[0]['character_index'], store.accounts()[0]['character_key']), (0, '123'))
            with self.assertRaises(ValueError):
                store.begin_creation(identifier, region='EU', server_id=384, nickname='Hero', source_sha256=SOURCE_SHA256)
            with self.assertRaises(ValueError): store.finish_creation(token, state='rejected', key='123')

    def test_competing_attempts_are_serialized(self):
        with tempfile.TemporaryDirectory() as folder:
            store, identifier = self.store(folder); self.listing(store, identifier)
            barrier = threading.Barrier(2); outcomes = []
            def begin():
                barrier.wait()
                try:
                    store.begin_creation(identifier, region='EU', server_id=384, nickname='Hero', source_sha256=SOURCE_SHA256)
                    outcomes.append('pending')
                except RuntimeError: outcomes.append('blocked')
            workers = [threading.Thread(target=begin) for _ in range(2)]
            for worker in workers: worker.start()
            for worker in workers: worker.join(3); self.assertFalse(worker.is_alive())
            self.assertCountEqual(outcomes, ['pending', 'blocked'])
            self.assertEqual(len(store.creation_attempts()), 1)

    def test_worker_persists_before_factory_returns_and_records_terminal_outcome(self):
        path = Path(__file__).parent / 'vampir-headless/account-worker.py'
        spec = importlib.util.spec_from_file_location('creation_worker_test', path)
        worker = importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)
        for mode in ('created', 'rejected', 'crash', 'existing'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                store, identifier = self.store(folder)
                cdn, login = MagicMock(), MagicMock()
                cdn.profile.return_value = dict(url='https://unit.invalid')
                cdn.fetch.return_value = (b'fixture', {})
                cdn.save.return_value = (Path('fixture.json'), None)
                def run_login(*args, **kwargs):
                    self.assertEqual(store.creation_attempts(), [])
                    if mode == 'existing':
                        return dict(status='game_login_probe', game=dict(login_result_code=0,
                            character_list_received=True, character_list_result_code=0,
                            characters=[dict(index=0, key='123', name='Existing')]))
                    payload = kwargs['creation_factory'](SimpleNamespace(result_code=0, records=()))
                    self.assertEqual(payload.name, 'Hero')
                    persisted = AccountStore(store.path, Vault()).creation_attempts()
                    self.assertEqual(persisted[-1]['state'], 'pending')
                    if mode == 'crash': raise ConnectionError('fixture')
                    game = dict(login_result_code=0, character_list_received=True,
                        character_list_result_code=0, characters=[], character_entry_state='empty_list',
                        character_creation_state=mode, character_creation_result_code=0 if mode == 'created' else 59)
                    if mode == 'created': game.update(created_character_key='123', created_character_name='ServerHero')
                    return dict(status='game_login_probe', game=game)
                login.run.side_effect = run_login
                def load(name, path):
                    if path.name == 'fetch-public-cdn-config.py': return cdn
                    if path.name == 'probe-selected-game-login.py': return login
                    self.fail('Unexpected auth/module: ' + path.name)
                with patch.object(worker, 'AccountStore', return_value=store), \
                     patch.object(worker, 'DeviceRegistry', return_value=MagicMock()), \
                     patch.object(worker, 'load', side_effect=load), patch.object(worker, 'emit'), \
                     patch.object(worker.Path, 'read_bytes', return_value=b'fixture'), \
                     patch.object(worker, 'parse_patch_client_revision', return_value=261105):
                    args = SimpleNamespace(store=store.path, account=identifier, operation='create', manual_sign_in=False)
                    if mode == 'crash':
                        with self.assertRaises(ConnectionError): worker.run(args)
                    else: worker.run(args)
                attempts = store.creation_attempts()
                if mode == 'existing': self.assertEqual(attempts, [])
                else:
                    self.assertEqual(attempts[0]['state'], 'unknown' if mode == 'crash' else mode)
                    if mode == 'created': self.assertEqual(attempts[0]['character_key'], '123')
                    else: self.assertNotIn('character_key', attempts[0])


if __name__ == '__main__': unittest.main()
