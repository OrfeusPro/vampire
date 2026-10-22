import collections
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import threading
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.account_store import AccountStore


class Vault:
    def encrypt(self, value): return b'fixture:' + value.encode()
    def decrypt(self, value): return value[len(b'fixture:'):].decode()


class AccountBatchTests(unittest.TestCase):
    def store(self, folder):
        store = AccountStore(Path(folder) / 'accounts.sqlite3', Vault())
        store.save_catalog('EU', {'observed_utc': '2026-10-23T00:00:00+00:00',
            'servers': [dict(id=381+i, name='Server '+str(i), excluded=False) for i in range(12)]})
        return store

    def test_batch_is_idempotent_distinct_and_assigns_two_per_server(self):
        with tempfile.TemporaryDirectory() as folder:
            store = self.store(folder)
            existing = store.save('existing@unit.invalid', password='old', assignment={'region': 'EU', 'server_id': 384})
            first = store.prepare_batch('eu-batch')
            self.assertEqual(first, store.prepare_batch('eu-batch'))
            accounts = [a for a in store.accounts() if a['id'] != existing]
            self.assertEqual(len(accounts), 24)
            self.assertEqual(set(collections.Counter(a['server_id'] for a in accounts).values()), {2})
            passwords = []
            for a in accounts:
                self.assertEqual(a['mail_status'], 'planned')
                self.assertEqual(a['registration_status'], 'unknown')
                self.assertFalse(a['enabled'])
                self.assertIsNone(a['character_index'])
                self.assertEqual(a['create_class'], 'Gunner')
                self.assertEqual(a['auth_flow'], 'launcher')
                for kind in ('mail', 'netmarble'):
                    password = store.reveal_password(a['id'], kind)
                    self.assertRegex(password, r'^[A-Za-z0-9]{20}[!#$%]$' if kind == 'mail' else r'^[A-Za-z0-9]{16}$')
                    self.assertTrue(any(c.islower() for c in password) and any(c.isupper() for c in password) and any(c.isdigit() for c in password))
                    self.assertNotIn(password, json.dumps(store.accounts()))
                    passwords.append(password)
            self.assertEqual(len(set(passwords)), 48)
            self.assertEqual(accounts[0]['email'], 'nightraven@vampir.top')
            self.assertEqual(accounts[0]['create_nickname'], 'NightRaven')
            self.assertEqual(store.credential(existing)[1], 'old')
            with self.assertRaises(ValueError): store.prepare_batch('eu-batch', minimum_new=25)

    def test_renaming_only_drafts_preserves_passwords_and_rolls_back_for_created_mail(self):
        with tempfile.TemporaryDirectory() as folder:
            store = self.store(folder)
            batch = store.prepare_batch('rename')
            identifiers = batch['account_ids']
            before = {i: (store.reveal_password(i, 'mail'), store.reveal_password(i, 'netmarble')) for i in identifiers}
            with store._db() as db:
                db.execute('UPDATE accounts SET email=? WHERE id=?', ('old-draft@vampir.top', identifiers[0]))
            renamed = store.rename_prepared_batch('rename')
            self.assertEqual(renamed[0], 'nightraven@vampir.top')
            self.assertEqual(renamed, store.rename_prepared_batch('rename'))
            self.assertEqual(before, {i: (store.reveal_password(i, 'mail'), store.reveal_password(i, 'netmarble')) for i in identifiers})
            store.mail_status(identifiers[-1], 'created')
            with store._db() as db:
                db.execute('UPDATE accounts SET email=? WHERE id=?', ('must-stay@vampir.top', identifiers[0]))
            with self.assertRaises(ValueError): store.rename_prepared_batch('rename')
            self.assertEqual(store.accounts()[0]['email'], 'must-stay@vampir.top')

    def test_expands_for_more_servers_and_transaction_rolls_back(self):
        with tempfile.TemporaryDirectory() as folder:
            store = self.store(folder)
            store.save_catalog('EU', {'servers': [dict(id=381+i, name='Server '+str(i), excluded=False) for i in range(13)]})
            self.assertEqual(len(store.prepare_batch('larger')['account_ids']), 26)
        class BrokenVault(Vault):
            count = 0
            def encrypt(self, value):
                self.count += 1
                if self.count == 5: raise RuntimeError('fixture failure')
                return super().encrypt(value)
        with tempfile.TemporaryDirectory() as folder:
            store = self.store(folder); store.vault = BrokenVault()
            with self.assertRaises(RuntimeError): store.prepare_batch('atomic')
            self.assertEqual(store.accounts(), [])
            with store._db() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM prepared_batches').fetchone()[0], 0)

    def test_reveal_requires_local_api_token_and_explicit_valid_kind(self):
        path = Path(__file__).parent / 'vampir-headless/account-manager.py'
        spec = importlib.util.spec_from_file_location('batch_api_test', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            store = self.store(folder)
            identifier = store.save('fixture@unit.invalid', password='fake-game-secret', mail_password='fake-mail-secret', assignment={})
            http, jobs = module.server(store, port=0)
            thread = threading.Thread(target=http.serve_forever, daemon=True); thread.start()
            base = 'http://127.0.0.1:'+str(http.server_port)
            try:
                with urlopen(base) as r:
                    token = re.search('name="console-token" content="([^"]+)"', r.read().decode())[1]
                body = json.dumps({'id': identifier, 'kind': 'mail'}).encode()
                with self.assertRaises(HTTPError) as rejected:
                    urlopen(Request(base+'/api/reveal', method='POST'))
                rejected.exception.close()
                with urlopen(Request(base+'/api/reveal', data=body, headers={'Content-Type': 'application/json', 'X-Console-Token': token})) as r:
                    self.assertEqual(json.load(r)['password'], 'fake-mail-secret')
                    self.assertEqual(r.headers['Cache-Control'], 'no-store')
                with urlopen(Request(base+'/api/state', headers={'X-Console-Token': token})) as r:
                    self.assertNotIn('fake-', r.read().decode())
                with self.assertRaises(ValueError): store.reveal_password(identifier, 'all')
            finally:
                http.shutdown(); http.server_close(); jobs.close(); thread.join(timeout=2)


if __name__ == '__main__': unittest.main()
