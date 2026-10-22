"""Local bot assignments and encrypted credentials; no game operations."""
import ctypes
from contextlib import contextmanager
from ctypes import wintypes
import json
from pathlib import Path
import sqlite3
import sys
import uuid

from .device_registry import _email


class WindowsVault:
    """Windows DPAPI CurrentUser, without plaintext fallback."""
    def _call(self, value, decrypt):
        if sys.platform != 'win32':
            raise RuntimeError('Windows DPAPI is required')
        if type(value) is not bytes or not value or len(value) > 65536:
            raise ValueError('Invalid protected credential')
        class Blob(ctypes.Structure):
            _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]
        buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
        source, target = Blob(len(value), buffer), Blob()
        crypt = ctypes.WinDLL('crypt32', use_last_error=True)
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        if decrypt:
            operation = crypt.CryptUnprotectData
            second = None
        else:
            operation = crypt.CryptProtectData
            second = 'Phone Exit Vampir account password'
        operation.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p if decrypt else wintypes.LPCWSTR,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        operation.restype = wintypes.BOOL
        if not operation(ctypes.byref(source), second, None, None, None, 1, ctypes.byref(target)):
            raise RuntimeError('Credential protection failed')
        try:
            return ctypes.string_at(target.data, target.size)
        finally:
            kernel.LocalFree(target.data)

    def encrypt(self, password):
        if type(password) is not str or not 1 <= len(password) <= 256:
            raise ValueError('Password must contain 1..256 characters')
        return self._call(password.encode('utf-8'), False)

    def decrypt(self, protected):
        return self._call(protected, True).decode('utf-8')


class AccountStore:
    def __init__(self, path, vault=None):
        self.path, self.vault = Path(path), vault or WindowsVault()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,password BLOB NOT NULL,assignment TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS catalogs(region TEXT PRIMARY KEY,data TEXT NOT NULL)')
            columns = {row[1] for row in db.execute('PRAGMA table_info(accounts)')}
            if 'mail_password' not in columns:
                db.execute('ALTER TABLE accounts ADD COLUMN mail_password BLOB')
            if 'registration_status' not in columns:
                db.execute("ALTER TABLE accounts ADD COLUMN registration_status TEXT NOT NULL DEFAULT 'unknown'")

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def assignment(value):
        if type(value) is not dict or set(value) - {'label', 'enabled', 'device_profile', 'region', 'server_id', 'character_index', 'character_key', 'create_nickname'}:
            raise ValueError('Unknown account setting')
        enabled = value.get('enabled', True)
        if type(enabled) is not bool:
            raise ValueError('Invalid account availability')
        label, nickname = value.get('label', ''), value.get('create_nickname', '')
        if any(type(v) is not str or len(v) > limit or any(ord(c) < 32 for c in v)
               for v, limit in ((label, 100), (nickname, 40))):
            raise ValueError('Invalid account text')
        profile = value.get('device_profile', 'current-pc')
        if profile != 'current-pc':
            raise ValueError('Only the observed current PC profile is supported')
        region = value.get('region', 'EU')
        if region not in ('EU', 'NA', 'SG', 'JP', 'TW', 'ASIA', 'KR'):
            raise ValueError('Invalid server region')
        server = value.get('server_id')
        character = value.get('character_index')
        key = value.get('character_key')
        if key is not None and (type(key) is not str or not key.isascii() or not key.isdigit() or len(key) > 20 or not 0 <= int(key) <= 0xffffffffffffffff):
            raise ValueError('Invalid character key')
        if server is not None and (type(server) is not int or not 1 <= server <= 0xffffffff):
            raise ValueError('Invalid server ID')
        if character is not None and (type(character) is not int or not 0 <= character <= 65535):
            raise ValueError('Invalid character index')
        if key is not None and character is None:
            raise ValueError('A character key requires a selected character')
        if character is not None and server is None:
            raise ValueError('A character requires a server')
        return dict(label=label, enabled=enabled, device_profile=profile, region=region, server_id=server,
            character_index=character, character_key=key, create_nickname=nickname)

    def save(self, email, *, password=None, mail_password=None, assignment):
        email, assignment = _email(email), self.assignment(assignment)
        protected = self.vault.encrypt(password) if password is not None else None
        protected_mail = self.vault.encrypt(mail_password) if mail_password is not None else None
        with self._db() as db:
            old = db.execute('SELECT id,password FROM accounts WHERE email=?', (email,)).fetchone()
            if old is None and protected is None:
                raise ValueError('A new account requires a password')
            identifier = old[0] if old else str(uuid.uuid4())
            db.execute('INSERT INTO accounts(id,email,password,assignment) VALUES(?,?,?,?) ON CONFLICT(email) DO UPDATE SET password=excluded.password,assignment=excluded.assignment',
                (identifier, email, protected if protected is not None else old[1], json.dumps(assignment)))
            if protected_mail is not None:
                db.execute('UPDATE accounts SET mail_password=? WHERE id=?', (protected_mail, identifier))
        return identifier

    def accounts(self):
        with self._db() as db:
            rows = db.execute('SELECT id,email,assignment,mail_password IS NOT NULL,registration_status FROM accounts ORDER BY rowid').fetchall()
        return [dict(id=i, email=e, password_saved=True, mail_password_saved=bool(m), registration_status=r,
            **json.loads(a)) for i, e, a, m, r in rows]

    def mail_credential(self, identifier):
        with self._db() as db:
            row = db.execute('SELECT mail_password FROM accounts WHERE id=?', (identifier,)).fetchone()
        if row is None or row[0] is None:
            raise ValueError('Save the mailbox password before registration')
        return self.vault.decrypt(row[0])

    def registration_status(self, identifier, state):
        if state not in ('in_progress', 'unconfirmed', 'registered'):
            raise ValueError('Invalid registration state')
        with self._db() as db:
            if db.execute('UPDATE accounts SET registration_status=? WHERE id=?', (state, identifier)).rowcount != 1:
                raise KeyError('Unknown account')

    def credential(self, identifier):
        with self._db() as db:
            row = db.execute('SELECT email,password,assignment FROM accounts WHERE id=?', (identifier,)).fetchone()
        if row is None:
            raise KeyError('Unknown account')
        return row[0], self.vault.decrypt(row[1]), json.loads(row[2])

    def save_catalog(self, region, data):
        if region not in ('EU', 'NA', 'SG', 'JP', 'TW', 'ASIA', 'KR') or type(data) is not dict:
            raise ValueError('Invalid catalog')
        if len(json.dumps(data)) > 262144:
            raise ValueError('Catalog exceeds budget')
        with self._db() as db:
            db.execute('INSERT INTO catalogs VALUES(?,?) ON CONFLICT(region) DO UPDATE SET data=excluded.data', (region, json.dumps(data)))

    def catalogs(self):
        with self._db() as db:
            return {region: json.loads(data) for region, data in db.execute('SELECT region,data FROM catalogs')}
