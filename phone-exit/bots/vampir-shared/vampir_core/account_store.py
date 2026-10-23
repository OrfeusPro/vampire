"""Local bot assignments and encrypted credentials; no game operations."""
import ctypes
from datetime import datetime
from contextlib import contextmanager
from ctypes import wintypes
import json
import re
import secrets
import string
from pathlib import Path
import sqlite3
import sys
import uuid

from .device_registry import _email
from .character_creation_plan import CLASS_CHOICES, DEFAULT_CLASS, MAX_NAME_ATTEMPTS, random_nickname

ACCOUNT_NICKNAMES = (
    'NightRaven', 'AshHunter', 'DuskWarden', 'MoonFang', 'BloodCrow', 'StormWolf',
    'GrimFalcon', 'DarkViper', 'FrostHawk', 'IronShade', 'EmberFang', 'RavenClaw',
    'SilverCrow', 'ScarletOwl', 'NightLynx', 'AshWarden', 'DuskFalcon', 'MoonRaven',
    'ShadowFox', 'StormCrow', 'FrostWolf', 'IronRaven', 'EmberHawk', 'CrimsonFang',
)


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
            db.execute('CREATE TABLE IF NOT EXISTS character_lists(account_id TEXT,region TEXT,server_id INTEGER,data TEXT NOT NULL,PRIMARY KEY(account_id,region,server_id))')
            db.execute('CREATE TABLE IF NOT EXISTS creation_names(account_id TEXT,region TEXT,server_id INTEGER,data TEXT NOT NULL,PRIMARY KEY(account_id,region,server_id))')
            db.execute('CREATE TABLE IF NOT EXISTS creation_attempts(attempt_id TEXT PRIMARY KEY,account_id TEXT NOT NULL,region TEXT NOT NULL,server_id INTEGER NOT NULL,data TEXT NOT NULL)')
            columns = {row[1] for row in db.execute('PRAGMA table_info(accounts)')}
            if 'mail_password' not in columns:
                db.execute('ALTER TABLE accounts ADD COLUMN mail_password BLOB')
            if 'registration_status' not in columns:
                db.execute("ALTER TABLE accounts ADD COLUMN registration_status TEXT NOT NULL DEFAULT 'unknown'")
            if 'mail_status' not in columns:
                db.execute("ALTER TABLE accounts ADD COLUMN mail_status TEXT NOT NULL DEFAULT 'unknown'")
            db.execute('CREATE TABLE IF NOT EXISTS prepared_batches(name TEXT PRIMARY KEY,data TEXT NOT NULL)')

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
        if type(value) is not dict or set(value) - {'label', 'enabled', 'device_profile', 'region', 'server_id', 'character_index', 'character_key', 'create_nickname', 'create_class', 'create_random_nickname', 'auth_flow'}:
            raise ValueError('Unknown account setting')
        enabled = value.get('enabled', True)
        if type(enabled) is not bool:
            raise ValueError('Invalid account availability')
        label, nickname = value.get('label', ''), value.get('create_nickname', '')
        if any(type(v) is not str or len(v) > limit or any(ord(c) < 32 for c in v)
               for v, limit in ((label, 100), (nickname, 40))):
            raise ValueError('Invalid account text')
        profile = value.get('device_profile', 'current-pc')
        auth_flow = value.get('auth_flow', 'launcher')
        if auth_flow not in ('launcher', 'nid'):
            raise ValueError('Invalid sign-in flow')
        create_class = value.get('create_class', DEFAULT_CLASS)
        random_name = value.get('create_random_nickname', True)
        if type(create_class) is not str or create_class not in {key for key, _ in CLASS_CHOICES} or type(random_name) is not bool:
            raise ValueError('Invalid character creation choices')
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
            character_index=character, character_key=key, create_nickname=nickname,
            create_class=create_class, create_random_nickname=random_name, auth_flow=auth_flow)

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
            rows = db.execute('SELECT id,email,assignment,mail_password IS NOT NULL,registration_status,mail_status FROM accounts ORDER BY rowid').fetchall()
        return [dict(id=i, email=e, password_saved=True, mail_password_saved=bool(m), registration_status=r, mail_status=ms,
            **self.assignment(json.loads(a))) for i, e, a, m, r, ms in rows]

    def reveal_password(self, identifier, kind):
        # Explicit local UI action only; never include this in accounts()/state.
        if kind not in ('mail', 'netmarble'):
            raise ValueError('Unknown password kind')
        column = 'mail_password' if kind == 'mail' else 'password'
        with self._db() as db:
            row = db.execute('SELECT ' + column + ' FROM accounts WHERE id=?', (identifier,)).fetchone()
        if row is None or row[0] is None:
            raise ValueError('Password is not saved')
        return self.vault.decrypt(row[0])

    def prepare_batch(self, name, *, domain='vampir.top', region='EU', per_server=2, minimum_new=24):
        """Atomic local plan; does not claim mailboxes or Netmarble accounts exist."""
        if (type(name) is not str or not re.fullmatch(r'[a-z0-9-]{1,80}', name) or domain != 'vampir.top'
                or type(per_server) is not int or not 1 <= per_server <= 10
                or type(minimum_new) is not int or not 1 <= minimum_new <= 128):
            raise ValueError('Invalid batch plan')
        config = dict(domain=domain, region=region, per_server=per_server, minimum_new=minimum_new)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT data FROM prepared_batches WHERE name=?', (name,)).fetchone()
            if old:
                data = json.loads(old[0])
                if data['config'] != config:
                    raise ValueError('Batch already exists with different settings')
                return data
            row = db.execute('SELECT data FROM catalogs WHERE region=?', (region,)).fetchone()
            if row is None:
                raise ValueError('A saved server catalog is required')
            servers = json.loads(row[0])['servers']
            servers = [server for server in servers if server.get('excluded') is False]
            if not servers or len({s['id'] for s in servers}) != len(servers):
                raise ValueError('No unambiguous available servers')
            count = max(minimum_new, len(servers) * per_server)
            if count > 128:
                raise ValueError('Batch exceeds account budget')
            targets = [server for server in servers for _ in range(per_server)]
            used_emails = {e for e, in db.execute('SELECT email FROM accounts')}
            used_passwords, identifiers = set(), []
            def password(size, special=False):
                alphabet = string.ascii_letters + string.digits
                while True:
                    value = ''.join(secrets.choice(alphabet) for _ in range(size))
                    if special:
                        value += secrets.choice('!#$%')
                    if (value not in used_passwords and any(c.islower() for c in value)
                            and any(c.isupper() for c in value) and any(c.isdigit() for c in value)):
                        used_passwords.add(value)
                        return value
            for index in range(count):
                target = targets[index % len(targets)]
                base = ACCOUNT_NICKNAMES[index % len(ACCOUNT_NICKNAMES)]
                ordinal = index // len(ACCOUNT_NICKNAMES) + 1
                while True:
                    nickname = base + (str(ordinal) if ordinal > 1 else '')
                    email = nickname.lower() + '@' + domain
                    if email not in used_emails:
                        used_emails.add(email); break
                    ordinal += 1
                settings = self.assignment(dict(label=nickname, enabled=False, create_nickname=nickname,
                    region=region, server_id=target['id'], auth_flow='launcher'))
                identifier = str(uuid.uuid4())
                db.execute('INSERT INTO accounts(id,email,password,mail_password,assignment,mail_status) VALUES(?,?,?,?,?,?)',
                    (identifier, email, self.vault.encrypt(password(16)), self.vault.encrypt(password(20, special=True)),
                     json.dumps(settings), 'planned'))
                identifiers.append(identifier)
            data = dict(name=name, config=config, account_ids=identifiers,
                server_ids=[s['id'] for s in servers], catalog_observed_utc=json.loads(row[0]).get('observed_utc'))
            db.execute('INSERT INTO prepared_batches VALUES(?,?)', (name, json.dumps(data)))
        return data

    def rename_prepared_batch(self, name):
        """Rename only local, unregistered drafts; external mailboxes are not changed."""
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT data FROM prepared_batches WHERE name=?', (name,)).fetchone()
            if row is None:
                raise ValueError('Unknown batch')
            batch = json.loads(row[0]); config = batch['config']
            renamed = []
            for index, identifier in enumerate(batch['account_ids']):
                account = db.execute('SELECT email,assignment,mail_status,registration_status FROM accounts WHERE id=?', (identifier,)).fetchone()
                if account is None or account[2:] != ('planned', 'unknown'):
                    raise ValueError('Only unregistered mailbox drafts can be renamed')
                settings = self.assignment(json.loads(account[1]))
                ordinal = index // len(ACCOUNT_NICKNAMES) + 1
                nickname = ACCOUNT_NICKNAMES[index % len(ACCOUNT_NICKNAMES)] + (str(ordinal) if ordinal > 1 else '')
                email = nickname.lower() + '@' + config['domain']
                collision = db.execute('SELECT id FROM accounts WHERE email=? AND id<>?', (email, identifier)).fetchone()
                if collision:
                    raise ValueError('Meaningful mailbox login already belongs to another account')
                settings['label'] = nickname
                settings['create_nickname'] = nickname
                db.execute('UPDATE accounts SET email=?,assignment=? WHERE id=?', (email, json.dumps(settings), identifier))
                renamed.append(email)
            batch['naming'] = 'meaningful-game-nicknames'
            db.execute('UPDATE prepared_batches SET data=? WHERE name=?', (json.dumps(batch), name))
        return renamed

    def mail_status(self, identifier, state):
        if state not in ('planned', 'created', 'verified', 'unconfirmed', 'error'):
            raise ValueError('Invalid mailbox status')
        with self._db() as db:
            if db.execute('UPDATE accounts SET mail_status=? WHERE id=?', (state, identifier)).rowcount != 1:
                raise KeyError('Unknown account')

    def creation_nickname(self, identifier, *, region, server_id, result='empty_list', rejected_name=None):
        """Name proposal only. Future decoder must confirm name_taken; no unknown retry."""
        if result not in ('empty_list', 'name_taken') or (result == 'name_taken' and not rejected_name):
            raise ValueError('A confirmed creation outcome is required')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT assignment FROM accounts WHERE id=?', (identifier,)).fetchone()
            if row is None:
                raise KeyError('Unknown account')
            assignment = self.assignment(json.loads(row[0]))
            if (assignment['region'], assignment['server_id']) != (region, server_id) or server_id is None:
                raise ValueError('Creation target changed')
            listing = db.execute('SELECT data FROM character_lists WHERE account_id=? AND region=? AND server_id=?',
                (identifier, region, server_id)).fetchone()
            if listing is None or json.loads(listing[0])['characters']:
                raise ValueError('An accepted empty character list is required')
            if assignment['character_key'] is not None or assignment['character_index'] is not None:
                raise ValueError('A character is already assigned')
            row = db.execute('SELECT data FROM creation_names WHERE account_id=? AND region=? AND server_id=?',
                (identifier, region, server_id)).fetchone()
            history = json.loads(row[0]) if row else []
            name = assignment['create_nickname']
            if result == 'name_taken':
                if not history or rejected_name != history[-1] or name != rejected_name:
                    raise ValueError('The rejected nickname is not the current proposal')
                if not assignment['create_random_nickname']:
                    raise ValueError('Automatic nickname replacement is disabled')
                if len(history) >= MAX_NAME_ATTEMPTS:
                    raise ValueError('Nickname attempts exhausted')
                name = random_nickname(history)
            elif not name and assignment['create_random_nickname']:
                name = history[-1] if history else random_nickname()
            if not name:
                return None
            if not history or name != history[-1]:
                if name in history or len(history) >= MAX_NAME_ATTEMPTS:
                    raise ValueError('Nickname attempts exhausted or repeated')
                history.append(name)
            assignment['create_nickname'] = name
            db.execute('UPDATE accounts SET assignment=? WHERE id=?', (json.dumps(assignment), identifier))
            db.execute('INSERT INTO creation_names VALUES(?,?,?,?) ON CONFLICT(account_id,region,server_id) DO UPDATE SET data=excluded.data',
                (identifier, region, server_id, json.dumps(history)))
            return name

    def mail_credential(self, identifier):
        with self._db() as db:
            row = db.execute('SELECT mail_password FROM accounts WHERE id=?', (identifier,)).fetchone()
        if row is None or row[0] is None:
            raise ValueError('Save the mailbox password before registration')
        return self.vault.decrypt(row[0])

    def registration_status(self, identifier, state):
        if state not in ('in_progress', 'unconfirmed', 'registered', 'email_in_use', 'nid_verified', 'sdk_created'):
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

    def save_characters(self, identifier, *, region, server_id, characters, observed_utc):
        self.assignment(dict(region=region, server_id=server_id))
        if server_id is None or type(characters) is not list or len(characters) > 4096:
            raise ValueError('Invalid character list')
        if type(observed_utc) is not str or len(observed_utc) > 50 or datetime.fromisoformat(observed_utc).utcoffset() is None:
            raise ValueError('Invalid character observation time')
        keys = set()
        for index, row in enumerate(characters):
            if type(row) is not dict or set(row) != {'index', 'key', 'name'} or type(row['index']) is not int or row['index'] != index:
                raise ValueError('Invalid character record')
            self.assignment(dict(region=region, server_id=server_id, character_index=index, character_key=row['key']))
            if row['key'] is None or row['key'] in keys:
                raise ValueError('Ambiguous character key')
            keys.add(row['key'])
            if type(row['name']) is not str or len(row['name']) > 512 or any(ord(c) < 32 for c in row['name']):
                raise ValueError('Invalid character label')
        data = json.dumps(dict(characters=characters, observed_utc=observed_utc), ensure_ascii=False)
        if len(data.encode('utf-8')) > 262144:
            raise ValueError('Character list exceeds budget')
        with self._db() as db:
            if db.execute('SELECT 1 FROM accounts WHERE id=?', (identifier,)).fetchone() is None:
                raise KeyError('Unknown account')
            db.execute('INSERT INTO character_lists VALUES(?,?,?,?) ON CONFLICT(account_id,region,server_id) DO UPDATE SET data=excluded.data',
                (identifier, region, server_id, data))

    def character_lists(self):
        with self._db() as db:
            return {f'{identifier}|{region}|{server}': json.loads(data)
                for identifier, region, server, data in db.execute('SELECT account_id,region,server_id,data FROM character_lists')}

    def begin_creation(self, identifier, *, region, server_id, nickname, source_sha256):
        from .creation_journal import begin
        return begin(self, identifier, region, server_id, nickname, source_sha256)

    def finish_creation(self, attempt_id, *, state, result_code=None, key=None, name=None):
        from .creation_journal import finish
        return finish(self, attempt_id, state, result_code, key, name)

    def reconcile_creation(self, identifier, *, region, server_id):
        from .creation_journal import reconcile
        return reconcile(self, identifier, region, server_id)

    def creation_attempts(self):
        with self._db() as db:
            return [dict(attempt_id=i, account_id=a, region=r, server_id=s, **json.loads(data))
                for i, a, r, s, data in db.execute('SELECT attempt_id,account_id,region,server_id,data FROM creation_attempts ORDER BY rowid')]
