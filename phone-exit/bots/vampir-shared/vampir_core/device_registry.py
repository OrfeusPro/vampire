"""Local account/device registry. No network, credentials or identity generation."""
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
import sqlite3
import uuid


@dataclass(frozen=True)
class DeviceBinding:
    email: str = field(repr=False)
    profile_id: str
    kind: str
    is_main: bool
    device_key: str = field(repr=False)
    nm_device_key: str = field(repr=False)
    identity_source: str = field(repr=False)
    confirmation: str
    confirmation_evidence: str = field(repr=False)
    nid_device_key: str = field(default='', repr=False)
    nid_identity_source: str = field(default='', repr=False)

    @property
    def identity_recorded(self):
        return bool(self.device_key and self.nm_device_key and self.identity_source)

    @property
    def nid_identity_recorded(self):
        return bool(self.nid_device_key and self.nid_identity_source)


def _text(value, limit=8192):
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ValueError('Expected bounded nonempty text')
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Control characters are forbidden')
    return value


def _email(value):
    value = _text(value, 254).strip().lower()
    if value.count('@') != 1 or any(c.isspace() for c in value):
        raise ValueError('Invalid email address')
    local, domain = value.split('@')
    if not local or not domain or '.' not in domain:
        raise ValueError('Invalid email address')
    return value


class DeviceRegistry:
    """One stable profile per email; identity replacement needs a future transfer flow.

    SQLite is local plaintext, not a secret vault. Never store passwords, tokens,
    confirmation codes or message contents here. Callers must protect the directory.
    """

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            version = db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0, 1, 2):
                raise ValueError('Unsupported device registry version')
            db.execute('''CREATE TABLE IF NOT EXISTS bindings (
                email TEXT PRIMARY KEY COLLATE NOCASE,
                profile_id TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL CHECK(kind IN ('real', 'planned')),
                is_main INTEGER NOT NULL CHECK(is_main IN (0,1)),
                device_key TEXT NOT NULL DEFAULT '',
                nm_device_key TEXT NOT NULL DEFAULT '',
                identity_source TEXT NOT NULL DEFAULT '',
                confirmation TEXT NOT NULL DEFAULT 'unknown'
                    CHECK(confirmation IN ('unknown','required','confirmed')),
                confirmation_evidence TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )''')
            db.execute('CREATE UNIQUE INDEX IF NOT EXISTS one_main ON bindings(is_main) WHERE is_main=1')
            if version < 2:
                db.execute("ALTER TABLE bindings ADD COLUMN nid_device_key TEXT NOT NULL DEFAULT ''")
                db.execute("ALTER TABLE bindings ADD COLUMN nid_identity_source TEXT NOT NULL DEFAULT ''")
            db.execute('PRAGMA user_version=2')

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def register(self, email, *, kind='planned', is_main=False):
        email = _email(email)
        if kind not in ('real', 'planned') or type(is_main) is not bool:
            raise ValueError('Invalid profile kind or main flag')
        with self._db() as db:
            existing = db.execute('SELECT kind,is_main FROM bindings WHERE email=?', (email,)).fetchone()
            if existing:
                if existing != (kind, int(is_main)):
                    raise ValueError('Existing binding cannot be silently replaced')
            else:
                # UUID is a local registry ID, never a game/device fingerprint.
                db.execute('INSERT INTO bindings(email,profile_id,kind,is_main) VALUES(?,?,?,?)',
                           (email, str(uuid.uuid4()), kind, int(is_main)))
        return self.get(email)

    def get(self, email):
        with self._db() as db:
            row = db.execute('''SELECT email,profile_id,kind,is_main,device_key,
                nm_device_key,identity_source,confirmation,confirmation_evidence,
                nid_device_key,nid_identity_source
                FROM bindings WHERE email=?''', (_email(email),)).fetchone()
        if row is None:
            raise KeyError('Account is not registered')
        return DeviceBinding(*row[:3], bool(row[3]), *row[4:])

    def record_real_identity(self, email, *, device_key, nm_device_key, source):
        values = tuple(_text(v) for v in (device_key, nm_device_key, source))
        email = _email(email)
        with self._db() as db:
            row = db.execute('SELECT kind,device_key,nm_device_key,identity_source FROM bindings WHERE email=?', (email,)).fetchone()
            if row is None:
                raise KeyError('Account is not registered')
            if row[0] != 'real':
                raise ValueError('Only a real device profile accepts observed identity')
            if any(row[1:]) and row[1:] != values:
                raise ValueError('Identity is already fixed; explicit transfer is required')
            db.execute('''UPDATE bindings SET device_key=?,nm_device_key=?,identity_source=?,
                updated_at=CURRENT_TIMESTAMP WHERE email=?''', (*values, email))
        return self.get(email)

    def record_real_nid_identity(self, email, *, nid_device_key, source):
        """Record observed NID identity independently of SDK sign-in deviceKey."""
        values = tuple(_text(v) for v in (nid_device_key, source))
        email = _email(email)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT kind,nid_device_key,nid_identity_source FROM bindings WHERE email=?', (email,)).fetchone()
            if row is None:
                raise KeyError('Account is not registered')
            if row[0] != 'real':
                raise ValueError('Only a real device profile accepts observed NID identity')
            if any(row[1:]) and row[1:] != values:
                raise ValueError('NID identity is already fixed; explicit transfer is required')
            if not any(row[1:]):
                db.execute('''UPDATE bindings SET nid_device_key=?,nid_identity_source=?,
                    confirmation=CASE WHEN confirmation='confirmed' THEN 'unknown' ELSE confirmation END,
                    confirmation_evidence='',updated_at=CURRENT_TIMESTAMP WHERE email=?''', (*values, email))
        return self.get(email)

    def require_confirmation(self, email):
        return self._confirmation(email, 'required', '')

    def record_confirmation(self, email, *, evidence):
        return self._confirmation(email, 'confirmed', _text(evidence, 1024))

    def _confirmation(self, email, state, evidence):
        email = _email(email)
        with self._db() as db:
            row = db.execute('SELECT device_key,nm_device_key,identity_source FROM bindings WHERE email=?', (email,)).fetchone()
            if row is None:
                raise KeyError('Account is not registered')
            if state == 'confirmed' and not all(row):
                raise ValueError('Record the observed identity before confirmation')
            db.execute('''UPDATE bindings SET confirmation=?,confirmation_evidence=?,
                updated_at=CURRENT_TIMESTAMP WHERE email=?''', (state, evidence, email))
        return self.get(email)
