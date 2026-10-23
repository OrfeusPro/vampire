"""Durable per-account creation attempt; contains no authentication secrets."""
from datetime import datetime, timezone
import json
import uuid

from .world_move_start import SOURCE_SHA256


def now(): return datetime.now(timezone.utc).isoformat()


def begin(store, identifier, region, server_id, nickname, source_sha256):
    if source_sha256 != SOURCE_SHA256 or type(nickname) is not str or not nickname or len(nickname) > 40:
        raise ValueError('Invalid creation journal request')
    with store._db() as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT assignment FROM accounts WHERE id=?', (identifier,)).fetchone()
        if row is None: raise KeyError('Unknown account')
        assignment = store.assignment(json.loads(row[0]))
        if (not assignment['enabled'] or (assignment['region'], assignment['server_id']) != (region, server_id)
                or server_id is None or assignment['create_class'] != 'Gunner'
                or assignment['create_nickname'] != nickname or assignment['character_index'] is not None
                or assignment['character_key'] is not None):
            raise ValueError('Creation assignment changed or is unsupported')
        listing = db.execute('SELECT data FROM character_lists WHERE account_id=? AND region=? AND server_id=?',
            (identifier, region, server_id)).fetchone()
        if listing is None or json.loads(listing[0])['characters']:
            raise ValueError('Accepted empty list is required before journaling')
        latest = db.execute('SELECT data FROM creation_attempts WHERE account_id=? AND region=? AND server_id=? ORDER BY rowid DESC LIMIT 1',
            (identifier, region, server_id)).fetchone()
        if latest and json.loads(latest[0])['state'] != 'empty_verified':
            raise RuntimeError('Read characters separately before another creation attempt')
        token = str(uuid.uuid4())
        data = dict(state='pending', nickname=nickname, source_sha256=source_sha256,
            observed_utc=json.loads(listing[0])['observed_utc'], updated_utc=now())
        db.execute('INSERT INTO creation_attempts VALUES(?,?,?,?,?)',
            (token, identifier, region, server_id, json.dumps(data)))
        return token


def finish(store, token, state, code, key, name):
    if state not in ('created', 'rejected', 'unknown', 'needs_refresh', 'not_queued'):
        raise ValueError('Invalid creation terminal state')
    if code is not None and (type(code) is not int or not 0 <= code <= 0xffffffff):
        raise ValueError('Invalid creation code')
    if (state == 'rejected' and code in (None, 0)) or (state == 'needs_refresh' and code != 0):
        raise ValueError('Creation terminal state requires its result code')
    if state == 'created':
        if code != 0 or type(key) is not str or len(key) > 20 or not key.isascii() or not key.isdigit() or not 0 < int(key) <= 0xffffffffffffffff:
            raise ValueError('Created character key missing')
        if type(name) is not str or not name or len(name) > 512 or any(ord(c) < 32 for c in name):
            raise ValueError('Created character name missing')
    elif key is not None or name is not None:
        raise ValueError('Only confirmed creation may retain identity')
    with store._db() as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT account_id,region,server_id,data FROM creation_attempts WHERE attempt_id=?', (token,)).fetchone()
        if row is None: raise KeyError('Unknown creation attempt')
        identifier, region, server, raw = row; data = json.loads(raw)
        if data['state'] != 'pending': return False  # Terminal results are immutable to late cleanup.
        data.update(state=state, result_code=code, updated_utc=now())
        if state == 'created': data.update(character_key=key, character_name=name)
        db.execute('UPDATE creation_attempts SET data=? WHERE attempt_id=?', (json.dumps(data), token))
        return True


def reconcile(store, identifier, region, server_id):
    """Only a separate, accepted list operation resolves a persisted attempt."""
    with store._db() as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT attempt_id,data FROM creation_attempts WHERE account_id=? AND region=? AND server_id=? ORDER BY rowid DESC LIMIT 1',
            (identifier, region, server_id)).fetchone()
        if row is None: return None
        listing = db.execute('SELECT data FROM character_lists WHERE account_id=? AND region=? AND server_id=?',
            (identifier, region, server_id)).fetchone()
        if listing is None: raise ValueError('Fresh accepted list is required')
        data, listing = json.loads(row[1]), json.loads(listing[0])
        if datetime.fromisoformat(listing['observed_utc']) <= datetime.fromisoformat(data['updated_utc']):
            raise ValueError('Character list predates the creation attempt')
        if data.get('character_key'):
            matches = [r for r in listing['characters'] if r['key'] == data['character_key']]
            account = db.execute('SELECT assignment FROM accounts WHERE id=?', (identifier,)).fetchone()
            assignment = store.assignment(json.loads(account[0])) if account else None
            if (len(matches) == 1 and assignment is not None
                    and (assignment['region'], assignment['server_id']) == (region, server_id)
                    and assignment['character_index'] is None and assignment['character_key'] is None):
                assignment.update(character_index=matches[0]['index'], character_key=matches[0]['key'])
                db.execute('UPDATE accounts SET assignment=? WHERE id=?', (json.dumps(assignment), identifier))
        data.update(state='existing_verified' if listing['characters'] else 'empty_verified', updated_utc=now())
        db.execute('UPDATE creation_attempts SET data=? WHERE attempt_id=?', (json.dumps(data), row[0]))
        return data['state']
