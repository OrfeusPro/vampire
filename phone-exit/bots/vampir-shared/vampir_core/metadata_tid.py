"""Persistent bot-owned I_TID; current source policy and GUID word format.

The bot keeps its own settings rather than modifying the installed game's
SaveGame. This is not an observation of the game's existing TID or a credential.
"""
import hashlib
from pathlib import Path
import sqlite3
import struct
import sys

SOURCE_SHA256 = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'


def format_guid_words(data):
    if type(data) is not bytes or len(data) != 16:
        raise ValueError('Expected 16 native GUID bytes')
    return ''.join(f'{word:08X}' for word in struct.unpack('<IIII', data))


def _generate_windows_guid():
    if sys.platform != 'win32': raise RuntimeError('Windows GUID provider is unavailable')
    import ctypes
    data = (ctypes.c_ubyte * 16)()
    function = ctypes.WinDLL('ole32').CoCreateGuid
    function.argtypes = [ctypes.POINTER(ctypes.c_ubyte * 16)]
    function.restype = ctypes.c_long
    if function(ctypes.byref(data)) < 0: raise OSError('Windows GUID creation failed')
    return bytes(data)


def resolve_metadata_tid(path, *, nm_device_key, source_sha256, _generate=None):
    """Create once per observed device/game scope, reuse, reject corrupt state.

    SQL storage is a local runtime policy. No game files or registry values
    change. A newly created value is not claimed equal to the official client.
    """
    if source_sha256 != SOURCE_SHA256:
        raise ValueError('Metadata TID policy is not verified for this source')
    if type(nm_device_key) is not str or not 1 <= len(nm_device_key) <= 8192:
        raise ValueError('Expected observed device scope')
    scope = hashlib.sha256(('thered\0' + nm_device_key).encode('utf-8')).hexdigest()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        db = sqlite3.connect(path, timeout=5)
    except sqlite3.Error:
        raise ValueError('Metadata TID state is unavailable') from None
    try:
        with db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS metadata_tid (scope TEXT PRIMARY KEY, value TEXT NOT NULL)')
            row = db.execute('SELECT value FROM metadata_tid WHERE scope=?', (scope,)).fetchone()
            if row is None:
                value = format_guid_words((_generate or _generate_windows_guid)())
                if value == '0' * 32: raise ValueError('Empty generated metadata TID')
                db.execute('INSERT INTO metadata_tid(scope,value) VALUES(?,?)', (scope, value))
            else:
                value = row[0]
            if type(value) is not str or len(value) != 32 or any(c not in '0123456789ABCDEF' for c in value) or value == '0' * 32:
                raise ValueError('Stored metadata TID is invalid; explicit repair required')
            return value
    except sqlite3.Error:
        raise ValueError('Metadata TID state is unavailable') from None
    finally:
        db.close()
