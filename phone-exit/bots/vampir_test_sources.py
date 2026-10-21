"""Explicit historical EXE fixture for tests of immutable old profile receipts.

Only one old source path is redirected, only inside the test scope. The saved
EXE must match the full historical SHA; production source guards stay intact.
"""
from contextlib import contextmanager
import hashlib
from pathlib import Path
from unittest.mock import patch


@contextmanager
def historical_exe_reads(source, sha256):
    snapshot = Path('F:/PhoneExit Resources/Vampir/client-code-snapshots') / sha256 / 'ProjectRED-Win64-Shipping.exe'
    original = Path.read_bytes
    raw = original(snapshot)
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError('Historical test EXE differs from the profile SHA')
    target = Path(source).resolve()
    def read(path):
        return raw if path.resolve() == target else original(path)
    with patch.object(Path, 'read_bytes', read):
        yield
