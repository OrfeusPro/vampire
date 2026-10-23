import importlib.util
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('local_backup', Path(__file__).parent / 'vampir-headless/backup-local-data.py')
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class LocalBackupTests(unittest.TestCase):
    def test_live_wal_snapshot_and_corruption_preserves_source_and_previous_backup(self):
        with tempfile.TemporaryDirectory() as folder:
            local = Path(folder) / 'local'; local.mkdir()
            source = local / 'console.sqlite3'
            with closing(sqlite3.connect(source)) as db:
                db.execute('PRAGMA journal_mode=WAL')
                db.execute('CREATE TABLE fixture(value BLOB)')
                db.execute('INSERT INTO fixture VALUES(?)', (b'protected-fixture',)); db.commit()
                first = TOOL.create(local, Path(folder) / 'backups')
                with closing(sqlite3.connect(first / source.name)) as copy:
                    self.assertEqual(copy.execute('SELECT value FROM fixture').fetchone(), (b'protected-fixture',))
                second = TOOL.create(local, Path(folder) / 'backups')
                self.assertNotEqual(first, second)
                (second / source.name).write_bytes(b'broken')
                with self.assertRaises(ValueError): TOOL.verify(second)
                self.assertEqual(len(TOOL.verify(first)['databases']), 1)
                self.assertEqual(db.execute('SELECT count(*) FROM fixture').fetchone()[0], 1)

    def test_missing_or_invalid_source_does_not_publish_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            local = Path(folder) / 'local'; local.mkdir()
            destination = Path(folder) / 'backups'
            with self.assertRaises(ValueError): TOOL.create(local, destination)
            (local / 'console.sqlite3').write_bytes(b'broken')
            with self.assertRaises(sqlite3.DatabaseError): TOOL.create(local, destination)
            self.assertEqual(list(destination.iterdir()), [])
            with self.assertRaises(ValueError): TOOL.create(local, local / 'backup')


if __name__ == '__main__':
    unittest.main()
