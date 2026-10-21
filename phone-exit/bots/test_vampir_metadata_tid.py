from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.metadata_tid import SOURCE_SHA256, format_guid_words, resolve_metadata_tid


class MetadataTidTests(unittest.TestCase):
    def test_format_matches_actual_current_native_formatter(self):
        root = Path(__file__).resolve().parents[2]
        run = subprocess.run([sys.executable, '-X', 'utf8', str(root / 'phone-exit/bots/resource-tools/vampir/replay-release-guid-format.py')],
            cwd=root, capture_output=True, text=True, encoding='utf-8', check=True)
        report = json.loads(Path(json.loads(run.stdout)['report']).read_text('utf-8'))
        self.assertEqual(len(report['cases']), 4)
        for case in report['cases']:
            self.assertEqual(format_guid_words(struct.pack('<IIII', *case['words'])), case['formatted'])

    def test_reopen_reuses_value_and_another_scope_has_separate_state(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'metadata.sqlite3'
            generate = Mock(side_effect=[bytes(range(16)), bytes(range(1, 17))])
            def resolve(scope):
                return resolve_metadata_tid(path, nm_device_key=scope, source_sha256=SOURCE_SHA256, _generate=generate)
            first = resolve('device-fixture')
            self.assertEqual(first, resolve('device-fixture'))
            self.assertNotEqual(first, resolve('another-device-fixture'))
            self.assertEqual(generate.call_count, 2)
            with closing(sqlite3.connect(path)) as db:
                with db: db.execute("UPDATE metadata_tid SET value='bad-state'")
            with self.assertRaises(ValueError): resolve('device-fixture')
            self.assertEqual(generate.call_count, 2)

    def test_unverified_source_cannot_create_state(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'metadata.sqlite3'
            generate = Mock()
            with self.assertRaises(ValueError):
                resolve_metadata_tid(path, nm_device_key='fixture', source_sha256='old', _generate=generate)
            generate.assert_not_called()
            self.assertFalse(path.exists())

    def test_concurrent_first_use_creates_only_one_value(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'metadata.sqlite3'
            generate = Mock(return_value=bytes(range(16)))
            def resolve(_):
                return resolve_metadata_tid(path, nm_device_key='fixture', source_sha256=SOURCE_SHA256, _generate=generate)
            with ThreadPoolExecutor(max_workers=2) as workers:
                values = list(workers.map(resolve, range(2)))
            self.assertEqual(values[0], values[1])
            generate.assert_called_once()


if __name__ == '__main__': unittest.main()
