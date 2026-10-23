import importlib.util
from pathlib import Path
import unittest
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))


class ReleaseLobbyErrorsTests(unittest.TestCase):
    def tool(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-lobby-errors.py'
        spec = importlib.util.spec_from_file_location('release_lobby_errors_test', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_whole_mapper_current_labels(self):
        report = self.tool().replay()
        self.assertEqual({r['code']: r['key'] for r in report['cases']},
                         {0: 'Success', 10036: 'IsInspect', 10048: 'BlockedInfo', 1: '', 0xffffffff: ''})
        self.assertEqual(report['network_requests'], 0)
        self.assertTrue(all(r['trace'] for r in report['cases']))
        from vampir_core.lobby_login_error import describe_lobby_login_error
        for row in report['cases']:
            if row['code'] in (10036, 10048):
                self.assertEqual(describe_lobby_login_error(row['code'])[0], row['key'])

    def test_corrupt_source_stops(self):
        read = Path.read_bytes
        def corrupt(path):
            data = read(path)
            return data + b' ' if path.name == 'ProjectRED-Win64-Shipping.exe' else data
        with patch.object(Path, 'read_bytes', corrupt):
            with self.assertRaisesRegex(ValueError, 'Lobby source SHA changed'):
                self.tool().replay()


if __name__ == '__main__': unittest.main()
