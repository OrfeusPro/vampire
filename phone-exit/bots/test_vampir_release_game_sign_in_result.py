"""Native callback branches with synthetic response fields; no authorization."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


class ReleaseGameSignInResultTests(unittest.TestCase):
    def tool(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-game-sign-in-result.py'
        spec = importlib.util.spec_from_file_location('release_game_signin_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        return tool

    def test_whole_callback_and_owner_lifetime(self):
        result = self.tool().replay()
        self.assertEqual(len(result['cases']), 67)
        self.assertEqual(len(result['route']), 5)
        self.assertEqual(result['network_requests'], 0)
        cases = [c for c in result['cases'] if c.get('step') in (14, 15)]
        ordinary = [c for c in cases if c['field_4'] == 1 and c['field_28'] == 1203]
        self.assertEqual(len(ordinary), 8)
        self.assertTrue(all([e['kind'] for e in c['events']] == ['log', 'error_text', 'message'] for c in ordinary))
        self.assertEqual({e['selector'] for c in ordinary for e in c['events'] if e['kind'] == 'message'}, {7, 8})
        self.assertTrue(all(c['owner_count'] == 4 for c in result['cases'] if 'step' in c))
        self.assertEqual({c['owner_gate'] for c in result['cases'] if 'owner_gate' in c}, {'no-control', 'expired', 'no-owner'})

    def test_modified_export_rejected(self):
        read = Path.read_bytes
        def changed(path):
            payload = read(path)
            return payload + b' ' if path.parent.name == 'run-6092fea5749a' else payload
        with patch.object(Path, 'read_bytes', changed):
            with self.assertRaisesRegex(ValueError, 'export changed'):
                self.tool().replay()


if __name__ == '__main__': unittest.main()
