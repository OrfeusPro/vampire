"""Static release audit rejects changed sources; never performs authorization."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


class ReleaseLauncherContractTests(unittest.TestCase):
    def tool(self):
        path = Path(__file__).parent / 'resource-tools/vampir/audit-release-launcher-contract.py'
        spec = importlib.util.spec_from_file_location('release_launcher_contract_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        return tool

    def test_current_source_and_request_response_boundaries(self):
        result = self.tool().audit()
        self.assertEqual(result['method'], 'static')
        self.assertEqual(result['network_requests'], 0)
        self.assertEqual(len(result['functions']), 7)
        self.assertEqual({r['key'] for r in result['keys']}, {'gameCode', 'buildCode', 'launcherToken'})
        self.assertEqual({r['endpoint'] for r in result['requests']}, {'launcher/token', 'launcher/sign-in'})
        self.assertEqual({r['callback_root'] for r in result['requests']}, {'0x1444cd020', '0x1444d45a0'})
        self.assertTrue(all(not r['direct_sign_up_reference'] for r in result['responses']))
        self.assertTrue(all(r['instruction_count'] > 0 for r in result['functions']))

    def test_changed_exe_rejected_before_decode(self):
        with patch.object(Path, 'read_bytes', return_value=b'changed executable'):
            with self.assertRaisesRegex(ValueError, 'source SHA changed'):
                self.tool().audit()

    def test_changed_export_rejected(self):
        read = Path.read_bytes
        def changed(path):
            raw = read(path)
            return raw + b' ' if path.name == 'details.json' else raw
        with patch.object(Path, 'read_bytes', changed):
            with self.assertRaisesRegex(ValueError, 'export SHA changed'):
                self.tool().audit()


if __name__ == '__main__': unittest.main()
