"""Current whole launcher source contract; offline guards only."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


class LauncherContractTests(unittest.TestCase):
    def tool(self):
        path=Path(__file__).parent/'resource-tools/vampir/audit-launcher-contract-11318.py'
        spec=importlib.util.spec_from_file_location('launcher_contract_11318',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_whole_current_requests_keys_and_responses(self):
        tool=self.tool();report=tool.audit()
        self.assertEqual(report['source_sha256'],tool.SHA)
        self.assertEqual(report['network_requests'],0)
        self.assertEqual(len(report['functions']),14)
        self.assertEqual(len(report['keys']),10)
        self.assertEqual({r['endpoint'] for r in report['requests']},
                         {'launcher/token','launcher/sign-in'})
        self.assertEqual({r['callback_root'] for r in report['requests']},
                         {'0x1444cc4b0','0x1444d3a30'})
        self.assertTrue(all(r['instruction_count'] for r in report['functions']))

    def test_changed_source_rejects_before_decode(self):
        with patch.object(Path,'read_bytes',return_value=b'changed'):
            with self.assertRaisesRegex(ValueError,'source SHA changed'):self.tool().audit()

    def test_changed_export_rejects(self):
        original=Path.read_bytes
        def changed(path):
            raw=original(path)
            return raw+b' ' if path.name=='details.json' else raw
        with patch.object(Path,'read_bytes',changed):
            with self.assertRaisesRegex(ValueError,'export SHA changed'):self.tool().audit()

    def test_missing_root_is_not_accepted(self):
        tool=self.tool();original=tool.REQUESTS
        tool.REQUESTS=(original[0],)
        with self.assertRaisesRegex(ValueError,'whole root missing'):tool.audit()


if __name__=='__main__':unittest.main()
