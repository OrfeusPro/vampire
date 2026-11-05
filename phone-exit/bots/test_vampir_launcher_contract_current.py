"""Source-bound Launcher contract on the explicitly registered current variant."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'
CONTEXT = HERE / 'knowledge/native-contexts/launcher-contract-11322.json'


class CurrentLauncherContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('current_launcher_contract', HERE / 'audit-launcher-contract.py')
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.context = json.loads(CONTEXT.read_bytes())

    def test_current_source_keys_requests_and_responses(self):
        checks = json.loads((HERE / 'knowledge/research-checks.json').read_bytes())['checks']
        check = next(row for row in checks if row['id'] == 'release-launcher-contract')
        sources = [sha for sha, variant in check['source_variants'].items()
                   if variant['test_pattern'] == Path(__file__).name]
        self.assertEqual(sources, [self.context['target']['source_sha256']])
        report = self.tool.audit(self.context, Path('F:/PhoneExit Resources/Vampir'))
        self.assertEqual(report['source_sha256'], sources[0])
        self.assertEqual(len(report['keys']), 10)
        self.assertEqual(len(report['functions']), 14)
        self.assertEqual({row['endpoint'] for row in report['requests']}, {'launcher/token', 'launcher/sign-in'})
        self.assertEqual(len(report['unresolved_dependencies']), 14)
        self.assertFalse(report['native_execution'])
        self.assertFalse(report['runtime_admitted'])

    def test_corrupt_source_rejects_before_native_decode(self):
        with patch.object(Path, 'read_bytes', return_value=b'changed'):
            with self.assertRaisesRegex(ValueError, 'source or export SHA changed'):
                self.tool.audit(self.context, Path('F:/PhoneExit Resources/Vampir'))

    def test_missing_key_rejects(self):
        target = dict(self.context['target'], keys={})
        context = dict(self.context, target=target)
        native = self.tool.load('build-native-entry-code')
        with self.assertRaisesRegex(ValueError, 'key or route set'):
            self.tool.read_release(native, None, Path('unused'), context['target'])
