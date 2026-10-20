import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'


def tool():
    spec = importlib.util.spec_from_file_location('function_registry_test', HERE / 'function-registry.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FunctionRegistryTests(unittest.TestCase):
    def test_historical_inventory_retains_roles_calls_and_navigation(self):
        module = tool()
        # Real exported old evidence must remain searchable after an installed update.
        sha = json.loads((module.ROOT / 'ghidra/latest-export.json').read_text('utf-8'))['source_sha256']
        snapshot = module.ROOT / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
        saved = module.build(snapshot)
        self.assertEqual(saved['source_scope'], 'historical')
        self.assertEqual(saved['source'], str(snapshot))
        self.assertEqual(len({r['address'] for r in saved['functions']}), saved['function_count'])
        direct = module.query(saved, '14453cdf0')
        self.assertEqual(direct, module.query(saved, '0x14453cdf0'))
        self.assertEqual(direct[0]['established_role']['role'], 'UNMServiceSettings::Save')
        self.assertIn('common-data-population', direct[0]['questions'])
        self.assertTrue(any('HEADLESS-NID-CREDENTIAL.md' in r['path'] for r in direct[0]['references']))
        self.assertTrue(module.query(saved, 'SendSignIn'))
        launcher = module.query(saved, '1444eb1c0')[0]
        self.assertIn('auth', launcher['navigation_topics'])
        self.assertIn('launcher-auth-contract', launcher['questions'])
        self.assertTrue(any('HEADLESS-LAUNCHER-AUTH-CONTEXT.md' in r['path'] for r in launcher['references']))
        self.assertEqual(module.query(saved, '0x1ffffffff'), [])
        self.assertEqual(module.query(saved, '0x140000000')[0]['address_kind'],
                         'documented_address_type_unverified')
        external = next(row for row in saved['documented_addresses'] if row['references'])
        self.assertEqual(module.query(saved, external['address']), [external])
        self.assertEqual(external['address_kind'], 'documented_address_type_unverified')
        self.assertIsNone(external['established_role'])

    def test_snapshot_requires_exact_source_hash_and_default_guard_remains(self):
        module = tool()
        with tempfile.TemporaryDirectory() as directory:
            old, installed = Path(directory) / 'old.exe', Path(directory) / 'installed.exe'
            old.write_bytes(b'old verified fixture')
            installed.write_bytes(b'new incompatible fixture')
            expected = module.digest(old)
            with self.assertRaisesRegex(ValueError, 'Installed client changed'):
                module.checked_source(installed, expected)
            self.assertEqual(module.checked_source(installed, expected, old), old)
            with self.assertRaisesRegex(ValueError, 'Source digest mismatch'):
                module.checked_source(old, expected, installed)

    def test_stale_evidence_is_rejected_instead_of_reusing_old_claims(self):
        module = tool()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, source = root / 'evidence.txt', root / 'client.exe'
            evidence.write_text('first result', encoding='utf-8')
            source.write_bytes(b'fake source fixture')
            module.OUTPUT = root / 'registry.json'
            module.documents = lambda: []
            module.OUTPUT.write_text(json.dumps(dict(inputs={str(evidence): module.digest(evidence)},
                source=str(source), source_sha256=module.digest(source))), encoding='utf-8')
            module.read_current()
            evidence.write_text('corrected result', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'Registry stale'):
                module.read_current()


if __name__ == '__main__':
    unittest.main()
