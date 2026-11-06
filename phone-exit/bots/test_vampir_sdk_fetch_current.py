"""Current source Fetch-only subset, with explicit static/native boundaries."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch

HERE = Path(__file__).parent / 'resource-tools/vampir'
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/sdk-fetch-current.json'


class CurrentSdkFetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('sdk_fetch_current_inspector', HERE / 'inspect-sdk-fetch-current.py')
        cls.tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.tool)
        cls.context = json.loads(CONTEXT.read_bytes())

    def test_whole_request_response_and_explicit_arguments_match_current_source(self):
        report = self.tool.audit(self.context, ROOT)
        self.assertTrue(report['contract_subset_verified'])
        self.assertEqual([f['instruction_count'] for f in report['functions']], [621, 667])
        self.assertEqual(report['contract']['endpoint'], 'v1/fetch-player')
        self.assertEqual(report['contract']['payload_keys'], ['credential', 'scope'])
        self.assertFalse(report['contract']['device_fields_in_body'])
        self.assertEqual(report['scope_initializer']['coverage'], 'explicit_fragment')
        self.assertFalse(report['scope_initializer']['whole_function_export'])
        self.assertEqual(report['closure']['blockers'], [])
        self.assertTrue(report['closure']['native_wide_unknowns'])
        self.assertFalse(report['native_execution'])
        self.assertFalse(report['runtime_admitted'])
        self.assertFalse(report['network_used'])

    def test_changed_source_or_evidence_fails_before_any_contract_claim(self):
        with patch.object(Path, 'read_bytes', return_value=b'corrupt-source-fixture'):
            with self.assertRaisesRegex(ValueError, 'SHA changed'):
                self.tool.audit(self.context, ROOT)

    def test_scope_fragment_rejects_changed_bytes_without_claiming_crt_execution(self):
        native = self.tool.load('build-native-entry-code')
        shared = self.tool.load('audit-launcher-contract')
        spec = deepcopy(self.context['scope_initializer'])
        original = bytes.fromhex(spec['bytes'])
        with patch.object(shared, 'data', return_value=b'X' + original[1:]):
            with self.assertRaisesRegex(ValueError, 'fragment differs'):
                self.tool.verify_fragment(native, shared, object(), spec)

    def test_report_verifier_rejects_unpinned_context_before_rebuilding(self):
        import hashlib
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            raw = b'{"context": {}, "inputs": {}}'
            digest = hashlib.sha256(raw).hexdigest()
            report = root / 'code-clues/sdk-fetch-current-static-v1' / digest / 'manifest.json'
            report.parent.mkdir(parents=True); report.write_bytes(raw)
            with patch.object(self.tool, 'build_report') as rebuild:
                with self.assertRaisesRegex(ValueError, 'context pointer differs'):
                    self.tool.verify_report(report, root=root)
                rebuild.assert_not_called()


if __name__ == '__main__': unittest.main()
