"""The source-check dispatcher binds this SDK matrix to its explicit client SHA."""
import importlib.util
import json
import os
from pathlib import Path
import re
import unittest


HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


class CurrentSdkBatchTests(unittest.TestCase):
    def test_target_native_components_and_candidate(self):
        expected = os.environ.get('PHONEEXIT_VAMPIR_SDK_CHECK_SOURCE_SHA256', '')
        self.assertRegex(expected, re.compile('^[0-9a-f]{64}$'))
        context = json.loads((HERE / 'knowledge/sdk-batch-runtime-current.json').read_bytes())
        self.assertEqual(context['source_sha256'], expected)
        exports = HERE / 'verify-sdk-batch-exports.py'
        spec = importlib.util.spec_from_file_location('current_sdk_export_guard', exports)
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        generation = json.loads(Path(context['generation']['path']).read_bytes())
        self.assertEqual(guard.verify(Path('F:/PhoneExit Resources/Vampir'), generation)['roots'], 34)
        path = HERE / 'sdk-batch-runner.py'
        spec = importlib.util.spec_from_file_location('current_sdk_batch', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _, report, _ = module.run(Path('F:/PhoneExit Resources/Vampir'), Path(context['generation']['path']))
        self.assertEqual(report['source_sha256'], expected)
        self.assertEqual(report['native_case_executions'], 3667)
        self.assertEqual(report['primitive_cases'], {'numeric': 112, 'channels': 176})
        self.assertEqual(set(report['component_reports']), {
            'defaults', 'override', 'platform', 'start', 'url', 'headers', 'geo', 'nid_base', 'nid_helpers',
        })
        self.assertEqual(report['profile_candidate']['public_gmc2']['profile']['game_code'], 'thered')
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])
