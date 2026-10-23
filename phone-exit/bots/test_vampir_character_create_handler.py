"""Native response handling and portable no-retry identity decisions."""
from dataclasses import replace
import importlib.util
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.character_create_result import CharacterCreateResult, character_creation_outcome, SOURCE_SHA256
from vampir_core.character_list import CharacterRecord


class CharacterCreateHandlerTests(unittest.TestCase):
    def test_whole_native_handler(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-character-create-handler.py'
        spec = importlib.util.spec_from_file_location('create_handler_test', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        _, report = module.run()
        self.assertEqual(len(report['cases']), 128)
        self.assertEqual(len(report['errors']), 30)
        for case in report['cases']:
            self.assertEqual(case['events'].count('record'), 1)
            self.assertTrue(case['packet_unchanged'])
            self.assertEqual('name_match' in case['events'], case['name_match'])
        self.assertEqual(sum(c['null_ui_fault'] for c in report['errors']), 12)
        self.assertEqual(sum(c['wait_cleared'] for c in report['errors']), 3)

    def test_outcome_uses_code_and_returned_identity_without_retry(self):
        record = CharacterRecord(('ServerName', '', ''), (0, 0), (), (123,), 0, (), (), (), None, False)
        result = CharacterCreateResult(0, record)
        def decide(value=result, sha=SOURCE_SHA256, requested='Requested'):
            return character_creation_outcome(value, source_sha256=sha, requested_name=requested)
        created = decide()
        self.assertEqual((created.status, created.character_key, created.character_name), ('created', 123, 'ServerName'))
        self.assertFalse(created.requested_name_matches)
        self.assertTrue(decide(requested='ServerName').requested_name_matches)
        for code in (1, 59, 0xffffffff):
            rejected = decide(replace(result, result_code=code))
            self.assertEqual(rejected.status, 'rejected')
            self.assertIsNone(rejected.character_key)
            self.assertIsNone(rejected.character_name)
            self.assertFalse(rejected.retry_allowed)
        for r in (replace(record, u64=(0,)), replace(record, strings=('', '', ''))):
            incomplete = decide(replace(result, record=r))
            self.assertEqual(incomplete.status, 'needs_refresh')
            self.assertFalse(incomplete.retry_allowed)
        with self.assertRaises(ValueError): decide(sha='0' * 64)
        with self.assertRaises(ValueError): decide(requested='')
        with self.assertRaises(ValueError): decide(replace(result, record=replace(record, u64=())))


if __name__ == '__main__': unittest.main()
