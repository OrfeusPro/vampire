import importlib.util
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.character_create import CharacterCreatePayload, encode_character_create, SOURCE_SHA256


class CharacterCreateWriterTests(unittest.TestCase):
    def test_whole_writer_strings_arrays_and_failure_propagation(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-character-create-writer.py'
        spec = importlib.util.spec_from_file_location('creation_writer_replay', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 42)
        self.assertEqual(len(report['failures']), 24)
        self.assertEqual([row['fail_at'] for row in report['failures'] if row['accepted']], [1, 2, 13, 14])
        self.assertTrue(all(row['stopped'] == (row['accepted'] == 0) for row in report['failures']))
        self.assertTrue(any(len(row['name']) == 129 for row in report['cases']))
        self.assertTrue(any(row['name'] == '界' * 80 for row in report['cases']))

    def test_encoder_rejects_wrong_source_and_invalid_strings_before_returning_body(self):
        value = CharacterCreatePayload(1, 'Name', (0,) * 10, '{}', (0, 0), ())
        with self.assertRaises(ValueError): encode_character_create(value, source_sha256='0' * 64)
        for name in ('embedded\0tail', '\ud800', 'a' * 4097):
            invalid = CharacterCreatePayload(1, name, value.appearance, '{}', (0, 0), ())
            with self.assertRaises(ValueError): encode_character_create(invalid, source_sha256=SOURCE_SHA256)


if __name__ == '__main__': unittest.main()
