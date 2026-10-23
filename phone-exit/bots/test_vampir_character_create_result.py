import importlib.util
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.character_create_result import decode_character_create_result, SOURCE_SHA256


class CharacterCreateResultTests(unittest.TestCase):
    def test_whole_current_reader_matches_every_record_field(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-character-create-result.py'
        spec = importlib.util.spec_from_file_location('creation_result_replay', path)
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertEqual(len(report['cases']), 16)
        self.assertGreater(len(report['short']), 700)
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])

    def test_error_code_alone_and_wrong_source_are_rejected(self):
        for code in (0, 1, 58, 0xffffffff):
            with self.assertRaises(ValueError):
                decode_character_create_result(struct.pack('<I', code), source_sha256=SOURCE_SHA256,
                    max_payload_size=4096, max_extension_items=128)
        with self.assertRaises(ValueError):
            decode_character_create_result(b'', source_sha256='0' * 64, max_payload_size=4096, max_extension_items=128)

    def test_trailing_bytes_and_extension_budget_are_rejected(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-character-list-extensions.py'
        spec = importlib.util.spec_from_file_location('creation_result_wire_test', path)
        wire = importlib.util.module_from_spec(spec); spec.loader.exec_module(wire)
        body = struct.pack('<I', 1) + wire.record_bytes(((1, 2, 3),))
        result = decode_character_create_result(body, source_sha256=SOURCE_SHA256,
            max_payload_size=4096, max_extension_items=1)
        self.assertEqual(result.result_code, 1)
        with self.assertRaises(ValueError):
            decode_character_create_result(body + b'\0', source_sha256=SOURCE_SHA256,
                max_payload_size=4096, max_extension_items=1)
        with self.assertRaises(BufferError):
            decode_character_create_result(body, source_sha256=SOURCE_SHA256,
                max_payload_size=4096, max_extension_items=0)
        with self.assertRaises(BufferError):
            decode_character_create_result(body, source_sha256=SOURCE_SHA256,
                max_payload_size=len(body) - 1, max_extension_items=1)


if __name__ == '__main__': unittest.main()
