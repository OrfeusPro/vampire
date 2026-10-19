"""Native wrapper allocation does not overwrite fixture backend tail bytes."""
import importlib.util
import json
from pathlib import Path
import unittest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class MigrationAllocationTests(unittest.TestCase):
    def test_native_wrapper_dispatch_and_tail_preservation(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-sdk-migration-allocation.py'
        spec = importlib.util.spec_from_file_location('migration_allocation_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        report = json.loads((tool.native.ROOT / 'code-clues/sdk-migration-allocation-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        self.assertEqual(len(report['cases']), 10)
        rows = {r['address']: r for f in report['evidence']['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x1414316ef]['direct_target'], 0x141431210)
        self.assertEqual(rows[0x141431243]['direct_target'], 0x14148c8d0)
        self.assertEqual(rows[0x14148c91b]['operands'], 'qword ptr [rax + 0x38]')
        for case in report['cases']:
            fixture = case['fixture']
            size = len(fixture['channel_key'])
            rounded = (size + 15) & ~15
            data = bytes(ord(c) - 1 for c in fixture['channel_key'])
            data += bytes([fixture['allocation_fill']]) * (rounded - size)
            self.assertEqual(case['transformed_hex'], data.hex())
            self.assertEqual(case['backend_events'], [
                dict(action='quantize_fixture', requested=rounded, alignment=1),
                dict(action='realloc_fixture', requested=rounded, alignment=1, fill=fixture['allocation_fill'])])
            enc = Cipher(algorithms.AES(fixture['nm_key'].encode('ascii')), modes.ECB()).encryptor()
            self.assertEqual(case['migration_path'], (enc.update(data) + enc.finalize()).hex().upper())
        self.assertFalse(report['user_storage_read'])


if __name__ == '__main__':
    unittest.main()
