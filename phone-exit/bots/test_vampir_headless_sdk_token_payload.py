"""Native container gates do not imply authenticated claims."""
import importlib.util
import json
from pathlib import Path
import unittest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class SdkTokenPayloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-sdk-token-payload.py'
        spec = importlib.util.spec_from_file_location('sdk_token_payload_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT / 'code-clues/sdk-token-payload-replay.json').read_text('utf-8'))

    def test_source_report_and_base64url_wrapper(self):
        self.assertEqual(self.tool.build(), self.report)
        rows = {r['address']: r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x14451d58d]['direct_target'], 0x1415230c0)
        self.assertEqual(rows[0x14451d530]['operands'], 'ecx, 0x2d')
        self.assertEqual(rows[0x14451d545]['operands'], 'r8d, [rdx - 2]')
        self.assertEqual(rows[0x14451d559]['operands'], 'ecx, 0x5f')
        self.assertEqual(rows[0x14451d56e]['operands'], 'r8d, [rdx - 0x30]')
        texts = {v['text'] for v in self.report['literals']}
        self.assertTrue({'.', '==', 'channelKey', 'bUseMigration'} <= texts)
        self.assertFalse(self.report['network_ready'])

    def test_caller_acceptance_and_rejection_do_not_validate_signature(self):
        cases = {c['fixture']['name']: c for c in self.report['cases']}
        self.assertEqual(len(cases), 16)
        accepted = {'objects', 'no-alg-check', 'non-base64-signature', 'missing-sub', 'padding-0', 'padding-1', 'padding-2'}
        self.assertEqual({name for name, c in cases.items() if c['accepted']}, accepted)
        for name in accepted:
            self.assertEqual(len(cases[name]['decode_calls']), 2)
        for name in ('two-segments', 'four-segments', 'bad-header-length', 'bad-payload-length', 'bad-signature-length'):
            self.assertEqual(cases[name]['decode_calls'], [])
        self.assertEqual(cases['missing-sub']['payload'], {})
        self.assertEqual(cases['no-alg-check']['header'], {'alg': 'none'})
        for name in ('padding-0', 'padding-1', 'padding-2'):
            self.assertTrue(all(len(d['encoded']) % 4 == 0 for d in cases[name]['decode_calls']))
        self.assertEqual(cases['objects']['payload'], {'sub': 'B' * 32})

    def test_native_channel_migration_rounding_and_allocation_tail_uncertainty(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-sdk-channel-migration-path.py'
        spec = importlib.util.spec_from_file_location('sdk_channel_migration_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        report = json.loads((tool.native.ROOT / 'code-clues/sdk-channel-migration-path-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        self.assertEqual(len(report['cases']), 8)
        results = {}
        for case in report['cases']:
            fixture = case['fixture']
            size = len(fixture['channel_key'])
            padded_size = (size + 15) & ~15
            value = bytes((ord(c) - 1) & 255 for c in fixture['channel_key'])
            value += bytes([fixture['allocation_fill']]) * (padded_size - size)
            self.assertEqual(case['transformed_hex'], value.hex())
            enc = Cipher(algorithms.AES(fixture['nm_key'].encode('ascii')), modes.ECB()).encryptor()
            self.assertEqual(case['migration_path'], (enc.update(value) + enc.finalize()).hex().upper())
            results[size, fixture['allocation_fill']] = case['migration_path']
        self.assertEqual(results[16, 0], results[16, 0xaa])
        self.assertNotEqual(results[17, 0], results[17, 0xaa])
        self.assertFalse(report['user_storage_read'])


if __name__ == '__main__':
    unittest.main()
