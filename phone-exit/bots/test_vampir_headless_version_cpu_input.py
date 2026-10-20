"""Source-bound CPU-input replay and remaining Version input evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'
ROOT = Path('F:/PhoneExit Resources/Vampir')


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class VersionCpuInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cpu = module('cpu_replay_test', 'replay-version-cpu-input.py')
        cls.index = module('login_input_index_test', 'build-game-login-input-index.py')

    def test_full_initializer_and_both_getters_reproduce_all_scenarios(self):
        path = ROOT / 'code-clues/version-cpu-input-replay.json'
        report = self.cpu.build()
        self.assertEqual(report, json.loads(path.read_text('utf-8')))
        self.assertEqual(len(report['cases']), 4)
        intel, amd, unsupported, disabled = report['cases']
        self.assertEqual(intel['getter_outputs'], ['GenuineIntel', 'Fixture CPU Brand'])
        self.assertEqual(amd['getter_outputs'], ['AuthenticAMD', '  Fixture padded CPU  '])
        self.assertEqual(unsupported['getter_outputs'], ['GenuineIntel', ''])
        self.assertEqual(disabled['getter_outputs'], ['previous', 'previous-brand'])
        self.assertEqual(disabled['events'], [])
        leaves = [e['leaf'] for e in intel['events'] if e['action'] == 'cpuid_fixture']
        self.assertEqual(leaves, ['0x0', '0x80000000', '0x80000002', '0x80000003', '0x80000004', '0x1', '0x80000006'])

    def test_source_index_reproduces_and_does_not_invent_appversion_bytes(self):
        report = self.index.build()
        self.assertEqual(report, json.loads((ROOT / 'code-clues/game-login-input-index.json').read_text('utf-8')))
        targets = {row['name']: row for row in report['targets']}
        self.assertFalse(targets['NetworkSetting_AppVersion']['file_backed'])
        self.assertEqual(targets['Version_b0_Login_110_pointer']['pointee']['ascii'], 'AC7F34E3AFA91ED417BE86CD45BF18C8')
        self.assertEqual(bytes.fromhex(targets['Version_c0_Login_120_dword']['bytes'])[:4], b'\x01\0\0\0')
        writes = [r for r in report['references'] if r['root'] == '0x140ff54a0']
        self.assertTrue(any(r['target'] == '0x14b058cb2' and r['instruction']['mnemonic'] == 'movsd' for r in writes))
        self.assertTrue(any(r['target'] == '0x14b058cbf' and r['instruction']['mnemonic'] == 'movups' for r in writes))
        self.assertIn('not exhaustive', report['scope'])

    def test_instruction_and_literal_proofs_match_source_bytes(self):
        report = json.loads((ROOT / 'code-clues/game-login-input-index.json').read_text('utf-8'))
        raw = Path(report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), report['source_sha256'])
        for fragment in report['fragments']:
            length = fragment['end_rva'] - fragment['begin_rva']
            offset = fragment['file_offset']
            self.assertEqual(hashlib.sha256(raw[offset:offset + length]).hexdigest(), fragment['sha256'])
        for literal in report['literals']:
            data = bytes.fromhex(literal['bytes'])
            offset = literal['file_offset']
            self.assertEqual(raw[offset:offset + len(data)], data)
            self.assertEqual(hashlib.sha256(data).hexdigest(), literal['sha256'])


if __name__ == '__main__': unittest.main()
