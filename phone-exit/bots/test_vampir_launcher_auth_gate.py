import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'


def tool():
    spec = importlib.util.spec_from_file_location('launcher_auth_gate_test', HERE / 'replay-launcher-auth-gate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LauncherAuthGateTests(unittest.TestCase):
    def test_native_gate_reproduces_and_keeps_distinct_auth_contexts(self):
        module = tool()
        saved = json.loads((module.ROOT / 'code-clues/launcher-auth-gate-replay.json').read_text('utf-8'))
        self.assertEqual(module.build(), saved)
        self.assertEqual(len(saved['cases']), 10)
        for row in saved['cases']:
            fixture = row['fixture']
            expected = fixture['context_ok'] and fixture['auth_type'].lower() == 'nmlauncher'
            self.assertEqual(row['accepted'], expected)
            self.assertEqual(row['flag_after'], 1 if expected else fixture['prior_flag'])
        self.assertEqual(saved['credential_vtable']['slots'][1], '0x1444e6570')
        self.assertFalse(saved['network_used'])

    def test_source_mutation_is_rejected_before_replay(self):
        module = tool()
        item = dict(file_offset=1, bytes='aabb')
        module.validate_bytes(b'\x00\xaa\xbb', item)
        with self.assertRaisesRegex(ValueError, 'source bytes changed'):
            module.validate_bytes(b'\x00\xaa\xbc', item)


if __name__ == '__main__':
    unittest.main()
