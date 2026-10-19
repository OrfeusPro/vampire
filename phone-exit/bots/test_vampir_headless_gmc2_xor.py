"""GMC2 XOR primitive: real native unit loop/append and portable bounds."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.gmc2_decode import MAX_KEY_BYTES, MAX_XOR_BYTES, xor_gmc2_utf16_units

TOOL = HERE / 'resource-tools/vampir/build-headless-gmc2-xor.py'
spec = importlib.util.spec_from_file_location('gmc2_xor_test', TOOL)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def packed(units):
    return struct.pack('<' + 'H' * len(units), *units)


class Gmc2XorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads((module.values.native.ROOT / 'code-clues/headless-gmc2-xor.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()

    def test_source_native_unit_width_and_zero_append_gate(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(TOOL.read_bytes()).hexdigest(), self.report['tool_sha256'])
        for fragment in self.report['fragments']:
            data = b''.join(bytes.fromhex(r['bytes']) for r in fragment['instructions'])
            self.assertEqual(hashlib.sha256(data).hexdigest(), fragment['sha256'])
            self.assertEqual(self.raw[fragment['file_offset']:fragment['file_offset'] + len(data)], data)
        rows = {r['address']: r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x1444de003]['mnemonic'], 'idiv')
        self.assertEqual(rows[0x1444de015]['operands'], 'dx, word ptr [rax + rsi*2]')
        self.assertEqual(rows[0x1444de019]['direct_target'], module.APPEND)
        self.assertEqual(rows[0x1414242b3]['direct_target'], 0x141424308)
        self.assertEqual(rows[0x1444f0f6e]['direct_target'], module.XOR)
        self.assertEqual(rows[0x1444ddf61]['rip_references'], [self.report['logging_fixture_address']])
        image = module.values.native.Image(self.raw)
        emu = module.Emulator(self.raw, image, self.report['fragments'])
        self.assertEqual(bytes(emu.uc.mem_read(self.report['logging_fixture_address'], 1)), b'\0')

    def test_native_replays_equal_shared_primitive(self):
        image = module.values.native.Image(self.raw)
        self.assertEqual(len(self.report['cases']), 18)
        for case in self.report['cases']:
            replay = module.Emulator(self.raw, image, self.report['fragments']).decode(case['source_units'], case['key_units'])
            self.assertEqual(replay, case)
            self.assertEqual(xor_gmc2_utf16_units(packed(case['source_units']), packed(case['key_units'])), packed(case['output_units']))
            self.assertTrue(case['guards_unchanged'])
            self.assertTrue(case['output_terminated'])
        self.assertEqual(self.report['cases'][2]['output_units'], [])
        self.assertEqual(self.report['cases'][3]['output_units'], [1, 1])
        self.assertFalse(self.report['network_ready'])

    def test_raw_units_surrogates_no_implicit_terminator_and_budgets(self):
        self.assertEqual(xor_gmc2_utf16_units(packed([0xd800, 0, 0xdc00]), packed([0])), packed([0xd800, 0xdc00]))
        self.assertEqual(xor_gmc2_utf16_units(packed([0, 0, 0]), packed([1, 2])), packed([1, 2, 1]))
        self.assertEqual(xor_gmc2_utf16_units(b'', packed([1])), b'')
        self.assertEqual(xor_gmc2_utf16_units(b'', bytes(MAX_KEY_BYTES)), b'')
        for source, key in ((b'x', b'aa'), (b'aa', b'x'), (b'', b''), ('aa', b'aa'),
                            (b'aa', None), (bytearray(b'aa'), b'aa'),
                            (bytes(MAX_XOR_BYTES + 2), b'aa'), (b'', bytes(MAX_KEY_BYTES + 2))):
            with self.subTest(source_type=type(source).__name__, key_type=type(key).__name__), self.assertRaises(ValueError):
                xor_gmc2_utf16_units(source, key)

    def test_reproducible_report(self):
        self.assertEqual(module.build(), self.report)


if __name__ == '__main__':
    unittest.main()
