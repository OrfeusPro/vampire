"""Native GMC2 XOR parity and source-bound SDK query literals."""
import hashlib
import importlib.util
import json
import os
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE/'vampir-shared'))
from vampir_core.sdk_constants import xor_sdk_utf16le


def packed(units):
    return struct.pack('<'+'H'*len(units), *units)


class SDKConstantsTests(unittest.TestCase):
    def test_code_units_preserve_surrogates_zeros_and_key_cycle(self):
        data = packed([0, 0xd800, 0xffff, 0xdc00, 0, 65])
        key = packed([0x1234, 0xabcd])
        result = xor_sdk_utf16le(data, key)
        self.assertEqual(result, packed([0x1234, 0xd800 ^ 0xabcd, 0xffff ^ 0x1234,
                                         0xdc00 ^ 0xabcd, 0x1234, 65 ^ 0xabcd]))
        self.assertEqual(xor_sdk_utf16le(result, key), data)
        self.assertEqual(xor_sdk_utf16le(b'', b''), b'')

    def test_reject_invalid_input_and_enforce_allocation_bounds(self):
        for data, key in [(b'a', b'xx'), (b'xx', b'a'), (b'xx', b''),
                          (b'x'*4098, b'xx'), (b'', b'x'*1026),
                          (bytearray(b'xx'), b'xx'), (b'xx', None), ('xx', b'xx')]:
            with self.assertRaises(ValueError):
                xor_sdk_utf16le(data, key)
        self.assertEqual(len(xor_sdk_utf16le(b'x'*4096, b'y'*1024)), 4096)


class SDKValuesEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        path = root/'code-clues/headless-sdk-values.json'
        if not path.exists():
            raise unittest.SkipTest('Generate native SDK value evidence first')
        cls.report = json.loads(path.read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()

    def test_source_bytes_and_query_literal_provenance(self):
        r = self.report
        self.assertFalse(r['network_ready'])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), r['sha256'])
        tool = HERE/'resource-tools/vampir/build-headless-sdk-values.py'
        self.assertEqual(hashlib.sha256(tool.read_bytes()).hexdigest(), r['tool_sha256'])
        rows = {i['address']: i for f in r['fragments'] for i in f['instructions']}
        for f in r['fragments']:
            data = self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(data).hexdigest(), f['sha256'])
            self.assertEqual(data, b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']))
        self.assertEqual([v['text'] for v in r['literals']], ['5.2.11', 'A', 'B', 'C'])
        for literal in r['literals']:
            data = bytes.fromhex(literal['bytes'])
            self.assertEqual(self.raw[literal['file_offset']:literal['file_offset']+len(data)], data)
            self.assertEqual(hashlib.sha256(data).hexdigest(), literal['sha256'])
            self.assertEqual(literal['instruction'], rows[literal['instruction']['address']])
        self.assertEqual(rows[0x1444f3bb3]['direct_target'], 0x144524390)
        self.assertEqual(rows[0x1444f3c6c]['operands'], 'edx, byte ptr [rdx + 0x48]')
        self.assertEqual(rows[0x1444f3c70]['direct_target'], 0x14452b820)
        for instruction, target in [(0x1411b322b, 0x14b4f1658),
                                    (0x1411b325b, 0x14b4f1668), (0x1411b328b, 0x14b4f1678)]:
            self.assertEqual(rows[instruction]['rip_references'], [target])

    def test_shared_transform_matches_all_native_vectors(self):
        self.assertEqual(self.report['statistics']['native_xor_cases'], 42)
        for case in self.report['cases']:
            self.assertEqual(xor_sdk_utf16le(packed(case['input_units']), packed(case['test_key_units'])),
                             packed(case['output_units']))

    def test_reexecute_native_loop_with_boundaries_and_unicode(self):
        path = HERE/'resource-tools/vampir/build-headless-sdk-values.py'
        spec = importlib.util.spec_from_file_location('sdk_values_replay', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        emulator = module.SDKValuesEmulator()
        for index in [0, 1, 10, 20, 30, 40, 41]:
            case = self.report['cases'][index]
            self.assertEqual(emulator.decrypt(case['input_units'], case['test_key_units']), case)


if __name__ == '__main__':
    unittest.main()
