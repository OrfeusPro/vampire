"""GMC2 native string unescape, strict portable handling and XOR composition."""
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
from vampir_core.sdk_constants import unescape_sdk_utf16le, decode_sdk_constants_string


def packed(units):
    return struct.pack('<'+'H'*len(units), *units)


class SDKUnescapeLimitsTests(unittest.TestCase):
    def test_constants_pipeline_matches_full_native_xor_append_fixtures(self):
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        report = json.loads((root / 'code-clues/headless-gmc2-xor.json').read_text('utf-8'))
        for case in report['cases']:
            text = packed(case['source_units']).decode('utf-16le', 'surrogatepass')
            escaped = json.dumps(text, ensure_ascii=True)[1:-1].encode('utf-16le')
            self.assertEqual(decode_sdk_constants_string(escaped, packed(case['key_units'])), packed(case['output_units']))

    def test_constants_pipeline_uses_actual_append_zero_omission(self):
        from vampir_core.sdk_constants import xor_sdk_utf16le
        from vampir_core.gmc2_decode import xor_gmc2_utf16_units
        content = r'\u0041\u0042\u0041'.encode('utf-16le')
        key = packed([0x41])
        self.assertEqual(xor_sdk_utf16le(unescape_sdk_utf16le(content), key), packed([0, 3, 0]))
        self.assertEqual(decode_sdk_constants_string(content, key), packed([3]))
        self.assertEqual(decode_sdk_constants_string(content, key), xor_gmc2_utf16_units(unescape_sdk_utf16le(content), key))
        self.assertEqual(decode_sdk_constants_string(r'\ud800'.encode('utf-16le'), packed([0])), packed([0xd800]))
        self.assertEqual(decode_sdk_constants_string(b'', key), b'')
        for data, key in ((b'', b''), (b'', bytes(1026)), (b'xx', b'x'), (b'xx', None)):
            with self.assertRaises(ValueError):
                decode_sdk_constants_string(data, key)

    def test_strict_inputs_and_limits(self):
        for invalid in [None, 'text', bytearray(b'xx'), b'x', b'xx'*2049]:
            with self.assertRaises(ValueError):
                unescape_sdk_utf16le(invalid)
        self.assertEqual(unescape_sdk_utf16le(('x'*2048).encode('utf-16le')), b'x\0'*2048)
        for text in ['abc\\u12G4', 'abc"tail', 'abc\\', 'abc\nraw']:
            with self.assertRaises(ValueError) as error:
                unescape_sdk_utf16le(text.encode('utf-16le'))
            self.assertNotIn('abc', str(error.exception))
        self.assertEqual(unescape_sdk_utf16le(b''), b'')
        self.assertEqual(unescape_sdk_utf16le(r'\ud800\u0000'.encode('utf-16le')), packed([0xd800, 0]))


class SDKUnescapeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        path = root/'code-clues/headless-sdk-unescape.json'
        if not path.exists():
            raise unittest.SkipTest('Generate native SDK unescape evidence first')
        cls.report = json.loads(path.read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()

    def test_source_provenance_code_data_and_field_bindings(self):
        r = self.report
        self.assertFalse(r['network_ready'])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), r['sha256'])
        tool = HERE/'resource-tools/vampir/build-headless-sdk-unescape.py'
        self.assertEqual(hashlib.sha256(tool.read_bytes()).hexdigest(), r['tool_sha256'])
        rows = {i['address']: i for f in r['fragments']+r['unescape_fragments'] for i in f['instructions']}
        for f in r['fragments']+r['unescape_fragments']:
            raw = self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(raw).hexdigest(), f['sha256'])
            self.assertEqual(raw, b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']))
        for record in r['data']+r['constants']:
            raw = bytes.fromhex(record['bytes'])
            self.assertEqual(self.raw[record['file_offset']:record['file_offset']+len(raw)], raw)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), record['sha256'])
        self.assertEqual(r['pow_import']['name'], 'powf')
        self.assertEqual(r['pow_import']['dll'], 'api-ms-win-crt-math-l1-1-0.dll')
        self.assertEqual(rows[0x1444f0f2c]['operands'], 'r9, [r13 + 0x110]')
        self.assertEqual(rows[0x1444f12c5]['operands'], 'r9, [r13 + 0x120]')
        self.assertEqual(rows[0x1444e3e20]['direct_target'], 0x1444f2670)
        self.assertEqual(rows[0x1444f0f6e]['direct_target'], 0x1444ddf50)
        self.assertEqual(rows[0x1444c9485]['operands'], 'r8, 0xb0')
        self.assertEqual(rows[0x1444c948f]['operands'], 'qword ptr [rax + 0x28]')
        self.assertEqual(rows[0x1444c957c]['operands'], 'r8, [rbp - 0x60]')
        self.assertEqual(rows[0x1444c9587]['direct_target'], 0x1444f0e80)
        for address, field in [(0x1444bdaa7, 'encConstants'), (0x1444bdaba, 'encSecretConstants'),
                               (0x1444bda35, 'DECKEY')]:
            self.assertEqual(next(c['text'] for c in r['constants'] if c['instruction']['address'] == address), field)

    def test_native_valid_vectors_and_explicit_stricter_invalid_policy(self):
        self.assertEqual(self.report['statistics'], dict(valid_cases=43, permissive_cases=7, pipeline_cases=3))
        for case in self.report['valid_cases']:
            self.assertEqual(unescape_sdk_utf16le(packed(case['input_units'])), packed(case['output_units']))
        for case in self.report['permissive_cases']:
            with self.assertRaises(ValueError):
                unescape_sdk_utf16le(packed(case['input_units']))

    def test_native_unescape_xor_pipeline_and_plaintext_json(self):
        for case in self.report['pipeline_cases']:
            output = decode_sdk_constants_string(packed(case['unescape']['input_units']),
                                                  packed(case['xor']['test_key_units']))
            self.assertEqual(output, packed(case['xor']['output_units']))
            self.assertIsInstance(json.loads(output.decode('utf-16le')), dict)

    def test_reexecute_native_escape_switch_unicode_and_early_stop(self):
        spec = importlib.util.spec_from_file_location('test_sdk_unescape',
                            HERE/'resource-tools/vampir/build-headless-sdk-unescape.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        emulator = module.SDKUnescapeEmulator()
        for case in self.report['valid_cases'][:9]+self.report['permissive_cases']:
            self.assertEqual(emulator.run(case['input_units']), case)


if __name__ == '__main__':
    unittest.main()
