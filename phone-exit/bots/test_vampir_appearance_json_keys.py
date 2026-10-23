"""Native numeric keys and portable appearance JSON semantic equivalence."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.character_appearance import GROUP_IDS, encode_character_appearance
from vampir_core.world_move_start import SOURCE_SHA256


class AppearanceJsonKeysTests(unittest.TestCase):
    def test_native_keys_and_float_values(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-appearance-json-keys.py'
        spec = importlib.util.spec_from_file_location('appearance_json_key_test', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        _, report = module.run()
        self.assertEqual(len(report['cases']), 36)
        self.assertEqual(report['definitions'][1], GROUP_IDS)
        values = (0.4, 0.3, 0.5, -0.0, 0.125, -2.5, 1.0)
        for case in report['cases']:
            if case['digits'] == 'latin':
                settings = {} if case['sparse'] == 'empty' else dict(zip(GROUP_IDS, values))
                encoded = encode_character_appearance(settings, case['voice'], source_sha256=SOURCE_SHA256, key_profile='latin')
                actual = json.loads(encoded)
                self.assertEqual({k: struct.pack('<d', v).hex() for k, v in actual.items()}, case['values_f64_hex'])
            elif case['sparse'] != 'empty':
                self.assertEqual(case['formatted_keys'], list('١٢٣٤٥٦٧'))

    def test_reject_unsupported_inputs_before_encoding(self):
        def encode(settings, voice=0, sha=SOURCE_SHA256, profile='latin'):
            return encode_character_appearance(settings, voice, source_sha256=sha, key_profile=profile)
        for settings in ({'Unknown': 1}, {'Height': True}, {'Height': float('nan')},
                         {'Height': float('inf')}, {'Height': 1e100}, []):
            with self.subTest(settings=settings), self.assertRaises(ValueError): encode(settings)
        for voice in (-1, 256, True):
            with self.assertRaises(ValueError): encode({}, voice)
        with self.assertRaises(ValueError): encode({}, sha='0' * 64)
        with self.assertRaises(ValueError): encode({}, profile='arabic')
        self.assertEqual(encode({}), '{"VoiceType":0}')


if __name__ == '__main__': unittest.main()
