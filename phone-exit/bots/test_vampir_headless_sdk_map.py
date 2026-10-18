"""Native SDK map merge/URL lookup and portable string-map behavior."""
import hashlib
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE/'vampir-shared'))
from vampir_core.sdk_config import merge_sdk_string_constants, lookup_sdk_url_value


class SDKStringMapTests(unittest.TestCase):
    def test_secret_overrides_ascii_alias_without_mutating_inputs(self):
        ordinary = {'authTokenUrl': 'https://ordinary.invalid/', 'clientId': 'test'}
        secret = {'AUTHTOKENURL': 'https://secret.invalid/'}
        merged = merge_sdk_string_constants(ordinary, secret)
        self.assertEqual(merged, {'AUTHTOKENURL': 'https://secret.invalid/', 'clientId': 'test'})
        self.assertEqual(lookup_sdk_url_value(merged, 'authtokenurl'), 'https://secret.invalid/')
        self.assertEqual(ordinary['authTokenUrl'], 'https://ordinary.invalid/')
        self.assertEqual(secret, {'AUTHTOKENURL': 'https://secret.invalid/'})
        self.assertIsNone(lookup_sdk_url_value(merged, 'clientId'))
        self.assertIsNone(lookup_sdk_url_value(merged, 'missing'))
        self.assertEqual(lookup_sdk_url_value({'key': 'https://'}, 'KEY'), 'https://')
        self.assertIsNone(lookup_sdk_url_value({'Ключ': 'https://x.invalid/'}, 'ключ'))

    def test_typed_limits_aliases_and_failed_merge_leave_input_unchanged(self):
        ordinary = {'authTokenUrl': 'https://ordinary.invalid/'}
        for invalid in [{'A': 'one', 'a': 'two'}, {'key': 42}, {'bad\0key': 'value'},
                        {'key': 'bad\0value'}, {'key': 'x'*4097}, {'x'*257: 'value'},
                        {str(i): 'value' for i in range(513)}, {'key': '😀'*3000},
                        {str(i): 'x'*4096 for i in range(9)}]:
            with self.assertRaises(ValueError):
                merge_sdk_string_constants(ordinary, invalid)
            self.assertEqual(ordinary, {'authTokenUrl': 'https://ordinary.invalid/'})


class SDKMapEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        path = root/'code-clues/headless-sdk-map.json'
        if not path.exists():
            raise unittest.SkipTest('Generate native SDK map evidence first')
        cls.report = json.loads(path.read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()

    def test_source_map_parser_order_and_auth_call_chain(self):
        r = self.report
        self.assertFalse(r['network_ready'])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), r['sha256'])
        tool = HERE/'resource-tools/vampir/build-headless-sdk-map.py'
        self.assertEqual(hashlib.sha256(tool.read_bytes()).hexdigest(), r['tool_sha256'])
        rows = {i['address']: i for f in r['fragments'] for i in f['instructions']}
        for f in r['fragments']:
            raw = self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(raw).hexdigest(), f['sha256'])
            self.assertEqual(raw, b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']))
        for record in r['data']+r['constants']:
            raw = bytes.fromhex(record['bytes'])
            self.assertEqual(self.raw[record['file_offset']:record['file_offset']+len(raw)], raw)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), record['sha256'])
        for address in (0x1444f1250, 0x1444f162f):
            self.assertEqual(rows[address]['direct_target'], 0x14150df70)
        self.assertEqual(rows[0x1450e2895]['direct_target'], 0x144553700)
        self.assertEqual(rows[0x144553722]['operands'], 'rcx, [rbx + 0x310]')
        self.assertEqual(rows[0x14455372f]['direct_target'], 0x144502730)
        self.assertEqual(r['move_import']['name'], 'memmove')

    def test_native_getter_replacement_and_ascii_hash_parity(self):
        r = self.report
        self.assertEqual(r['statistics'], dict(lookup_cases=24, replacement_cases=3, hash_cases=5))
        for case in r['cases']:
            self.assertEqual(lookup_sdk_url_value(dict(case['pairs']), case['key']),
                             case['output'] if case['success'] else None)
        for case in r['replacements']:
            self.assertEqual(merge_sdk_string_constants({case['old_key']: case['old_value']},
                                                       {case['new_key']: case['new_value']}),
                             {case['result_key']: case['result_value']})
        self.assertEqual(len({c['value'] for c in r['hash_cases'][:3]}), 1)

    def test_reexecute_native_getter_hash_and_replace_slice(self):
        spec = importlib.util.spec_from_file_location('map_replay', HERE/'resource-tools/vampir/build-headless-sdk-map.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        emulator = module.SDKMapEmulator()
        for case in self.report['cases']:
            self.assertEqual(emulator.lookup(case['pairs'], case['key']), case)
        for case in self.report['replacements']:
            self.assertEqual(emulator.replace(case['old_key'], case['new_key'], case['old_value'], case['new_value']), case)
        for case in self.report['hash_cases']:
            self.assertEqual(emulator.key_hash(case['key']), case['value'])


if __name__ == '__main__':
    unittest.main()
