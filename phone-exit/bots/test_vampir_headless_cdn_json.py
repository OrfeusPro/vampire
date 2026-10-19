"""Native JSON result branches and bounded offline document/environment flow."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.cdn_config import decode_cdn_config_document, read_cdn_sdk_environment
from vampir_core.cdn_response import MAX_BODY_BYTES, take_cdn_length_response
from vampir_core.sdk_config import select_game_sdk_zone


class CdnJsonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = HERE / 'resource-tools/vampir/build-headless-cdn-json-flow.py'
        spec = importlib.util.spec_from_file_location('cdn_json_test_tool', cls.tool)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        cls.report = json.loads((root / 'code-clues/headless-cdn-json-flow.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()
        cls.image = cls.module.body.head.headers.uri.http.preparation.url.settings.config.native.Image(cls.raw)
        spec = importlib.util.spec_from_file_location('json_fallback_fixture', HERE / 'resource-tools/vampir/build-headless-cdn-fallback.py')
        cls.crypto = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.crypto)
        prior = json.loads((root / 'code-clues/headless-cdn-fallback.json').read_text('utf-8'))
        cls.key = hashlib.sha256(prior['seed_literal']['text'].encode()).digest()

    def test_source_tool_and_native_instructions(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(self.tool.read_bytes()).hexdigest(), self.report['tool_sha256'])
        for fragment in self.report['fragments']:
            for row in fragment['instructions']:
                data = bytes.fromhex(row['bytes'])
                self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        self.assertFalse(self.report['network_ready'])

    def test_all_native_branch_replays_and_separate_validation_requirement(self):
        self.assertEqual(len(self.report['parser_cases']) + len(self.report['read_cases']), 12)
        for case in self.report['parser_cases']:
            emulator = self.module.JsonFlowEmulator(self.raw, self.image, self.report['fragments'])
            self.assertEqual(emulator.parser_result(case['parser_success_fixture'], case['object_present_fixture']), case)
            self.assertEqual(case['goes_to_readjson'], case['parser_success_fixture'] and case['object_present_fixture'])
            self.assertFalse(case['parser_executed'])
        for case in self.report['read_cases']:
            emulator = self.module.JsonFlowEmulator(self.raw, self.image, self.report['fragments'])
            self.assertEqual(emulator.read_result(case['read_success_fixture'], case['validate_success_fixture'], case['source_flag_fixture']), case)
            success = case['read_success_fixture'] and case['validate_success_fixture']
            self.assertEqual(case['reaches_next_branch'], success)
            self.assertEqual(case['result_flag'], int(success))
            self.assertEqual(case['global_flag'], case['source_flag_fixture'] if case['read_success_fixture'] else 0xa5)
            self.assertFalse(case['readjson_and_validation_executed'])

    def test_plain_encodings_preserve_document_and_do_not_load_crypto(self):
        root = {'NetmarbleS': {'Zone': 'REAL'}, 'name': 'Вампир 😀', 'values': [None, True, 12, 1.5]}
        text = json.dumps(root, ensure_ascii=False)
        variants = [text.encode(), b'\xef\xbb\xbf' + text.encode(), b'\xff\xfe' + text.encode('utf-16le')]
        with patch('vampir_core.cdn_fallback.decrypt_cdn_fallback', side_effect=AssertionError('unexpected crypto')):
            for body in variants:
                decoded = decode_cdn_config_document(body)
                self.assertEqual(decoded, root)
                self.assertEqual(select_game_sdk_zone(read_cdn_sdk_environment(decoded)), 2)

    def test_encrypted_document_http_to_sdk_selection(self):
        for zone, expected in [('real', 2), ('ReAl', 2), ('dev', 1), ('unreal', 1), ('real ', 1), ('', 1)]:
            plain = json.dumps({'NetmarbleS': {'Zone': zone}}, ensure_ascii=False).encode()
            encrypted = self.crypto.encrypt_fixture(plain, self.key, bytes(range(16)))
            header = f'HTTP/1.1 200\r\nContent-Length: {len(encrypted)}\r\n\r\n'.encode()
            self.assertIsNone(take_cdn_length_response(header + encrypted[:-1]))
            response = take_cdn_length_response(header + encrypted + b'trailing')
            document = decode_cdn_config_document(response.body)
            self.assertEqual(select_game_sdk_zone(read_cdn_sdk_environment(document)), expected)
            self.assertEqual(response.consumed, len(header) + len(encrypted))
        for plain in [b'not json', b'[]', b'{"x":NaN}', b'{"x":1,"x":2}',
                      b'{}\0extra', b'\xef\xbb\xbf{}', b'\xff\xfe{\0}\0']:
            payload = self.crypto.encrypt_fixture(plain, self.key, bytes(16))
            with self.assertRaises(ValueError):
                decode_cdn_config_document(payload)

    def test_local_json_policy_failures_do_not_fall_back_or_echo_input(self):
        invalid = [b'{"private":1,"private":2}', b'{"n":NaN}', b'{"n":Infinity}',
                   b'{"n":1e10000}', b'{"n":' + b'1' * 129 + b'}',
                   b'{"s":"\\ud800"}', b'{"s":"\\u0000"}',
                   b'{"a":' + b'[' * 64 + b'0' + b']' * 64 + b'}',
                   b'{"a":[' + b'0,' * 65536 + b'0]}']
        with patch('vampir_core.cdn_fallback.decrypt_cdn_fallback', side_effect=AssertionError('unexpected crypto')):
            for body in invalid:
                with self.subTest(size=len(body)), self.assertRaises(ValueError) as caught:
                    decode_cdn_config_document(body)
                self.assertNotIn('private', str(caught.exception))
        valid = b'{"a":' + b'[' * 63 + b'0' + b']' * 63 + b'}'
        self.assertIsInstance(decode_cdn_config_document(valid), dict)
        self.assertEqual(decode_cdn_config_document(b'{"s":"\\ud83d\\ude00"}')['s'], '😀')
        self.assertEqual(decode_cdn_config_document(b'{"s":"[\\\"{,]}"}')['s'], '["{,]}')

    def test_environment_schema_is_explicit_and_never_defaults_missing(self):
        for document in [{}, {'netmarbles': {'Zone': 'real'}}, {'NetmarbleS': None},
                         {'NetmarbleS': []}, {'NetmarbleS': {}}, {'NetmarbleS': {'zone': 'real'}},
                         {'NetmarbleS': {'Zone': 2}}, {'NetmarbleS': {'Zone': 'x' * 129}},
                         {'NetmarbleS': {'Zone': '\0real'}}, {'NetmarbleS': {'Zone': '\ud800'}}]:
            with self.assertRaises(ValueError):
                read_cdn_sdk_environment(document)

    def test_body_limits_and_invalid_documents_remain_errors(self):
        for body in [bytearray(b'{}'), b'x' * (MAX_BODY_BYTES + 1), b'', b'[]', b'null', b'not json']:
            with self.assertRaises(ValueError):
                decode_cdn_config_document(body)
        valid = b'{"s":"' + b'x' * (MAX_BODY_BYTES - 8) + b'"}'
        self.assertEqual(len(valid), MAX_BODY_BYTES)
        self.assertEqual(len(decode_cdn_config_document(valid)['s']), MAX_BODY_BYTES - 8)


if __name__ == '__main__':
    unittest.main()
