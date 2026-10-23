"""Public terms shape is not consent; all inputs are synthetic/offline."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.sdk_terms import plan_basic_terms_read, plan_individual_terms_read, parse_basic_terms_summary


class SdkTermsTests(unittest.TestCase):
    def inputs(self):
        return dict(constants={'termsUrl': 'https://terms-api.netmarble.com'}, game_code='thered',
                    country='UA', locale='en-US', platform='PC', filtered=False)

    def test_explicit_public_query_and_branch(self):
        plan = plan_basic_terms_read(**self.inputs())
        self.assertEqual(plan.method, 'GET')
        self.assertEqual(plan.url, 'https://terms-api.netmarble.com/game/v2/thered/terms?country=UA&locale=en-US&platform=PC')
        self.assertIn('/terms/filtered/unique?', plan_basic_terms_read(**dict(self.inputs(), filtered=True)).url)
        for overrides in (dict(country=''), dict(locale='en&token=secret'), dict(game_code='../account'),
                          dict(platform='Android'), dict(filtered=1), dict(constants={'termsUrl': 'http://terms-api.netmarble.com'}),
                          dict(constants={'termsUrl': 'https://user:pass@terms-api.netmarble.com'})):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                plan_basic_terms_read(**dict(self.inputs(), **overrides))

    def test_no_data_empty_and_available_never_assert_consent(self):
        cases = [(b'{"resultCode":-1,"resultData":{"terms":[]},"resultMessage":"NO DATA"}', 'no_data', 0),
                 (b'{"resultCode":0,"resultData":{"terms":[]}}', 'empty', 0),
                 (b'{"resultCode":0,"resultData":{"terms":[{"url":"private-fixture","title":"fixture"}]}}', 'terms_available', 1)]
        for body, state, count in cases:
            result = parse_basic_terms_summary(status=200, body=body)
            self.assertEqual((result.state, result.terms_count), (state, count))
            self.assertFalse(result.consent_confirmed)
            self.assertFalse(result.sdk_creation_ready)
            self.assertNotIn('private-fixture', repr(result))

    def test_individual_no_player_query_is_separate_from_basic_array(self):
        inputs = dict(self.inputs(), terms_name='terms_of_service_ko')
        del inputs['filtered']
        plan = plan_individual_terms_read(**inputs)
        self.assertEqual(plan.method, 'GET')
        self.assertEqual(plan.url, 'https://terms-api.netmarble.com/game/v2/thered/terms/terms_of_service_ko?country=UA&locale=en-US&termsType=I&platform=PC')
        for overrides in (dict(terms_name='../other'), dict(country=''), dict(locale='en?x=y'),
                          dict(platform='Android'), dict(constants={'termsUrl': 'https://example.org'})):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                plan_individual_terms_read(**dict(inputs, **overrides))
        # Public individual NO DATA has an object with null fields, not a basic terms array.
        body = b'{"resultCode":-1,"resultData":{"terms":{"title":null,"url":null}}}'
        with self.assertRaises(ValueError):
            parse_basic_terms_summary(status=200, body=body)

    def test_ambiguous_or_failed_response_stops(self):
        for body in (b'{"resultCode":true,"resultData":{"terms":[]}}',
                     b'{"resultCode":0,"resultCode":-1,"resultData":{"terms":[]}}',
                     b'{"resultCode":-1,"resultData":{"terms":[{}]}}',
                     b'{"resultCode":42,"resultData":{"terms":[]}}',
                     b'{"resultCode":0,"resultData":{"terms":[1]}}',
                     b'{"resultCode":0,"resultData":{"terms":[]},"x":NaN}',
                     b'{"resultCode":0}', b'x' * 524289):
            with self.subTest(body=body[:100]), self.assertRaises(ValueError):
                parse_basic_terms_summary(status=200, body=body)
        with self.assertRaises(ValueError):
            parse_basic_terms_summary(status=400, body=cases_body())

    def test_current_source_keys_get_method_and_callback_provenance(self):
        path = Path(__file__).parent / 'resource-tools/vampir/build-native-entry-code.py'
        spec = importlib.util.spec_from_file_location('terms_source_test', path)
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        sha = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
        raw = (native.ROOT / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), sha)
        image = native.Image(raw)
        folder = native.ROOT / 'ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details'
        for run, digest in (('run-b3245757b183', 'c3598cec6dd815f76ffa191424a096af5cedfe94f5d74ed7e5301c35e69a626c'),
                            ('run-4855ed8063c4', '363d3050bc6cf769014003e267ca2226e51caa4e9817f6e612c03db7633745aa'),
                            ('run-ac97599e2191', '81ff7f6647afcd199648e8951c39ca30fb4e13b30d70a2487d926af2d0a441bf'),
                            ('run-006adfae88f9', '8a17f0d348ee3ceb45424666e5f43611d6d0ffb5887fabdd07ad48f01a72897a'),
                            ('run-61bf93179385', '21adce1460632974a791d1e957058596d17bcb6ec04e336e3488686be04bef4c'),
                            ('run-870ba3c30a43', '6b08dda0178d473c5daa6d4a3ef497340ad10eb91f66342967ecfeef7d4a95f0')):
            payload = (folder / run / 'details.json').read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)
            report = json.loads(payload)
            self.assertEqual(report['new_source_sha256'], sha)
            for function in report['functions']:
                self.assertTrue(function['decompilation_completed'])
                for row in function['instructions']:
                    offset = image.offset(int(row['address'], 16) - image.pe.base)
                    code = bytes.fromhex(row['bytes'])
                    self.assertEqual(raw[offset:offset + len(code)], code)
        for address, text in ((0x14952d348, 'resultCode'), (0x14952d3b0, 'resultData'),
                              (0x14985b958, 'terms_of_service_ko'), (0x148a919b8, 'I'),
                              (0x149549ff0, 'termsType'), (0x14954a008, '{0}/game/v2/{1}/terms/{2}?{3}')):
            offset = image.offset(address - image.pe.base)
            encoded = (text + '\0').encode('utf-16le')
            self.assertEqual(raw[offset:offset + len(encoded)], encoded)
        offset = image.offset(0x14953a0d0 - image.pe.base)
        signature = raw[offset:raw.find(b'\0', offset)].decode('ascii')
        self.assertIn('FNetworkManagerImpl::CreateGet(', signature)
        offset = image.offset(0x1445744b0 - image.pe.base)
        self.assertEqual(raw[offset:offset + 5], bytes.fromhex('e9bb63ffff'))
        offset = image.offset(0x1445744c0 - image.pe.base)
        self.assertEqual(raw[offset:offset + 5], bytes.fromhex('e94b70ffff'))
        offset = image.offset(0x149549ba0 - image.pe.base)
        self.assertEqual(int.from_bytes(raw[offset + 0x30:offset + 0x38], 'little'), 0x144586be0)


def cases_body():
    return b'{"resultCode":0,"resultData":{"terms":[]}}'


if __name__ == '__main__': unittest.main()
