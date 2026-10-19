"""Native numeric/channel helpers, caller integration and portable field boundary."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.nid_result import channel_key_to_sdk_type, validate_nid_email_result_fields


class NidPrimitiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('nid_primitives_test', HERE / 'resource-tools/vampir/replay-nid-result-primitives.py')
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.config.native.ROOT / 'code-clues/nid-result-primitives.json').read_text('utf-8'))

    def test_reproduce_native_helpers_imports_and_initializers(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertEqual(len(self.report['evidence']['bindings']), 13)
        self.assertEqual([r['name'] for r in self.report['evidence']['imports']], ['_wtoi','_finite','iswspace','iswspace'])
        self.assertFalse(self.report['network_ready'])

    def test_numeric_permissiveness_and_real_caller_integration(self):
        numeric = {r['text']: r for r in self.report['numeric']}
        for value in ('0abc', '00abc', '0.1', '0x10'):
            self.assertTrue(numeric[value]['ok'])
            self.assertEqual(numeric[value]['value'], 0)
        self.assertFalse(numeric['abc']['ok'])
        self.assertFalse(numeric['']['ok'])
        self.assertEqual(numeric['2147483648']['value'], 2147483647)
        self.assertEqual([r['outcome'] for r in self.report['integration']],
            ['adoption_calls_reached','invalid_or_nonzero_result','invalid_or_nonzero_result',
             'adoption_calls_reached','unknown_channel','unknown_channel'])
        self.assertFalse(any(e['kind'].endswith('return_fixture') for c in self.report['integration'] for e in c['events']))

    def test_portable_channel_mapper_matches_native_ascii_cases(self):
        self.assertEqual(len(self.report['channels']), 45)
        for row in self.report['channels']:
            if row['text'].isascii():
                self.assertEqual(channel_key_to_sdk_type(row['text']), row['channel'])
            else:
                with self.assertRaises(ValueError):
                    channel_key_to_sdk_type(row['text'])
            self.assertTrue(row['guards_unchanged'])
        for bad in (None, 20, 'a' * 129, 'mailUserKey\0', 'mailUserKey\n'):
            with self.assertRaises(ValueError):
                channel_key_to_sdk_type(bad)

    def test_decoded_email_field_boundary_is_redacted_and_has_no_io(self):
        sample = dict(resultCode='0', accessToken='access-secret-fixture', refreshToken='',
                      channelKey='MAILUSERKEY', netmarbleId='id-private-fixture', joinedCountryCode='UA')
        credential = validate_nid_email_result_fields(sample)
        self.assertEqual(credential.channel_type, 20)
        self.assertEqual(credential.access_token, sample['accessToken'])
        self.assertEqual(credential.refresh_token, '')
        self.assertNotIn('secret', repr(credential))
        self.assertNotIn('private', repr(credential))
        self.assertEqual(validate_nid_email_result_fields({**sample, 'easyLoginToken':'discard-fixture', 'issueType':''}), credential)
        for key in sample:
            with self.assertRaises(ValueError):
                validate_nid_email_result_fields({k:v for k,v in sample.items() if k != key})
        invalid = [dict(resultCode=v) for v in ('0abc','00','+0','200','')]
        invalid += [dict(accessToken=''), dict(netmarbleId=''), dict(channelKey='googleIdKey'),
                    dict(joinedCountryCode='ua'), dict(joinedCountryCode=''), dict(unknown='value'),
                    dict(refreshToken='x\nsecret'), dict(accessToken='x'*8193)]
        for changes in invalid:
            with self.assertRaises(ValueError) as error:
                validate_nid_email_result_fields({**sample, **changes})
            self.assertNotIn('secret', str(error.exception))
            self.assertNotIn('private', str(error.exception))


if __name__ == '__main__':
    unittest.main()
