import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.nid_metadata import NID_METADATA_KEYS, encode_base_nid_metadata


def encode(values, **changed):
    return encode_base_nid_metadata(values, **dict(user_info_available=True, optional_device_key=False,
                                                   marketing_attribution=False, **changed))


class NidMetadataTests(unittest.TestCase):
    def test_native_collector_and_selector_reproduce(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-nid-metadata.py'
        spec = importlib.util.spec_from_file_location('nid_metadata_replay_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        saved = json.loads((tool.native.ROOT / 'code-clues/nid-metadata-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), saved)
        self.assertEqual(len(saved['cases']), 6)
        self.assertEqual(tuple(saved['cases'][0]['selected_keys']), NID_METADATA_KEYS)
        for case in saved['cases']:
            if any('"' in v or '\\' in v for v in case['map_fixture'].values()):
                with self.assertRaises(ValueError): encode(case['map_fixture'])
                continue
            values = case['map_fixture'] if case['user_info_available'] else {}
            self.assertEqual(encode_base_nid_metadata(values, user_info_available=case['user_info_available'],
                optional_device_key=False, marketing_attribution=False), case['output'])

    def test_repeated_world_empty_and_missing_values_remain_distinct(self):
        self.assertEqual(encode({'I_World': '251'}), '{"I_World":"251","I_World":"251"}')
        self.assertEqual(encode({}), '{}')
        self.assertEqual(encode({'I_PID': '', 'unselected': 'ignored'}), '{"I_PID":""}')
        self.assertEqual(encode_base_nid_metadata({}, user_info_available=False,
            optional_device_key=False, marketing_attribution=False), '')

    def test_rejects_unsupported_branches_and_unescaped_or_excessive_values(self):
        for value in (None, 42, 'quote"', 'slash\\', 'line\n', '\0', '\ud800', 'x' * 4097):
            with self.subTest(value=repr(value)[:20]), self.assertRaises(ValueError): encode({'I_PID': value})
        with self.assertRaises(ValueError): encode({k: 'Ж' * 4096 for k in NID_METADATA_KEYS})
        for branch in ('optional_device_key', 'marketing_attribution'):
            args = dict(user_info_available=True, optional_device_key=False, marketing_attribution=False)
            args[branch] = True
            with self.assertRaises(NotImplementedError): encode_base_nid_metadata({}, **args)
        with self.assertRaises(ValueError):
            encode_base_nid_metadata({'I_PID': 'value'}, user_info_available=False,
                optional_device_key=False, marketing_attribution=False)


if __name__ == '__main__': unittest.main()
