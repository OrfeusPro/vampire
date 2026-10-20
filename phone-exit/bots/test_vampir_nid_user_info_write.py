import importlib.util
import json
from pathlib import Path
import unittest


class NidUserInfoWriteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-nid-user-info-write.py'
        spec = importlib.util.spec_from_file_location('nid_writer_replay_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.saved = json.loads((cls.tool.native.ROOT / 'code-clues/nid-user-info-write-replay.json').read_text('utf-8'))

    def test_full_native_writer_reproduces(self):
        self.assertEqual(self.tool.build(), self.saved)
        self.assertEqual(len(self.saved['cases']), 12)

    def test_direct_getter_callers_reproduce_with_explicit_decode_gap(self):
        path = Path(__file__).parent / 'resource-tools/vampir/build-nid-user-info-callers.py'
        spec = importlib.util.spec_from_file_location('nid_user_info_callers_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        saved = json.loads((tool.native.ROOT / 'code-clues/nid-user-info-callers.json').read_text('utf-8'))
        self.assertEqual(tool.build(), saved)
        self.assertEqual(len(saved['calls']), 56)
        self.assertEqual(saved['failed_roots'], ['0x14458f270'])
        self.assertEqual({r['root'] for r in saved['calls'] if r['target'] == '0x144521e80'},
                         {'0x1444c1ad0', '0x144588bb0', '0x145604090'})

    def test_field_markers_establish_identity_and_keep_distinct_values_separate(self):
        expected = {'I_GameCode': '0x0a0', 'I_GameVersion': '0x080', 'I_PID': '0x150',
                    'I_CountryCD': '0x100', 'I_JoinedCountryCode': '0x170', 'I_World': '0x190',
                    'I_SDKVersion': '0x090', 'I_NMNID': '0x230', 'I_NMCPU': '0x1f0',
                    'I_NMRAM': '0x200', 'I_NMVGA': '0x210'}
        for case in (self.saved['cases'][0], self.saved['cases'][6]):
            mapping = {r['key']: r['offset'] for r in case['field_mapping']}
            self.assertEqual(len(mapping), 33)
            for key, offset in expected.items(): self.assertEqual(mapping[key], offset)
            pairs = {p['key']: p['value'] for p in case['pairs']}
            self.assertEqual(len(pairs), 39)
            self.assertEqual(pairs['I_NMDeviceKey'], 'getter-0x1444e5ff0')
            self.assertNotEqual(pairs['I_NMDeviceKey'], pairs['I_PID'])

    def test_optional_identity_fields_and_mode_getter_gates(self):
        for case in self.saved['cases']:
            pairs = {p['key']: p['value'] for p in case['pairs']}
            fields = case['initial_fields']
            for key, offset in (('I_GameCode', '0xa0'), ('I_NMBuildCode', '0xb0')):
                self.assertEqual(key in pairs, bool(fields[offset]))
            self.assertEqual('I_NMNID' in pairs, bool(fields['0x230']))
            self.assertEqual('I_NMNIDChannelType' in pairs, bool(fields['0x230']))
            if fields['0x230']: self.assertEqual(pairs['I_NMNIDChannelType'], fields['0x240'])
            self.assertEqual(case['overwritten_fields']['0x50'], 'getter-0x1444e5ff0')
            self.assertEqual(case['overwritten_fields']['0x70'],
                             'getter-0x1444e3ac0' if case['fixture']['mode'] else '')


if __name__ == '__main__': unittest.main()
