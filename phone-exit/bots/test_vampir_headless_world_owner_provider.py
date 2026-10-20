import importlib.util
import json
from pathlib import Path
import unittest


class WorldOwnerProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-world-owner-provider.py'
        spec = importlib.util.spec_from_file_location('test_world_owner_provider', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT / 'code-clues/world-owner-provider-replay.json').read_text('utf-8'))

    def test_whole_factory_reproduces(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertEqual(len(self.report['cases']), 8)
        self.assertFalse(self.report['network_ready'])
        self.assertFalse(self.report['active_world_class_verified'])

    def test_default_class_reaches_spawn_and_result_survives_cleanup(self):
        for case in self.report['cases']:
            events = case['events']
            self.assertEqual(case['table'], self.tool.TABLE)
            self.assertEqual([e['action'] for e in events], [
                'base_constructor_capture', 'native_factory', 'world_settings_capture',
                'empty_string_capture', 'empty_string_capture', 'native_class_copy',
                'spawn_parameters_capture', 'spawn_capture', 'url_cleanup_capture'])
            selected = 0x23005000 if case['alternate_default'] else 0x23004000
            self.assertEqual(events[5]['incoming'], selected)
            self.assertEqual(events[7]['selected_class'], selected)
            self.assertEqual(events[7]['world'], 0x23001000)
            expected = 0 if case['spawn_null'] else 0x23009000
            self.assertEqual(case['result'], expected)
            self.assertEqual(events[7]['result'], expected)

    def test_provider_identity_and_inherited_slots(self):
        self.assertEqual([r['text'] for r in self.report['registration_literals']],
                         ['GameInstance', '/Script/Engine', 'RdGameInstance', '/Script/ProjectRED'])
        self.assertEqual(len(self.report['provider_tables']), 3)
        for table in self.report['provider_tables']:
            self.assertEqual([(s['slot'], s['target']) for s in table['slots']],
                             [(0x3d0, self.tool.FACTORY), (0x3e0, 0x14178c590)])
        descriptor = self.report['default_class_descriptor']
        self.assertEqual((descriptor['name'], descriptor['object_offset']), ('DefaultGameMode', 0x348))


if __name__ == '__main__':
    unittest.main()
