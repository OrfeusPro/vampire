"""Offline installed-mode configuration check, separate from the accumulated UI suite."""
import importlib.util
import json
from pathlib import Path
import unittest
HERE=Path(__file__).parent/'resource-tools/vampir'
spec=importlib.util.spec_from_file_location('installed_cold_replay',HERE/'replay-ui-config-installed-cold.py')
cold=importlib.util.module_from_spec(spec);spec.loader.exec_module(cold)


class InstalledConfigTests(unittest.TestCase):
    def test_native_cached_source_normalizer_and_physical_resolver_chain(self):
        source=json.loads((cold.native.ROOT/'code-clues/ui-properties.json').read_text('utf-8'))['source']
        base=dict(source=source,source_sha256=cold.getter.SHA,question='ui-nktileview-property-schema')
        req=lambda addresses:dict(base,functions=[dict(address=hex(a)) for a in addresses])
        result=cold.run(req(cold.ROOTS),req(cold.PREDICATES),req((0x1414324d0,)),
            req((0x141459960,0x141435f10,0x1414891c0,0x1415ca400)),req((0x141584080,0x1414833a0)))
        self.assertTrue(result['native_source_chain'])
        self.assertEqual(len(result['cases']),384)
        self.assertEqual(len(result['leaves']),2)
        self.assertEqual(result['dispatch']['next_backend'],'0x1415c6140 fixture')
        self.assertEqual({c['platform_mode'] for c in result['cases']},
            {'resolver_ready','resolver_empty_physical_ready','resolver_empty_physical_init'})
        for case in result['cases']:
            self.assertTrue(case['normalizer_native'])
            self.assertNotIn(chr(92),case['constructed_path'])
            self.assertNotIn('base_directory',case['services'])
            self.assertNotIn('normalize_fixture',case['services'])
            self.assertNotIn('platform_manager',case['services'])
            self.assertNotIn('platform_resolver',case['services'])
            self.assertTrue(case['cached_repeat'])

    def test_cold_mode_uses_native_path_flags_and_file_backed_dispatch_then_cache(self):
        source=json.loads((cold.native.ROOT/'code-clues/ui-properties.json').read_text('utf-8'))['source']
        base=dict(source=source,source_sha256=cold.getter.SHA,question='ui-nktileview-property-schema')
        req=lambda addresses:dict(base,functions=[dict(address=hex(a)) for a in addresses])
        result=cold.run(req(cold.ROOTS),req(cold.PREDICATES),req((0x1414324d0,)))
        self.assertEqual(len(result['cases']),128)
        self.assertEqual(result['dispatch']['target'],'0x141465720')
        self.assertEqual(result['dispatch']['next_slot'],'0x78')
        for case in result['cases']:
            self.assertTrue(case['cached_repeat'])
            self.assertTrue(case['complete_return'])
            self.assertEqual(case['services'].count('backend_query'),1)
            if case['query_result_fixture'] and case['command_line_fixture']=='-NotInstalled':
                self.assertEqual(case['result'],0)
            if not case['query_result_fixture'] and case['command_line_fixture']=='-Installed':
                self.assertEqual(case['result'],1)


if __name__=='__main__':unittest.main()
