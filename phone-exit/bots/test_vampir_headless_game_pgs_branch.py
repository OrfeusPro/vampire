"""PGS is optional Windows unsupported branch, separate from original SDK success."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest


class GamePgsBranchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-game-pgs-branch.py'
        spec=importlib.util.spec_from_file_location('game_pgs_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/game-pgs-branch-replay.json').read_text('utf-8'))
        cls.cases={c['fixture']['name']:c for c in cls.report['cases']}

    def test_source_diagnostics_and_vtable(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),4)
        texts=[v['text'] for v in self.report['literals']]
        self.assertTrue(any('FPGSIDProvider::GetOrCreate(' in v for v in texts))
        self.assertTrue(any('FPGSIDProvider::SignIn(' in v for v in texts))
        table=bytes.fromhex(self.report['provider_vtable']['bytes'])
        self.assertEqual(struct.unpack_from('<Q',table,0x10)[0],0x1450c35e0)
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x1450b12d2]['operands'],'qword ptr [rdi], rax')
        self.assertEqual(rows[0x1450c3665]['direct_target'],0x1468e4100)
        self.assertEqual(rows[0x1450c3720]['direct_target'],0x1445342d0)

    def test_optional_and_error_gates(self):
        for name in ('no-game-instance','no-provider','original-error'):
            self.assertFalse(any(e['action']=='native_pgs_signin_entry' for e in self.cases[name]['events']))
        self.assertFalse(any(e['action']=='pgs_get_or_create_capture' for e in self.cases['original-error']['events']))
        for case in self.report['cases']:
            self.assertEqual(case['owner_strong_after'],4)
            self.assertEqual(case['original_response_field_4'],case['fixture']['field_4'])
            self.assertTrue(case['response_pair_preserved'])

    def test_native_provider_builds_separate_unsupported_result(self):
        events=self.cases['provider']['events']
        constructor=next(e for e in events if e['action']=='pgs_result_constructor_capture')
        self.assertEqual(constructor,dict(action='pgs_result_constructor_capture',arg_edx=400,arg_r8d=30020000,
                                         arg_r9d=1,message='platform is not supported'))
        delivery=next(e for e in events if e['action']=='pgs_result_delivery_capture')
        self.assertEqual(delivery['logging_target'],0x1455f7bd0)
        self.assertEqual((delivery['field_4'],delivery['field_c'],delivery['status']),(1,30020000,400))
        self.assertEqual(sum(e['action']=='pgs_function_clone_fixture' for e in events),1)
        self.assertEqual(sum(e['action']=='pgs_function_release_capture' for e in events),1)


if __name__=='__main__':
    unittest.main()
