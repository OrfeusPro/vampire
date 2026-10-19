"""Native server choice/map lookup/target transfer, bounded before actual connection."""
import importlib.util
import json
from pathlib import Path
import unittest


class BeginGameServerTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-begin-game-server-target.py'
        spec=importlib.util.spec_from_file_location('begin_server_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/begin-game-server-target-replay.json').read_text('utf-8'))
        cls.cases={c['fixture']['name']:c for c in cls.report['cases']}

    def test_source_leaf_setters_and_lookup(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),11)
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        rows.update({r['address']:r for span in self.report['spans'] for r in span['instructions']})
        self.assertEqual(rows[0x14642588b]['direct_target'],0x145d39440)
        self.assertEqual(rows[0x144aab514]['operands'],'dword ptr [rax + 0x270], edx')
        self.assertEqual(rows[0x144aab524]['operands'],'word ptr [rax + 0x288], dx')
        self.assertEqual(rows[0x144aab4f4]['operands'],'word ptr [rax + 0x28a], dx')
        self.assertEqual(rows[0x145d394e1]['operands'],'rax, [rcx + 8]')

    def test_exact_target_transfer_and_collisions(self):
        for name in ('direct','fallback','collision-second','word-boundaries','empty-text'):
            c=self.cases[name];f=c['fixture']
            record=next(r for r in f['records'] if r['id']==42)
            self.assertEqual(c['stop'],'target_setters_completed',name)
            self.assertEqual(c['target_id'],42)
            self.assertEqual(c['target_text'],record['text'])
            self.assertEqual(c['target_words'],[record['word_30'],record['word_32']])
            self.assertEqual(c['busy_after'],1)
        self.assertEqual(self.cases['fallback']['selected_id'],42)

    def test_missing_busy_and_zero_preserve_existing_target(self):
        expected={'missing-id':'server_missing','empty-map':'server_missing','collision-miss':'server_missing',
                  'busy':'already_busy','zero-empty':'server_missing','zero-selection':'zero_id_selection_branch'}
        for name,stop in expected.items():
            c=self.cases[name]
            self.assertEqual(c['stop'],stop,name)
            self.assertEqual((c['target_id'],c['target_text'],c['target_words']),
                             (777,'old-target-fixture',[111,222]))
            self.assertEqual(c['busy_after'],int(c['fixture']['busy']))
        self.assertEqual(len(self.cases['zero-selection']['events']),3)


if __name__=='__main__':
    unittest.main()
