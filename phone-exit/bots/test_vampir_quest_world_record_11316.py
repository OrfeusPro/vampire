"""Native map lookup must preserve synthetic record identity and derived initialization."""
import importlib.util
from pathlib import Path
import unittest


class WorldRecordTests(unittest.TestCase):
    def test_native_hash_collisions_missing_keys_and_initialization(self):
        p=Path(__file__).parent/'resource-tools/vampir/replay-quest-world-record-11316.py'
        spec=importlib.util.spec_from_file_location('world_record_replay',p)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        artifact,result=module.run()
        self.assertTrue(artifact.is_file());self.assertTrue(result['native_execution'])
        self.assertFalse(result['network_used']);self.assertFalse(result['action_admitted'])
        self.assertEqual(result['source_sha256'],module.SHA);self.assertEqual(len(result['exports']),4)
        self.assertEqual((result['lookup_stride'],result['lookup_value_offset']),(0x158,8))
        self.assertEqual(result['singleton'],'0x14b1c8cf0')
        self.assertEqual(len(result['initialized']),4)
        for row in result['initialized']:
            self.assertEqual((row['phase'],row['selected']),(7,[0]))
        expected={0:11,1:0,10012:7,10020:9,0xffffffff:0xdeadbeef}
        self.assertEqual(len(result['cases']),28)
        for row in result['cases']:
            present=not row['empty_counts'] and row['key'] in expected
            self.assertEqual(row['found'],present)
            self.assertEqual(row['field_0c'],expected[row['key']] if present else 0)
        for external in (False,True):
            rows=[r for r in result['cases'] if r['external_buckets']==external and not r['empty_counts']]
            self.assertEqual(sum(r['found'] for r in rows),5)


if __name__=='__main__':unittest.main()
