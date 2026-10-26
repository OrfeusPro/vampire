"""Native progress lookup consumes actual native-loaded six-row task records."""
import importlib.util
from pathlib import Path
import struct
import unittest

class QuestLoaderProjectionTests(unittest.TestCase):
    def test_lookup_and_progress_use_loaded_array_in_both_source_orders(self):
        root=Path(__file__).parent/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('quest_loader_projection',root/'replay-quest-loader-11316.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        target,result=module.run(root/'knowledge/native-contexts/quest-loader-projection-11316.json')
        self.assertTrue(target.is_file());self.assertTrue(result['native_projection'])
        self.assertFalse(result['network_used']);self.assertFalse(result['order_admitted'])
        self.assertEqual(len(result['runs']),2)
        original=['110120005','110120010','110120020','110120030','110120040','110120070']
        for run in result['runs']:
            ids=list(reversed(original)) if run['reverse'] else original
            self.assertEqual(run['task_ids'],ids);self.assertEqual(run['records'],6);self.assertEqual(run['group_count'],1)
            self.assertEqual(len(run['native_projections']),18)
            for p in run['native_projections']:
                self.assertEqual(p['quest_id'],'110120');self.assertEqual(p['task_id'],ids[p['index']])
                raw=bytes.fromhex(p['progress_hex'])
                self.assertEqual(struct.unpack_from('<QBB',raw), (int(p['task_id']),p['kind'],p['index']))
                self.assertEqual(struct.unpack_from('<II',raw,12),(p['first']&0xffffffff,p['second']&0xffffffff))
                self.assertEqual(raw[24:],bytes(8))
            self.assertEqual(run['native_projections'][0]['kind'],6)
            self.assertTrue(run['group_order_matches_records'])
        self.assertEqual(result['runs'][0]['native_projections'][0]['task_id'],'110120005')
        self.assertEqual(result['runs'][1]['native_projections'][0]['task_id'],'110120070')

if __name__=='__main__':unittest.main()
