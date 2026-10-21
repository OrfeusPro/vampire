"""Current ID206 whole-reader collections: native execution, no game IO."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE=Path(__file__).parent


class ReleaseWorldFinishCollectionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tool=(HERE/'resource-tools/vampir/replay-release-world-finish-collections.py').resolve()
        run=subprocess.run([sys.executable,'-X','utf8',str(tool)],cwd=HERE.parents[1],
            capture_output=True,text=True,encoding='utf-8',check=True,timeout=120)
        cls.report=json.loads(Path(json.loads(run.stdout)['report']).read_text('utf-8'))
        spec=importlib.util.spec_from_file_location('finish_collections_test',tool)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)

    def test_whole_reader_matches_all_collection_fields_and_reference_counts(self):
        r=self.report
        self.assertEqual(r['source_sha256'],'98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e')
        self.assertTrue(r['native_execution']);self.assertFalse(r['network_used'])
        self.assertEqual(len(r['cases']),24)
        self.assertTrue(all(c['fields_match'] for c in r['cases']))
        self.assertTrue(any(c['counts']=={'0xb8':205,'0xc8':0,'0xe8':1,'0x100':0} for c in r['cases']))
        self.assertTrue(any(all(n==8 for n in c['counts'].values()) for c in r['cases']))

    def test_every_short_prefix_of_joint_optional_body_is_rejected(self):
        self.assertEqual([c['size'] for c in self.report['short']],list(range(286)))
        self.assertTrue(all(c['consumed']<=c['size'] for c in self.report['short']))

    def test_reviewed_leaf_boundaries_and_storage_limit(self):
        leaves={c['address']:c for c in self.report['leaves']}
        self.assertIn('0x145821190',leaves);self.assertIn('0x1457a45a0',leaves)
        h=self.tool.make_harness()
        with self.assertRaisesRegex(ValueError,'fresh bounded container'):
            h.read_finish(self.tool.body_bytes(counts=(257,0,0,0)))


if __name__=='__main__':unittest.main()
