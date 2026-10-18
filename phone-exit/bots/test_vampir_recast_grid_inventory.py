import importlib.util,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('recast_grid',Path(__file__).parent/'resource-tools/vampir/build-recast-grid-inventory.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class RecastGridInventoryTests(unittest.TestCase):
    def tile(self,sha='a',grid=None,layer=0):return dict(source_tile_sha256=sha,grid_raw=grid or [1,2],layer_raw=layer)

    def test_identical_duplicates_keep_all_sources(self):
        result=module.inventory([self.tile(),self.tile()])
        self.assertEqual(result['summary']['grid_keys'],1)
        self.assertEqual(result['summary']['identical_duplicate_occurrences'],1)
        self.assertEqual(len(result['tiles'][0]['sources']),2)
        self.assertFalse(result['summary']['runtime_selection_verified'])

    def test_conflicting_buffers_are_quarantined_without_winner(self):
        result=module.inventory([self.tile('a'),self.tile('b'),self.tile('a')])
        self.assertEqual(result['tiles'],[])
        self.assertEqual(result['conflicts'][0]['buffer_hashes'],['a','b'])
        self.assertEqual(result['summary']['conflicting_grid_keys'],1)

    def test_grid_order_and_layer_are_part_of_identity(self):
        result=module.inventory([self.tile(),self.tile(grid=[2,1]),self.tile(layer=1)])
        self.assertEqual(result['summary']['grid_keys'],3)
        with self.assertRaises(ValueError):module.inventory([self.tile(grid=[True,2])])


if __name__=='__main__':unittest.main()
