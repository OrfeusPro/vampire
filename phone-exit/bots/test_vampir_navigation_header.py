import importlib.util,struct,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('nav_header',Path(__file__).parent/'resource-tools/vampir/decode-navigation-header.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class NavigationHeaderTests(unittest.TestCase):
    def fixture(self,minimum=(1.,2.,3.),maximum=(4.,5.,6.),count=1,ref=0):
        path=b'/Game/__ExternalActors__/World/Chunk\0'
        return struct.pack('<Hiii',0x701,10,count,1)+struct.pack('<Hi',0x700,ref)+struct.pack('<i',len(path))+path+struct.pack('<ddddddBI',*minimum,*maximum,1,0)
    def test_chunk_reference_path_and_bounds_are_preserved_without_walkability(self):
        result=module.decode(self.fixture())
        self.assertEqual(result['num_chunks'],1)
        self.assertEqual(result['num_max_tiles'],10)
        self.assertEqual(result['chunks'][0]['bounds']['minimum'],[1.,2.,3.])
        self.assertEqual(result['chunks'][0]['asset_file_path'],'/Game/__ExternalActors__/World/Chunk')
        self.assertFalse(result['walkability_verified'])
        self.assertFalse(result['chunks'][0]['walkable_polygon'])
    def test_invalid_counts_bounds_and_truncation_fail(self):
        for raw in [self.fixture(count=2),self.fixture(minimum=(9.,2.,3.)),self.fixture(maximum=(float('inf'),5.,6.)),self.fixture()[:-1],self.fixture()+b'\0']:
            with self.assertRaises(ValueError):module.decode(raw)
    def test_unknown_schema_cannot_be_silently_decoded(self):
        raw=bytearray(self.fixture());raw[:2]=struct.pack('<H',0x702)
        with self.assertRaises(ValueError):module.decode(raw)
if __name__=='__main__':unittest.main()
