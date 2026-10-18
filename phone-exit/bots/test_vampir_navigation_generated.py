import copy,importlib.util,struct,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('generated_nav',Path(__file__).parent/'resource-tools/vampir/build-navigation-generated-chunks.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class GeneratedNavigationTests(unittest.TestCase):
    def fixture(self):
        return dict(exports=[dict(index=4,name='Nocturne',type='World',outer=0,offset=100,size=4),
            dict(index=2,name='PersistentLevel',type='Level',outer=4,offset=104,size=4),
            dict(index=1,name='Actor',type='NavigationDataChunkActor',outer=2,offset=108,size=4),
            dict(index=3,name='Chunk',type='RecastNavMeshDataChunk',outer=1,offset=112,size=8)])

    def test_summary_identity_is_not_inferred_from_an_imported_path(self):
        data=bytes.fromhex('c1832a9e')+bytes(28)+struct.pack('<i',4)+b'Own\0'
        self.assertEqual(module.package_path(data+b'/Game/RED/Level/Field/Nocturne/Nocturne'),'Own')
        with self.assertRaises(ValueError):module.package_path(data[:-1])

    def test_export_ranges_and_full_actor_level_world_ownership_are_required(self):
        parsed=self.fixture()
        self.assertEqual(module.validate_exports(parsed,100,24)[0]['index'],3)
        for index,key,value in [(3,'outer',2),(2,'outer',4),(0,'name','Other'),(3,'offset',113),(2,'offset',104)]:
            changed=copy.deepcopy(parsed);changed['exports'][index][key]=value
            with self.assertRaises(ValueError):module.validate_exports(changed,100,24)
        with self.assertRaises(ValueError):module.validate_exports(parsed,100,28)

if __name__=='__main__':unittest.main()
