import importlib.util,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('chunk_headers',Path(__file__).parent/'resource-tools/vampir/search-navigation-chunk-headers.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class ChunkHeaderTests(unittest.TestCase):
    def test_exact_leaf_can_be_found_without_game_path_and_remains_candidate(self):
        result=module.matches(b'\x00ABC123\0Class\0',{'ABC123'})
        self.assertEqual(result,[dict(kind='external_actor_leaf',text='ABC123',offset=1,relation_verified=False)])
        self.assertEqual(module.matches(b'prefixXABC123Zsuffix',{'ABC123'}),[])

    def test_class_requires_full_name_and_does_not_certify_payload(self):
        self.assertEqual(module.matches(b'NnDataAssetRefNavMeshChunkExtra\0',set()),[])
        result=module.matches(b'abcNnDataAssetRefNavMeshChunk\0',set())
        self.assertEqual(result[0]['text'],'NnDataAssetRefNavMeshChunk')
        self.assertFalse(result[0]['relation_verified'])

if __name__=='__main__':unittest.main()
