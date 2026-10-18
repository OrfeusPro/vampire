"""Navigation resource strings are evidence, not a validated connectivity graph."""
import importlib.util,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('navigation_sources',Path(__file__).parent/'resource-tools/vampir/build-navigation-sources.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class NavigationSourceTests(unittest.TestCase):
    def test_resource_references_preserve_byte_offset_and_do_not_claim_relation(self):
        path=b'/Game/__ExternalActors__/RED/Level/Field/Nocturne/A/BC/ABC123'
        rows=module.references(b'\x00\x01'+path+b'\x00tail')
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['path'],path.decode())
        self.assertEqual(rows[0]['byte_offset'],2)
        self.assertFalse(rows[0]['relation_verified'])
    def test_repeated_paths_keep_distinct_source_locations(self):
        rows=module.references(b'/Game/A\x00/Game/A\x00')
        self.assertEqual([r['byte_offset'] for r in rows],[0,8])
        self.assertEqual([r['path'] for r in rows],['/Game/A','/Game/A'])
    def test_arbitrary_binary_is_not_a_path_graph(self):
        self.assertEqual(module.references(b'\x01\x02Nocturne_Nav.bin\x00'),[])
if __name__=='__main__':unittest.main()
