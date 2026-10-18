import importlib.util,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('nav_search',Path(__file__).parent/'resource-tools/vampir/search-navigation-payloads.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class NavigationPayloadSearchTests(unittest.TestCase):
    def test_magic_candidates_preserve_offsets_without_claiming_navigation(self):
        rows=module.matches(b'xxVAND\x00yyVAND',set())
        self.assertEqual([r['offset'] for r in rows],[2,9])
        self.assertTrue(all(not r['relation_verified'] for r in rows))
    def test_external_actor_tokens_are_exact_and_empty_bytes_do_not_match(self):
        rows=module.matches(b'xxABC123yy',{'ABC123','NOPE'})
        self.assertEqual([(r['needle'],r['offset']) for r in rows],[('ABC123',2)])
        self.assertEqual(module.matches(b'',{'ABC123'}),[])
    def test_repeated_signatures_have_a_bounded_result(self):
        self.assertEqual(len(module.matches(b'VAND'*101,set())),100)
if __name__=='__main__':unittest.main()
