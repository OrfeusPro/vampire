"""Check Ghidra export integrity and links against existing native evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).parent/'resource-tools/vampir'


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,HERE/filename)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


class GhidraExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool=module('ghidra_manifest_test','build-ghidra-manifest.py')
        latest_path=cls.tool.ROOT/'ghidra/latest-export.json'
        if not latest_path.exists():raise unittest.SkipTest('Run the pinned Ghidra batch first')
        cls.latest=json.loads(latest_path.read_text('utf-8'));cls.out=Path(cls.latest['output'])
        cls.report=json.loads((cls.out/'functions.json').read_text('utf-8'))

    def test_manifest_ranges_match_the_client_and_existing_evidence(self):
        manifest=self.tool.build()
        self.assertEqual(manifest,json.loads((self.tool.ROOT/'ghidra/entry-manifest.json').read_text('utf-8')))
        raw=Path(manifest['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),self.report['source_sha256'])
        for function in manifest['functions']:
            for r in function['ranges']:
                length=int(r['end_exclusive'],16)-int(r['start'],16)
                self.assertEqual(hashlib.sha256(raw[r['file_offset']:r['file_offset']+length]).hexdigest(),r['sha256'])

    def test_every_requested_function_has_hash_verified_pseudocode(self):
        verifier=module('ghidra_verify_test','verify-ghidra-export.py')
        result=verifier.verify(self.out)
        self.assertEqual(result['functions'],22)
        self.assertEqual(self.report['ghidra_version'],'12.1.4')
        self.assertFalse(self.report['game_executed'])
        self.assertFalse(self.report['whole_program_analysis'])
        self.assertEqual(hashlib.sha256((self.out/'functions.json').read_bytes()).hexdigest(),self.latest['report_sha256'])
        for function in self.report['functions']:
            self.assertGreater(function['instruction_count'],0)
            self.assertIn(function['name'],(self.out/function['pseudocode_file']).read_text('utf-8'))

    def test_known_call_edges_resolve_to_shared_names(self):
        functions={f['name']:f for f in self.report['functions']}
        for caller,callee in (('VersionResult_Handler','Login_Prepare'),('Login_Prepare','PktLogin_Constructor'),
            ('PktLogin_Write','Archive_WriteFString'),('Version_Prepare','PktVersion_Constructor')):
            targets={t.get('name') for c in functions[caller]['calls'] for t in c['targets']}
            self.assertIn(callee,targets)
            self.assertIn(callee+'(',(self.out/functions[caller]['pseudocode_file']).read_text('utf-8'))


if __name__=='__main__':
    unittest.main()
