import importlib.util
import json
from pathlib import Path
import unittest


class LoginLanguageEvidenceTests(unittest.TestCase):
    def test_source_bound_localization_store_and_diagnostics(self):
        path=Path(__file__).parent/'resource-tools/vampir/build-login-language-evidence.py'
        spec=importlib.util.spec_from_file_location('login_language_evidence_test',path)
        tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
        actual=tool.build()
        saved=json.loads((tool.native.ROOT/'code-clues/login-language-evidence.json').read_text('utf-8'))
        self.assertEqual(actual,saved)
        self.assertEqual([(s['address'],s['bytes']) for s in actual['byte18_stores']],[(0x145570338,'884618')])
        texts={r['address']:r['text'] for r in actual['literals']}
        self.assertEqual(texts['0x1498a9830'],'FNnLocalizationManager::UpdateLanguageCode()')
        self.assertEqual(texts['0x1494e0618'],'en-US')
        self.assertEqual(texts['0x1494e0628'],'ko-KR')
        self.assertEqual(texts['0x1494e0638'],'ja-JP')
        self.assertTrue(next(r for r in actual['literals'] if r['address']=='0x1498a9830')['references'])


if __name__=='__main__':unittest.main()
