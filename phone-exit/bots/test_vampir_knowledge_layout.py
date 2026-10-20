import importlib.util
import json
import re
from pathlib import Path
import subprocess
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class KnowledgeLayoutTests(unittest.TestCase):
    def test_all_local_document_links_resolve(self):
        checker = load('knowledge_links_test', 'check-knowledge.py')
        result = checker.check()
        self.assertGreater(result['markdown_links_checked'], 1000)
        self.assertEqual(result['broken'], [])

    def test_evidence_content_is_preserved_except_rebased_links(self):
        migration = load('knowledge_migration_test', 'regroup-documentation.py')
        data = json.loads((HERE / 'knowledge/document-locations.json').read_text('utf-8'))
        workspace = migration.WORKSPACE
        moved = {workspace / r['old']: workspace / r['current'] for r in data['documents'] if r['topic'] != 'history'}
        archived = {workspace / r['old']: workspace / r['current'] for r in data['documents'] if r['topic'] == 'history'}
        for old, new in moved.items():
            self.assertFalse(old.exists(), old)
            original = subprocess.check_output(['git', 'show', data['source_commit'] + ':' + old.relative_to(workspace).as_posix()], cwd=workspace).decode('utf-8-sig').replace('\r\n', '\n')
            expected = migration.rebase(original, old, new, moved, archived)
            self.assertEqual(new.read_text('utf-8'), expected, new)
        self.assertEqual(len({row['topic'] for row in data['documents'] if row['topic'] != 'history'}), 9)
        for old, new in archived.items():
            original = subprocess.check_output(['git', 'show', data['source_commit'] + ':' + old.relative_to(workspace).as_posix()], cwd=workspace).decode('utf-8-sig').replace('\r\n', '\n')
            expected = migration.rebase(original, old, new, moved, archived)
            observed = re.sub(r'\n> Исторический снимок[^\n]*\n> Старые[^\n]*\n> Актуальное[^\n]*\n', '', new.read_text('utf-8'), count=1)
            self.assertEqual(observed, expected, new)


if __name__ == '__main__':
    unittest.main()
