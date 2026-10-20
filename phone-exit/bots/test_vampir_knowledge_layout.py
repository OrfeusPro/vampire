import importlib.util
import json
import re
from pathlib import Path
import subprocess
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'
# Audit the move itself; evidence remains editable as research advances.
MIGRATION_COMMIT = 'ee90fb9cceb2e81864089646c2c80fdf41235897'


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

    def test_migration_preserved_content_except_rebased_links(self):
        migration = load('knowledge_migration_test', 'regroup-documentation.py')
        data = json.loads((HERE / 'knowledge/document-locations.json').read_text('utf-8'))
        workspace = migration.WORKSPACE
        moved = {workspace / r['old']: workspace / r['current'] for r in data['documents'] if r['topic'] != 'history'}
        archived = {workspace / r['old']: workspace / r['current'] for r in data['documents'] if r['topic'] == 'history'}
        def git_text(commit, path):
            return subprocess.check_output(['git', 'show', commit + ':' + path.relative_to(workspace).as_posix()],
                cwd=workspace).decode('utf-8-sig').replace('\r\n', '\n')
        for old, new in moved.items():
            self.assertFalse(old.exists(), old)
            self.assertTrue(new.is_file(), new)
            original = git_text(data['source_commit'], old)
            expected = migration.rebase(original, old, new, moved, archived)
            self.assertEqual(git_text(MIGRATION_COMMIT, new), expected, new)
        self.assertEqual(len({row['topic'] for row in data['documents'] if row['topic'] != 'history'}), 9)
        for old, new in archived.items():
            original = git_text(data['source_commit'], old)
            expected = migration.rebase(original, old, new, moved, archived)
            observed = re.sub(r'\n> Исторический снимок[^\n]*\n> Старые[^\n]*\n> Актуальное[^\n]*\n', '', new.read_text('utf-8'), count=1)
            self.assertEqual(observed, expected, new)


if __name__ == '__main__':
    unittest.main()
