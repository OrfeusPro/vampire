import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from test_vampir_update_contracts import load


class UpdateDefinitionStatusTests(unittest.TestCase):
    def test_changed_registry_requires_resume_without_execution_or_journal_write(self):
        with tempfile.TemporaryDirectory() as folder:
            knowledge = Path(folder)
            paths = [knowledge / name for name in ('update-contracts.json', 'research-checks.json', 'targets.json')]
            for path in paths: path.write_text('{}', 'utf-8')
            digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
            saved = {str(path): digest(path) for path in paths}
            run = dict(plan=dict(definition_sha256=saved)); before = json.dumps(run)
            update = SimpleNamespace(target_plans=Mock(return_value=[paths[-1]]))
            index = SimpleNamespace(HERE=knowledge, digest=digest, extension=Mock(return_value=update))
            args = SimpleNamespace(knowledge=knowledge)
            tool = load('update-run')
            self.assertTrue(tool.definition_status(index, args, run)['current'])
            paths[1].write_text('{"changed":true}', 'utf-8')
            result = tool.definition_status(index, args, run)
            self.assertFalse(result['current'])
            self.assertEqual(result['changed'], [str(paths[1])])
            self.assertEqual(json.dumps(run), before)
            self.assertIsNone(tool.definition_status(index, args, {})['current'])
            paths[1].unlink()
            self.assertFalse(tool.definition_status(index, args, run)['current'])
            self.assertTrue(all(c.args == ('research-update',) for c in index.extension.call_args_list))


if __name__ == '__main__':
    unittest.main()
