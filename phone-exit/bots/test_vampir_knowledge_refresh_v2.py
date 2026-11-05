"""Full-history refresh parity, one verification pass and guarded publication."""
import importlib.util
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class KnowledgeRefreshV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        here = Path(__file__).parent
        cls.fixtures = load_module('knowledge_refresh_fixture_helpers', here / 'test_vampir_knowledge_index.py')
        cls.tool = load_module('knowledge_refresh_legacy', here / 'resource-tools/vampir/knowledge-index.py')
        cls.refresh = load_module('knowledge_refresh_v2', here / 'resource-tools/vampir/knowledge-index-refresh-v2.py')
        cls.check_tool = load_module('knowledge_full_check_v2', here / 'resource-tools/vampir/knowledge-check-v2.py')

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.folder = Path(directory.name)
        self.root = self.folder / 'materials'
        self.knowledge = self.folder / 'curated'
        self.knowledge.mkdir()
        (self.knowledge / 'questions.json').write_text('{"questions": []}', encoding='utf-8')
        self.document = self.knowledge / 'fixture.md'
        self.document.write_text('fixture context alpha', encoding='utf-8')
        previous = self.tool.KNOWLEDGE
        self.tool.KNOWLEDGE = self.knowledge
        self.addCleanup(setattr, self.tool, 'KNOWLEDGE', previous)

    def source(self, root, number):
        return self.fixtures.KnowledgeIndexTests.source(self, root, number)

    def export(self, root, label, sha, code, **kwargs):
        return self.fixtures.KnowledgeIndexTests.export(self, root, label, sha, code, **kwargs)

    def seed(self, root=None, *, receipt=True):
        root = root or self.root
        sha, code = self.source(root, 1)
        old = self.export(root, 'old', sha, code)
        provenance = old.parent / 'provenance.json'
        saved_receipt = provenance.read_bytes()
        if not receipt:
            provenance.unlink()
        output = root / 'knowledge/search.sqlite3'
        self.tool.build(root, output, knowledge=self.knowledge)
        return root, sha, code, old, output, saved_receipt

    def build(self, root, output, **kwargs):
        return self.refresh.build(self.tool, root, output, knowledge=self.knowledge, **kwargs)

    def sql_snapshot(self, path):
        db = self.tool.open_index(path)
        try:
            tables = [row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'search_%' ORDER BY name")]
            return {name: sorted((tuple(row) for row in db.execute('SELECT * FROM "' + name + '"')), key=repr)
                    for name in tables}
        finally:
            db.close()

    def query_snapshot(self, path, sha):
        db = self.tool.open_index(path)
        try:
            return {operation: self.tool.query(db, operation, value, sha, 20)
                    for operation, value in (('function', '140001000'), ('search', 'I_fixture'),
                                             ('search', 'fixture context'), ('callers', '140001000'))}
        finally:
            db.close()

    def test_refresh_has_full_sql_and_query_parity_with_legacy_refresh(self):
        root, sha, code, old, output, _ = self.seed()
        full = root / 'knowledge/legacy.sqlite3'
        full.write_bytes(output.read_bytes())
        self.export(root, 'new', sha, code, completed=False)
        self.document.write_text('fixture context beta', encoding='utf-8')
        result = self.build(root, output)
        legacy = self.tool.build(root, full, knowledge=self.knowledge)
        self.assertEqual(result['counts'], legacy['counts'])
        self.assertEqual(self.sql_snapshot(output), self.sql_snapshot(full))
        self.assertEqual(self.query_snapshot(output, sha), self.query_snapshot(full, sha))
        db = self.tool.open_index(output)
        try:
            self.tool.verify_index(db)
        finally:
            db.close()

    def test_cold_build_has_full_sql_and_query_parity_with_legacy_build(self):
        sha, code = self.source(self.root, 1)
        self.export(self.root, 'fixture', sha, code)
        output = self.root / 'knowledge/search.sqlite3'
        full = self.root / 'knowledge/legacy.sqlite3'
        result = self.build(self.root, output)
        legacy = self.tool.build(self.root, full, knowledge=self.knowledge)
        self.assertEqual(result['counts'], legacy['counts'])
        self.assertEqual(self.sql_snapshot(output), self.sql_snapshot(full))
        self.assertEqual(self.query_snapshot(output, sha), self.query_snapshot(full, sha))

    def test_addition_imports_only_new_report_and_verifies_history_once(self):
        root, sha, code, old, output, _ = self.seed()
        new = self.export(root, 'new', sha, code)
        with patch.object(self.tool, 'import_report', wraps=self.tool.import_report) as importer, \
                patch.object(self.tool, 'verify_index', wraps=self.tool.verify_index) as verifier:
            result = self.build(root, output)
        self.assertEqual([call.args[2] for call in importer.call_args_list], [new])
        self.assertEqual(verifier.call_count, 1)
        self.assertEqual(result['imported_reports'], 1)
        self.assertTrue(result['code_reused'])

    def test_context_refresh_reimports_context_without_reimporting_old_exports(self):
        root, sha, code, old, output, _ = self.seed()
        new = self.export(root, 'new', sha, code)
        self.document.write_text('fixture context changed', encoding='utf-8')
        original_extension = self.tool.extension
        context = original_extension('knowledge-context')
        with patch.object(context, 'import_context', wraps=context.import_context) as context_importer, \
                patch.object(self.tool, 'extension', side_effect=lambda name:
                             context if name == 'knowledge-context' else original_extension(name)), \
                patch.object(self.tool, 'import_report', wraps=self.tool.import_report) as importer:
            self.build(root, output)
        self.assertEqual([call.args[2] for call in importer.call_args_list], [new])
        self.assertEqual(context_importer.call_count, 1)
        db = self.tool.open_index(output)
        try:
            self.assertTrue(self.tool.query(db, 'search', 'fixture context changed', None, 20))
        finally:
            db.close()

    def test_unchanged_repeat_runs_one_real_verification_and_preserves_database(self):
        root, sha, code, old, output, _ = self.seed()
        before = output.read_bytes()
        with patch.object(self.tool, 'verify_index', wraps=self.tool.verify_index) as verifier, \
                patch.object(self.tool, 'import_report', wraps=self.tool.import_report) as importer:
            result = self.build(root, output)
        self.assertTrue(result['reused'])
        self.assertEqual(verifier.call_count, 1)
        importer.assert_not_called()
        self.assertEqual(output.read_bytes(), before)
        (old.parent / 'fixture.c').write_text('corrupt existing pseudocode', encoding='utf-8')
        with self.assertRaises(ValueError):
            self.build(root, output)
        self.assertEqual(output.read_bytes(), before)

    def test_existing_corruption_cannot_be_hidden_by_added_export(self):
        for kind in ('pseudocode', 'source', 'artifact', 'receipt'):
            with self.subTest(kind=kind):
                root, sha, code, old, output, _ = self.seed(self.root / kind)
                before = output.read_bytes()
                self.export(root, 'new', sha, code)
                target = {'pseudocode': old.parent / 'fixture.c',
                          'source': root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe',
                          'artifact': old, 'receipt': old.parent / 'provenance.json'}[kind]
                raw = target.read_bytes()
                target.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
                with self.assertRaises(ValueError):
                    self.build(root, output)
                self.assertEqual(output.read_bytes(), before)

    def test_same_size_and_restored_mtime_corruption_is_rejected(self):
        root, sha, code, old, output, _ = self.seed()
        self.export(root, 'new', sha, code)
        target = old.parent / 'fixture.c'
        before_db = output.read_bytes()
        before_stat = target.stat()
        raw = target.read_bytes()
        target.write_bytes(raw.replace(b'void', b'VOID', 1))
        os.utime(target, ns=(before_stat.st_atime_ns, before_stat.st_mtime_ns))
        self.assertEqual(target.stat().st_size, before_stat.st_size)
        self.assertEqual(target.stat().st_mtime_ns, before_stat.st_mtime_ns)
        with self.assertRaises(ValueError):
            self.build(root, output)
        self.assertEqual(output.read_bytes(), before_db)

    def test_context_mutation_during_refresh_preserves_previous_database(self):
        root, sha, code, old, output, _ = self.seed()
        self.export(root, 'new', sha, code)
        before = output.read_bytes()

        def mutate_context(*_):
            self.document.write_text('fixture context late mutation', encoding='utf-8')

        with self.assertRaises(ValueError):
            self.build(root, output, on_progress=mutate_context)
        self.assertEqual(output.read_bytes(), before)

    def test_new_discovered_report_during_refresh_is_rejected(self):
        root, sha, code, old, output, _ = self.seed()
        self.export(root, 'new', sha, code)
        before = output.read_bytes()

        def add_report(*_):
            self.export(root, 'arrived-during-refresh', sha, code)

        with self.assertRaises(ValueError):
            self.build(root, output, on_progress=add_report)
        self.assertEqual(output.read_bytes(), before)

    def test_new_receipt_during_refresh_is_rejected_even_with_same_report_set(self):
        root, sha, code, old, output, saved_receipt = self.seed(receipt=False)
        self.export(root, 'new', sha, code)
        before = output.read_bytes()

        def finish_old_report(*_):
            (old.parent / 'provenance.json').write_bytes(saved_receipt)

        with self.assertRaises(ValueError):
            self.build(root, output, on_progress=finish_old_report)
        self.assertEqual(output.read_bytes(), before)

    def test_tools_change_during_refresh_preserves_previous_database(self):
        root, sha, code, old, output, _ = self.seed()
        self.export(root, 'new', sha, code)
        before = output.read_bytes()
        tools = self.tool.tool_inputs()
        changed = dict(tools, **{'knowledge-context.py': '0' * 64})
        calls = []

        def changing_tools():
            calls.append(True)
            return tools if len(calls) == 1 else changed

        with patch.object(self.tool, 'tool_inputs', side_effect=changing_tools):
            with self.assertRaises(ValueError):
                self.build(root, output)
        self.assertEqual(output.read_bytes(), before)

    def test_final_input_barrier_runs_after_history_verification(self):
        root, sha, code, old, output, _ = self.seed()
        self.export(root, 'new', sha, code)
        before = output.read_bytes()
        verify = self.tool.verify_index

        def verify_then_mutate(*args, **kwargs):
            verify(*args, **kwargs)
            self.document.write_text('context changed after full history verification', encoding='utf-8')

        with patch.object(self.tool, 'verify_index', side_effect=verify_then_mutate) as verifier:
            with self.assertRaises(ValueError):
                self.build(root, output)
        self.assertEqual(verifier.call_count, 1)
        self.assertEqual(output.read_bytes(), before)

    def test_new_receipt_before_refresh_uses_validated_full_rebuild(self):
        root, sha, code, old, output, saved_receipt = self.seed(receipt=False)
        (old.parent / 'provenance.json').write_bytes(saved_receipt)
        with patch.object(self.tool, 'build', wraps=self.tool.build) as legacy_build:
            result = self.build(root, output)
        self.assertEqual(legacy_build.call_count, 1)
        self.assertNotEqual(Path(legacy_build.call_args.args[1]), output)
        self.assertFalse(result.get('code_reused', False))
        self.assertEqual(result['counts']['functions'], 1)

    def test_failed_private_fallback_does_not_replace_previous_database(self):
        root, sha, code, old, output, saved_receipt = self.seed(receipt=False)
        before = output.read_bytes()
        (old.parent / 'provenance.json').write_bytes(saved_receipt)
        source = root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
        raw = source.read_bytes()
        source.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        with self.assertRaises(ValueError):
            self.build(root, output)
        self.assertEqual(output.read_bytes(), before)

    def test_concurrent_destination_replacement_is_preserved(self):
        root, sha, code, old, output, _ = self.seed()
        self.export(root, 'new', sha, code)
        replacement = root / 'knowledge/concurrent.sqlite3'
        self.tool.build(root, replacement, knowledge=self.knowledge)
        db = sqlite3.connect(replacement)
        try:
            with db:
                db.execute('INSERT INTO metadata VALUES(?,?)', ('concurrent_writer', 'preserve me'))
        finally:
            db.close()
        concurrent_bytes = replacement.read_bytes()

        def replace_destination():
            replacement.replace(output)

        with self.assertRaisesRegex(ValueError, 'destination changed'):
            self.build(root, output, before_publish=replace_destination)
        self.assertEqual(output.read_bytes(), concurrent_bytes)

    def test_existing_sqlite_sidecars_are_rejected_without_touching_database(self):
        for suffix in ('-wal', '-journal'):
            with self.subTest(suffix=suffix):
                root, sha, code, old, output, _ = self.seed(self.root / suffix[1:])
                before = output.read_bytes()
                sidecar = Path(str(output) + suffix)
                sidecar.write_bytes(b'concurrent sqlite writer')
                with self.assertRaisesRegex(ValueError, 'SQLite sidecar'):
                    self.build(root, output)
                self.assertEqual(output.read_bytes(), before)
                self.assertEqual(sidecar.read_bytes(), b'concurrent sqlite writer')

    def test_late_sqlite_sidecar_prevents_publication(self):
        root, sha, code, old, output, _ = self.seed()
        self.export(root, 'new', sha, code)
        before = output.read_bytes()
        sidecar = Path(str(output) + '-wal')

        def start_concurrent_writer():
            sidecar.write_bytes(b'writer started after validation')

        with self.assertRaisesRegex(ValueError, 'SQLite sidecar'):
            self.build(root, output, before_publish=start_concurrent_writer)
        self.assertEqual(output.read_bytes(), before)
        self.assertTrue(sidecar.is_file())

    def cli_fixture(self, output):
        workspace = self.folder / 'git-workspace'
        workspace.mkdir()
        subprocess.run(['git', 'init', '-q', str(workspace)], check=True, capture_output=True)
        staged = workspace / 'status.md'
        staged.write_text('# Проверенный текст\n', encoding='utf-8')
        subprocess.run(['git', 'add', '--', staged.name], cwd=workspace, check=True, capture_output=True)
        api = self.tool.api()
        api.HERE = workspace / 'phone-exit/bots/resource-tools/vampir'
        api.KNOWLEDGE = self.folder / 'unused-default-knowledge'
        args = SimpleNamespace(root=self.root, knowledge=self.knowledge, database=output, output=None)
        workflow = self.tool.extension('research-workflow')
        tools = {str(Path(self.check_tool.__file__).resolve()): 'a' * 64}
        return workspace, staged, api, args, workflow, tools

    def cli_check(self, api, args, workflow, tools):
        with patch.object(self.check_tool, 'load', side_effect=lambda name:
                          workflow if name == 'research-workflow' else self.refresh), \
                patch.object(self.check_tool, 'tool_snapshot', return_value=tools), \
                patch.object(workflow, 'consistency'):
            return self.check_tool.check(api, args, args.database, tools=tools)

    def test_cli_reuse_keeps_legacy_staged_markdown_check_without_global_patches(self):
        root, sha, code, old, output, _ = self.seed()
        workspace, staged, api, args, workflow, tools = self.cli_fixture(output)
        original_build, original_digest = self.tool.build, self.tool.digest
        with patch.object(workflow, 'check', wraps=workflow.check) as workflow_check:
            result = self.cli_check(api, args, workflow, tools)
        self.assertEqual(workflow_check.call_count, 1)
        self.assertTrue(result['index_build']['reused'])
        self.assertTrue(result['full_history_verified'])
        self.assertEqual(result['staged_markdown_checked'], 1)
        self.assertIs(self.tool.build, original_build)
        self.assertIs(self.tool.digest, original_digest)
        before = output.read_bytes()
        staged.write_text('\\# Ошибочно экранированный заголовок\n', encoding='utf-8')
        subprocess.run(['git', 'add', '--', staged.name], cwd=workspace, check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, 'Escaped Markdown heading'):
            self.cli_check(api, args, workflow, tools)
        self.assertEqual(output.read_bytes(), before)

    def test_cli_git_index_change_before_publication_preserves_database(self):
        root, sha, code, old, output, _ = self.seed()
        self.export(root, 'new', sha, code)
        workspace, staged, api, args, workflow, tools = self.cli_fixture(output)
        before = output.read_bytes()
        verify = api.verify_index

        def verify_then_stage(*arguments, **kwargs):
            verify(*arguments, **kwargs)
            staged.write_text('# Другой staged текст\n', encoding='utf-8')
            subprocess.run(['git', 'add', '--', staged.name], cwd=workspace, check=True, capture_output=True)

        with patch.object(api, 'verify_index', side_effect=verify_then_stage):
            with self.assertRaisesRegex(ValueError, 'Git index'):
                self.cli_check(api, args, workflow, tools)
        self.assertEqual(output.read_bytes(), before)

    def test_cli_report_cannot_overwrite_a_checked_input_or_database(self):
        root, sha, code, old, output, _ = self.seed()
        workspace, staged, api, args, workflow, tools = self.cli_fixture(output)
        before = output.read_bytes()
        document_before = self.document.read_bytes()
        for target in (output, self.document, self.knowledge / 'new-report.json'):
            with self.subTest(target=target):
                args.output = target
                with self.assertRaises(ValueError), patch.object(api, 'verify_index') as verifier:
                    self.cli_check(api, args, workflow, tools)
                verifier.assert_not_called()
        self.assertEqual(output.read_bytes(), before)
        self.assertEqual(self.document.read_bytes(), document_before)


if __name__ == '__main__':
    unittest.main()
