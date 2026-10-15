import importlib.util
import unittest
import hashlib
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location('native_ui_links',
    Path(__file__).parent / 'resource-tools/vampir/build-native-ui-links.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
query_spec = importlib.util.spec_from_file_location('query_native_ui',
    Path(__file__).parent / 'resource-tools/vampir/query-native-ui.py')
query = importlib.util.module_from_spec(query_spec)
query_spec.loader.exec_module(query)


class NativeUIPaths(unittest.TestCase):
    path = '/Game/RED/UI/Lobby/WBP_PatchUI'

    def test_relative_full_and_class_paths_resolve_to_same_asset(self):
        for text in ['Lobby/WBP_PatchUI', self.path, self.path + '.WBP_PatchUI', self.path + '.WBP_PatchUI_C']:
            self.assertEqual(module.canonical_path(text), self.path)

    def test_bare_wrong_object_and_outside_paths_rejected(self):
        for text in ['WBP_PatchUI', '/Lobby/WBP_PatchUI', '/Game/Other/WBP_PatchUI',
                     'Lobby/WBP_PatchUI.WBP_Other', 'Lobby/../WBP_PatchUI', 'Lobby//WBP_PatchUI']:
            self.assertIsNone(module.canonical_path(text), text)

    def test_exact_terminated_literal_and_original_offset_preserved(self):
        text = 'Lobby/WBP_PatchUI'
        data = b'\0' * 10 + (text + '\0').encode('utf-16le')
        found = module.literals(data, {self.path})
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['file_offset'], 10)
        self.assertEqual(found[0]['text'], text)

    def test_unterminated_unknown_or_suffixed_name_not_linked(self):
        for text in ['Lobby/WBP_PatchUI', 'Lobby/WBP_PatchUI_Unrelated\0', 'Unknown/WBP_PatchUI\0']:
            self.assertEqual(module.literals(text.encode('utf-16le'), {self.path}), [])

    def test_object_suffix_does_not_duplicate_literal(self):
        data = (self.path + '.WBP_PatchUI_C\0').encode('utf-16le')
        self.assertEqual(len(module.literals(data, {self.path})), 1)

    def test_query_uses_exact_name_not_substring(self):
        report = dict(resources={self.path: [], self.path + 'Other': []},
                      references=[dict(literal=dict(canonical_path=self.path))], unresolved_candidates=[])
        result = query.select(report, 'WBP_PatchUI')
        self.assertEqual(len(result), 1)
        self.assertEqual(len(result[0]['references']), 1)
        self.assertFalse(result[0]['runtime_binding_verified'])
        with self.assertRaises(ValueError):
            query.select(report, 'Patch')

    def test_query_rejects_changed_executable_index_or_widget(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            exe, index, widget = [directory / name for name in ('source.exe', 'index.json', 'widget.json')]
            for path in (exe, index, widget):
                path.write_bytes(b'original')
            digest = hashlib.sha256(b'original').hexdigest()
            report = dict(source=str(exe), sha256=digest, catalog_sha256=digest)
            selected = [dict(resources=[dict(catalog_file=widget.name, catalog_sha256=digest)])]
            query.verify_sources(report, selected, directory)
            for path in (exe, index, widget):
                path.write_bytes(b'changed')
                with self.assertRaises(ValueError):
                    query.verify_sources(report, selected, directory)
                path.write_bytes(b'original')


if __name__ == '__main__':
    unittest.main()
