"""Source separation, corruption rejection and preserved export observations."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest


class KnowledgeIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/knowledge-index.py'
        spec = importlib.util.spec_from_file_location('knowledge_index_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        previous = self.tool.KNOWLEDGE
        self.tool.KNOWLEDGE = Path(directory.name)
        self.addCleanup(setattr, self.tool, 'KNOWLEDGE', previous)

    def source(self, root, number):
        raw = bytearray(0x400)
        raw[:2] = b'MZ'
        struct.pack_into('<I', raw, 60, 0x80)
        raw[0x80:0x84] = b'PE\0\0'
        struct.pack_into('<H', raw, 0x86, 2)
        struct.pack_into('<H', raw, 0x94, 0xf0)
        struct.pack_into('<H', raw, 0x98, 0x20b)
        struct.pack_into('<Q', raw, 0xb0, 0x140000000)
        section = 0x98 + 0xf0
        raw[section:section+8] = b'.text\0\0\0'
        struct.pack_into('<IIII', raw, section+8, 0x100, 0x1000, 0x100, 0x200)
        raw[section+40:section+48] = b'.rdata\0\0'
        struct.pack_into('<IIII', raw, section+48, 0x100, 0x2000, 0x100, 0x300)
        raw[0x200:0x206] = b'\xb8' + struct.pack('<I', number) + b'\xc3'
        raw[0x210:0x217] = bytes.fromhex('488d15e90f0000')
        raw[0x300:0x30a] = b'I_fixture\0'
        import hashlib
        sha = hashlib.sha256(raw).hexdigest()
        path = root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
        path.parent.mkdir(parents=True)
        path.write_bytes(raw)
        return sha, bytes(raw[0x200:0x206])

    def export(self, root, label, sha, code, *, completed=True, duplicate=False):
        folder = root / 'ghidra/release-comparisons/fixture/run-fixture/details' / label
        folder.mkdir(parents=True)
        pseudo = folder / 'fixture.c'
        pseudo.write_text('void searchable_fixture() {}', encoding='utf-8')
        row = dict(address='0x140001000', pseudocode_file='fixture.c', decompilation_completed=completed,
            message='' if completed else 'timeout', instructions=[dict(address='0x140001000', bytes=code.hex(), text='MOV EAX,1'),
                dict(address='0x140001010', bytes='488d15e90f0000', text='LEA RDX,[0x140002000]')])
        report = folder / 'details.json'
        report.write_text(json.dumps(dict(new_source_sha256=sha, functions=[row, row] if duplicate else [row],
            literals=[dict(address='0x140002000', bytes=b'I_fixture\0'.hex())])), encoding='utf-8')
        receipt = folder / 'provenance.json'
        receipt.write_text(json.dumps(dict(files={p.name:self.tool.digest(p) for p in (report,pseudo)})), encoding='utf-8')
        return report

    def test_rebuild_deduplicates_variants_but_preserves_versions_and_partial_exports(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sha1, code1 = self.source(root, 1)
            sha2, code2 = self.source(root, 2)
            self.export(root, 'one', sha1, code1, duplicate=True)
            self.export(root, 'two', sha2, code2)
            self.export(root, 'partial', sha2, code2, completed=False)
            output = root / 'knowledge/search.sqlite3'
            first = self.tool.build(root, output)
            second = self.tool.build(root, output)
            self.assertTrue(second['reused'])
            self.assertEqual(first['counts'], second['counts'])
            self.assertEqual(first['counts']['functions'], 2)
            self.assertEqual(first['counts']['variants'], 3)
            self.assertEqual(first['counts']['observations'], 4)
            db = self.tool.open_index(output)
            try:
                rows = self.tool.query(db, 'function', '140001000', sha2, 20)
                self.assertEqual([r['completed'] for r in rows], [1, 0])
                self.assertTrue(all(r['source_sha'] == sha2 for r in rows))
                literals = self.tool.query(db, 'search', 'I_fixture', sha1, 20)
                self.assertEqual(len(literals), 1)
                self.assertEqual(literals[0]['kind'], 'literal')
                self.assertTrue(Path(literals[0]['path']).is_file())
                self.assertEqual(literals[0]['references'][0]['function'], '0x140001000')
                with self.assertRaises(ValueError): self.tool.select_release(db, '0'*64)
            finally: db.close()

    def test_bad_receipt_or_forged_instructions_cannot_replace_working_index(self):
        for failure in ('output_hash', 'instruction_bytes', 'receipt_path'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                sha, code = self.source(root, 1)
                report = self.export(root, 'one', sha, code)
                output = root / 'knowledge/search.sqlite3'
                self.tool.build(root, output)
                before = output.read_bytes()
                receipt = report.parent / 'provenance.json'
                data = json.loads(receipt.read_text())
                if failure == 'output_hash':
                    (report.parent / 'fixture.c').write_text('changed', encoding='utf-8')
                elif failure == 'instruction_bytes':
                    content = json.loads(report.read_text())
                    content['functions'][0]['instructions'][0]['bytes'] = 'cc'*6
                    report.write_text(json.dumps(content), encoding='utf-8')
                    data['files']['details.json'] = self.tool.digest(report)
                else:
                    data['files']['../escape.c'] = '0'*64
                receipt.write_text(json.dumps(data), encoding='utf-8')
                with self.assertRaises(ValueError): self.tool.build(root, output)
                self.assertEqual(output.read_bytes(), before)

    def test_missing_completion_receipt_is_inventory_only(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sha, code = self.source(root, 1)
            report = self.export(root, 'unfinished', sha, code)
            (report.parent / 'provenance.json').unlink()
            output = root / 'knowledge/search.sqlite3'
            result = self.tool.build(root, output)
            self.assertEqual(result['counts']['functions'], 0)
            db = self.tool.open_index(output)
            try: self.assertEqual(db.execute('SELECT state FROM artifacts').fetchone()[0], 'unverified')
            finally: db.close()

    def test_missing_ghidra_function_is_not_promoted_to_exported_code(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sha, code = self.source(root, 1)
            report = self.export(root, 'missing-function', sha, code)
            content = json.loads(report.read_text())
            content['functions'] = [dict(address='0x140001000', function_missing=True)]
            report.write_text(json.dumps(content), encoding='utf-8')
            receipt = report.parent / 'provenance.json'
            value = json.loads(receipt.read_text())
            value['files']['details.json'] = self.tool.digest(report)
            receipt.write_text(json.dumps(value), encoding='utf-8')
            result = self.tool.build(root, root/'knowledge/search.sqlite3')
            self.assertEqual(result['counts']['unresolved'], 1)
            self.assertEqual(result['counts']['functions'], 0)
            report = self.export(root, 'body-budget', sha, code)
            content = json.loads(report.read_text())
            receipt = report.parent / 'provenance.json'
            value = json.loads(receipt.read_text())
            content['functions'] = [dict(address='0x140001000', skipped='body_budget')]
            report.write_text(json.dumps(content), encoding='utf-8')
            value['files']['details.json'] = self.tool.digest(report)
            receipt.write_text(json.dumps(value), encoding='utf-8')
            result = self.tool.build(root, root/'knowledge/search.sqlite3')
            self.assertEqual(result['counts']['unresolved'], 2)
            self.assertEqual(result['counts']['functions'], 0)

    def test_decompiler_timeout_preserves_instructions_without_inventing_pseudocode(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sha, code = self.source(root, 1)
            report = self.export(root, 'timeout', sha, code, completed=False)
            content = json.loads(report.read_text())
            del content['functions'][0]['pseudocode_file']
            report.write_text(json.dumps(content), encoding='utf-8')
            receipt = report.parent / 'provenance.json'
            value = json.loads(receipt.read_text())
            value['files']['details.json'] = self.tool.digest(report)
            receipt.write_text(json.dumps(value), encoding='utf-8')
            output = root/'knowledge/search.sqlite3'
            self.tool.build(root, output)
            db = self.tool.open_index(output)
            try:
                rows = self.tool.query(db, 'function', '140001000', sha, 20)
                self.assertEqual(rows[0]['completed'], 0)
                self.assertIsNone(rows[0]['pseudocode'])
                self.assertTrue(Path(rows[0]['artifact']).is_file())
            finally: db.close()


if __name__ == '__main__': unittest.main()
