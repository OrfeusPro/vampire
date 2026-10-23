"""Offline adapter boundaries: no authorization, game execution or Ghidra."""
import importlib.util
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

TOOL=Path(__file__).parent/'resource-tools/vampir/binary-diff.py'
spec=importlib.util.spec_from_file_location('binary_diff',TOOL)
adapter=importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class BinaryDiffTests(unittest.TestCase):
    def test_heap_budget_rejected_before_launch(self):
        with patch.object(adapter,'installation') as install:
            with self.assertRaisesRegex(ValueError,'heap'):
                adapter.export(Path('.'),Path('source'),Path('project'),'program',64)
            install.assert_not_called()

    def test_candidates_are_never_semantic_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            db=Path(temporary)/'test.BinDiff'
            with closing(sqlite3.connect(db)) as conn:
                conn.execute('CREATE TABLE function(address1 INTEGER,address2 INTEGER,similarity REAL,confidence REAL)')
                conn.executemany('INSERT INTO function VALUES(?,?,?,?)',[(4096,8192,1,1),(4096,12288,.9,.8)])
                conn.commit()
            matches=adapter.candidates(db,'0x1000')
            self.assertEqual(len(matches),2)  # Preserve ambiguity even at maximum confidence.
            self.assertTrue(all(x['state']=='candidate' and not x['semantic_verification'] for x in matches))
            self.assertEqual(adapter.candidates(db,'0x9999'),[])

    def test_changed_source_and_export_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'source';export=root/'export';receipt=root/'manifest.json'
            source.write_bytes(b'PE');export.write_bytes(b'protobuf')
            data=dict(source=str(source),source_sha256=adapter.digest(source),export=str(export),export_sha256=adapter.digest(export))
            adapter.save(receipt,data)
            self.assertEqual(adapter.checked_export(receipt),data)
            export.write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError,'export'):adapter.checked_export(receipt)
            export.write_bytes(b'protobuf');source.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'source'):adapter.checked_export(receipt)

    def test_pinned_tool_corruption_and_escape_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);p=root/'tool';p.write_bytes(b'original')
            expected={'tool':adapter.digest(p)}
            adapter.verify_files(root,expected);p.write_bytes(b'changed')
            with self.assertRaises(ValueError):adapter.verify_files(root,expected)
            with self.assertRaises(ValueError):adapter.verify_files(root,{'../outside':'0'*64})

    def test_project_changes_invalidate_export_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            project=Path(temporary)/'analysis.gpr';project.write_bytes(b'project')
            folder=project.with_suffix('.rep');folder.mkdir()
            part=folder/'db.1.gbf';part.write_bytes(b'old analysis')
            old=adapter.project_inputs(project)
            part.write_bytes(b'new analysis')
            self.assertNotEqual(old,adapter.project_inputs(project))
            self.assertEqual(adapter.project_inputs(project),adapter.project_inputs(project))

    def test_cached_export_does_not_launch_ghidra(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);tools=root/'tools';tools.mkdir()
            adapter.save(tools/'install.json',dict(pinned=True))
            source=root/'source.exe';source.write_bytes(b'source')
            project=root/'analysis.gpr';project.write_bytes(b'project')
            project.with_suffix('.rep').mkdir()
            (project.with_suffix('.rep')/'db.1.gbf').write_bytes(b'analysis')
            inputs=dict(source_sha256=adapter.digest(source),project=str(project.resolve()),
                program='source.exe',project_inputs=adapter.project_inputs(project.resolve()),
                install_sha256=adapter.digest(tools/'install.json'),
                script_sha256=adapter.digest(TOOL.parent/'ghidra/CheckedBinExport.java'))
            key=hashlib.sha256(json.dumps(inputs,sort_keys=True).encode()).hexdigest()
            folder=root/'binary-diff/exports'/inputs['source_sha256']/key
            folder.mkdir(parents=True)
            output=folder/'program.BinExport';output.write_bytes(b'export')
            adapter.save(folder/'manifest.json',dict(**inputs,source=str(source),export=str(output),
                export_sha256=adapter.digest(output)))
            with patch.object(adapter,'installation',return_value=(tools,{})), \
                 patch.object(adapter,'command') as launch:
                result=adapter.export(root,source,project,'source.exe')
                self.assertEqual(result['export_sha256'],adapter.digest(output))
                self.assertTrue(result['reused'])
                launch.assert_not_called()

    def test_changed_comparison_receipt_rejected_before_reading_matches(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);primary=root/'old.json';secondary=root/'new.json'
            primary.write_text('{}');secondary.write_text('{}')
            receipt=root/'comparison.json'
            adapter.save(receipt,dict(primary=str(primary),secondary=str(secondary),
                primary_sha256=adapter.digest(primary),secondary_sha256=adapter.digest(secondary)))
            primary.write_text('{"changed":true}')
            with self.assertRaisesRegex(ValueError,'receipts changed'):adapter.checked_comparison(receipt)

    def test_unknown_database_schema_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            db=Path(temporary)/'test.BinDiff'
            with closing(sqlite3.connect(db)) as conn:conn.execute('CREATE TABLE unrelated(x)')
            with self.assertRaisesRegex(ValueError,'schema'):adapter.candidates(db)

    def test_prepare_requires_unique_candidate_and_keeps_source_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            comparison=Path(temporary)/'manifest.json';comparison.write_text('{}')
            context=dict(database='unused',source_sha256='b'*64,baseline_sha256='a'*64)
            with patch.object(adapter,'checked_comparison',return_value=context), \
                 patch.object(adapter,'candidates',return_value=[dict(new_address='0x2000')]), \
                 patch.object(adapter.subprocess,'run') as run:
                run.return_value.stdout='{"request":"offline task"}'
                self.assertEqual(adapter.prepare_candidate(Path(temporary),comparison,'0x1000','question')['request'],'offline task')
                argv=run.call_args.args[0]
                self.assertIn('prepare',argv);self.assertIn('b'*64,argv);self.assertIn('0x2000',argv)
                self.assertNotIn('collect',argv)
            with patch.object(adapter,'checked_comparison',return_value=context), \
                 patch.object(adapter,'candidates',return_value=[{},{}]), \
                 patch.object(adapter.subprocess,'run') as run:
                with self.assertRaisesRegex(ValueError,'ambiguous'):
                    adapter.prepare_candidate(Path(temporary),comparison,'0x1000','question')
                run.assert_not_called()


if __name__=='__main__':unittest.main()
