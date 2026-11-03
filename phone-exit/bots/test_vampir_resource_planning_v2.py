"""Frozen resource planning: legacy equivalence and real input corruption guards."""
from collections import Counter
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent / 'resource-tools' / 'vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), TOOLS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ResourcePlanningV2Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.args = SimpleNamespace(root=self.root)
        self.calls = Counter()
        def read_json(path):
            self.calls[('json',str(Path(path).resolve()))] += 1
            return json.loads(Path(path).read_text('utf-8-sig'))
        def hash_file(path):
            self.calls[('sha',str(Path(path).resolve()))] += 1
            return digest(path)
        self.core_sha = 'c' * 64
        self.index = SimpleNamespace(read_json=read_json, digest=hash_file,
            extension=lambda name: SimpleNamespace(EXE_SHA256=self.core_sha))
        self.legacy = load('update-run')
        self.tool = load('resource-planning-v2')
        self.table_index = self.root/'table-study/index.json'
        self.archive_a = self.root/'installed/a.pak'; self.archive_b = self.root/'installed/b.pak'
        self.write(self.archive_a,b'archive A'); self.write(self.archive_b,b'archive B')
        self.row_a = self.row(self.archive_a,'a'); self.row_b = self.row(self.archive_b,'b')
        self.entries_a = self.root/'pak-extracted/a/entries.json'
        self.entries_b = self.root/'pak-extracted/b/entries.json'
        self.blob_a = self.entries_a.parent/'blob.bin'; self.blob_b = self.entries_b.parent/'blob.bin'
        self.csv_a = self.table_index.parent/'a.csv'; self.csv_b = self.table_index.parent/'b.csv'
        self.cache_a = self.root/'knowledge/archive-cache/a.json'
        self.cache_b = self.root/'knowledge/archive-cache/b.json'
        self.write(self.blob_a,b'blob A'); self.write(self.blob_b,b'blob B')
        self.write(self.csv_a,b'id,value\n1,A\n'); self.write(self.csv_b,b'id,value\n1,B\n')
        self.write_json(self.entries_a,[dict(saved=str(self.blob_a))])
        self.write_json(self.entries_b,[dict(saved=str(self.blob_b))])
        self.write_json(self.cache_a,dict(archive='a')); self.write_json(self.cache_b,dict(archive='b'))
        self.row_a['cached_index'] = dict(path=str(self.cache_a),sha256=digest(self.cache_a))
        self.row_b['cached_index'] = dict(path=str(self.cache_b),sha256=digest(self.cache_b))
        self.tables = [self.table(self.archive_a,'a.csv','table-a'),self.table(self.archive_b,'b.csv','table-b')]
        self.write_json(self.table_index,dict(tables=self.tables))
        self.tools = dict(format=2,fixture='tool-v1')

    @staticmethod
    def write(path,raw):
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw)

    def write_json(self,path,value):
        self.write(path,json.dumps(value,sort_keys=True).encode())

    @staticmethod
    def row(path,kind):
        return dict(path=str(path),current=dict(sha256=digest(path),size=path.stat().st_size,pak_version=11),
            baseline=dict(sha256=kind*64,size=8,pak_version=11))

    @staticmethod
    def table(archive,filename,identity):
        return dict(file=filename,source=dict(path=str(archive)),id=identity,rows=1)

    def scope(self):
        return self.tool.Scope(self.index,self.args)

    def legacy_inputs(self,row=None,tools=None,**kwargs):
        return self.legacy.resource_stage_inputs(self.index,self.args,row or self.row_a,
            self.tools if tools is None else tools,**kwargs)

    def test_complete_stage_and_table_projection_match_legacy_exactly(self):
        scope=self.scope()
        for row in (self.row_a,self.row_b):
            with self.subTest(archive=row['path']):
                self.assertEqual(scope.table_baseline(row),self.legacy.table_baseline(self.index,self.args,row))
                self.assertEqual(scope.stage_inputs(row,self.tools),self.legacy_inputs(row))
        scope.validate()

    def test_table_registry_missing_empty_foreign_and_duplicate_order_match_legacy(self):
        cases=(None,[],[self.tables[1]],[self.tables[0],self.tables[0],self.tables[1]])
        for tables in cases:
            with self.subTest(tables=tables):
                if tables is None:self.table_index.unlink(missing_ok=True)
                else:self.write_json(self.table_index,dict(tables=tables))
                scope=self.scope()
                self.assertEqual(scope.table_baseline(self.row_a),
                    self.legacy.table_baseline(self.index,self.args,self.row_a))
                self.assertEqual(scope.stage_inputs(self.row_a,self.tools),self.legacy_inputs())
                scope.validate()

    @unittest.skipUnless(Path('Case.PAK') == Path('case.pak'), 'Path equality is case-sensitive on this OS')
    def test_windows_archive_case_aliases_match_legacy_for_absent_archive(self):
        # resolve() preserves the final component's spelling when it does not
        # exist. Legacy WindowsPath equality still matches both source rows;
        # grouping by their string spellings would incorrectly lose them.
        archive=self.archive_a.parent/'AbsentCase.PAK'
        self.assertFalse(archive.exists())
        tables=[self.table(Path(str(archive).lower()),'a.csv','lower-source'),
            self.table(Path(str(archive).upper()),'b.csv','upper-source')]
        self.write_json(self.table_index,dict(tables=tables))
        scope=self.scope()
        for name in ('AbsentCase.PAK','absentcase.pak','ABSENTCASE.PAK'):
            row=dict(self.row_a,path=str(archive.with_name(name)))
            with self.subTest(archive=name):
                expected=self.legacy.table_baseline(self.index,self.args,row)
                self.assertEqual(expected['state'],'selected')
                self.assertEqual([item['id'] for item in expected['tables']],
                    ['lower-source','upper-source'])
                self.assertEqual(scope.table_baseline(row),expected)
                self.assertEqual(scope.table_baseline(row),expected)
                self.assertEqual(scope.stage_inputs(row,self.tools),self.legacy_inputs(row))
        scope.validate()

    def test_material_mtime_is_ignored_and_incomplete_sha_keeps_audit_fallback(self):
        first=self.scope().stage_inputs(self.row_a,self.tools,audit_sha='audit-one')
        changed=copy.deepcopy(self.row_a);changed['current']['modified_ns']=1234
        self.assertEqual(first,self.scope().stage_inputs(changed,self.tools,audit_sha='audit-two'))
        for value in (None,dict(sha256='partial',size=8,pak_version=11)):
            with self.subTest(baseline=value):
                changed['baseline']=value
                actual=self.scope().stage_inputs(changed,self.tools,audit_sha='audit-three')
                self.assertEqual(actual,self.legacy_inputs(changed,audit_sha='audit-three'))
                self.assertEqual('incomplete_material_audit_sha256' in actual,value is not None)

    def test_named_config_archives_keep_source_and_historical_materials(self):
        config=self.root/'resource-config-snapshots/393c0697115ec6beceeb0e822bed0f6907eab83dfe9a47f81e9c7875deff35db/manifest.json'
        old_exe=self.root/'client-code-snapshots'/self.core_sha/'ProjectRED-Win64-Shipping.exe'
        self.write_json(config,dict(fixture=True));self.write(old_exe,b'old source fixture')
        for name in ('ProjectRED-Windows.pak','pakchunk0-Windows.pak'):
            with self.subTest(name=name):
                row=dict(self.row_a,path=str(self.root/name))
                actual=self.scope().stage_inputs(row,self.tools,source_sha='d'*64)
                self.assertEqual(actual,self.legacy_inputs(row,source_sha='d'*64))
                self.assertEqual(actual['config_source_sha256'],'d'*64)
                self.assertEqual(actual['historical'][str(config)],digest(config))
                self.assertEqual(actual['historical'][str(old_exe)],digest(old_exe))

    def test_repeated_consumers_parse_and_hash_frozen_inputs_once_before_barrier(self):
        scope=self.scope()
        with patch.object(self.tool.json,'loads',wraps=json.loads) as parser:
            first=scope.stage_inputs(self.row_a,self.tools)
            scope.table_baseline(self.row_a)
            second=scope.stage_inputs(self.row_a,self.tools)
            scope.stage_inputs(self.row_b,self.tools)
            third=scope.stage_inputs(self.row_a,self.tools)
        self.assertEqual(first,second);self.assertEqual(first,third)
        # Three consumed JSON inputs: table registry and each archive's entries.
        # Cached index JSON is opaque material, not another parser prerequisite.
        self.assertEqual(parser.call_count,3)
        self.assertIsInstance(scope.metrics,dict)
        self.assertEqual(scope.metrics['json_reads'],3)
        self.assertEqual(scope.metrics['digest_reads'],9)
        self.assertGreater(scope.metrics['stage_cache_hits'],0)
        self.assertGreater(scope.metrics['table_cache_hits'],0)
        scope.validate()
        self.assertGreaterEqual(scope.metrics['barrier_digest_reads'],9)

    def test_returned_dictionaries_cannot_poison_projection_or_tools_cache(self):
        scope=self.scope();first=scope.stage_inputs(self.row_a,self.tools)
        expected=copy.deepcopy(first)
        first['table_baseline']['tables'][0]['id']='poison'
        first['historical'].clear();first['tools']['fixture']='poison'
        first['cached_index']['path']='poison'
        baseline=scope.table_baseline(self.row_a);baseline['tables'].clear()
        self.assertEqual(scope.stage_inputs(self.row_a,self.tools),expected)
        self.assertEqual(self.tools['fixture'],'tool-v1')

    def test_changed_selected_material_identity_and_tools_have_distinct_stage_inputs(self):
        scope=self.scope();original=scope.stage_inputs(self.row_a,self.tools)
        variants=[]
        changed=copy.deepcopy(self.row_a);changed['baseline']['sha256']='d'*64;variants.append((changed,self.tools))
        changed=copy.deepcopy(self.row_a);changed['current']['sha256']='e'*64;variants.append((changed,self.tools))
        variants.append((self.row_a,dict(self.tools,fixture='tool-v2')))
        for row,tools in variants:
            with self.subTest(row=row,tools=tools):
                actual=scope.stage_inputs(row,tools)
                self.assertNotEqual(original,actual)
                self.assertEqual(actual,self.legacy_inputs(row,tools))
        self.assertEqual(scope.stage_inputs(self.row_a,self.tools),original)

    def test_new_invocation_unrelated_material_changes_preserve_selected_key(self):
        first=self.scope().stage_inputs(self.row_a,self.tools)
        before_b=self.scope().stage_inputs(self.row_b,self.tools)
        self.write(self.csv_b,b'id,value\n1,Z\n');self.write(self.blob_b,b'blob Z')
        self.tables[1]['rows']=99;self.write_json(self.table_index,dict(tables=self.tables))
        self.assertEqual(first,self.scope().stage_inputs(self.row_a,self.tools))
        self.assertNotEqual(before_b,self.scope().stage_inputs(self.row_b,self.tools))

    def test_new_invocation_selected_material_changes_only_affected_archive(self):
        before_a=self.scope().stage_inputs(self.row_a,self.tools)
        before_b=self.scope().stage_inputs(self.row_b,self.tools)
        for path in (self.csv_a,self.blob_a,self.cache_a):
            with self.subTest(material=path.name):
                original=path.read_bytes();self.write(path,original+b'new')
                self.assertNotEqual(before_a,self.scope().stage_inputs(self.row_a,self.tools))
                self.assertEqual(before_b,self.scope().stage_inputs(self.row_b,self.tools))
                self.write(path,original)
        self.tables[0]['rows']=5;self.write_json(self.table_index,dict(tables=self.tables))
        self.assertNotEqual(before_a,self.scope().stage_inputs(self.row_a,self.tools))
        self.assertEqual(before_b,self.scope().stage_inputs(self.row_b,self.tools))

    def test_selected_entries_change_tracks_new_blob_and_preserves_other_archive_key(self):
        before_a=self.scope().stage_inputs(self.row_a,self.tools)
        before_b=self.scope().stage_inputs(self.row_b,self.tools)
        another=self.entries_a.parent/'another.bin';self.write(another,b'new input')
        self.write_json(self.entries_a,[dict(saved=str(another))])
        scope=self.scope();after=scope.stage_inputs(self.row_a,self.tools)
        self.assertNotEqual(before_a,after)
        self.assertIn(str(another),after['historical'])
        self.assertNotIn(str(self.blob_a),after['historical'])
        self.assertEqual(before_b,scope.stage_inputs(self.row_b,self.tools))

    def test_selected_byte_changes_with_restored_size_mtime_fail_full_barrier(self):
        for path in (self.csv_a,self.blob_a,self.cache_a,self.entries_a,self.table_index):
            with self.subTest(material=path.name):
                scope=self.scope();scope.stage_inputs(self.row_a,self.tools)
                original=path.read_bytes();stamp=path.stat()
                changed=bytes([original[0]^1])+original[1:]
                self.write(path,changed);os.utime(path,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
                try:
                    with self.assertRaises(ValueError):scope.validate()
                finally:self.write(path,original)

    def test_mid_invocation_unrelated_registry_edit_aborts_but_unread_blob_is_excluded(self):
        scope=self.scope();scope.stage_inputs(self.row_a,self.tools)
        self.write(self.blob_b,b'changed unselected blob')
        scope.validate(self.row_a)
        self.tables[1]['rows']=99;self.write_json(self.table_index,dict(tables=self.tables))
        with self.assertRaises(ValueError):scope.validate()

    def test_adapter_self_write_requires_new_scope_instead_of_silent_adoption(self):
        scope=self.scope();frozen=scope.stage_inputs(self.row_a,self.tools)
        self.write(self.blob_a,b'adapter replaced its own historical input')
        self.assertEqual(scope.stage_inputs(self.row_a,self.tools),frozen)
        with self.assertRaises(ValueError):scope.validate(self.row_a)
        fresh=self.scope().stage_inputs(self.row_a,self.tools)
        self.assertNotEqual(fresh,frozen)
        self.assertEqual(fresh,self.legacy_inputs())

    def test_per_archive_barrier_excludes_other_archives_materials(self):
        scope=self.scope();scope.stage_inputs(self.row_a,self.tools);scope.stage_inputs(self.row_b,self.tools)
        self.write(self.blob_b,b'changed B')
        scope.validate(self.row_a)
        with self.assertRaises(ValueError):scope.validate(self.row_b)
        with self.assertRaises(ValueError):scope.validate()

    def test_missing_material_creation_and_existing_material_deletion_abort(self):
        missing=self.entries_a.parent/'not-yet-created.bin'
        self.write_json(self.entries_a,[dict(saved=str(missing))])
        scope=self.scope();before=scope.stage_inputs(self.row_a,self.tools)
        self.assertIsNone(before['historical'][str(missing)])
        self.write(missing,b'new')
        with self.assertRaises(ValueError):scope.validate()
        scope=self.scope();scope.stage_inputs(self.row_a,self.tools);missing.unlink()
        with self.assertRaises(ValueError):scope.validate()

    def test_missing_registry_creation_is_a_mid_invocation_change(self):
        self.table_index.unlink()
        scope=self.scope();self.assertEqual(scope.table_baseline(self.row_a)['state'],'missing')
        self.write_json(self.table_index,dict(tables=[]))
        with self.assertRaises(ValueError):scope.validate()

    def test_blob_and_csv_paths_cannot_escape_allowed_historical_directories(self):
        outside=self.root/'outside.bin';self.write(outside,b'outside')
        self.write_json(self.entries_a,[dict(saved=str(outside))])
        with self.assertRaises(ValueError):self.scope().stage_inputs(self.row_a,self.tools)
        self.write_json(self.entries_a,[dict(saved=str(self.blob_a))])
        for filename in ('../outside.bin',str(outside)):
            with self.subTest(filename=filename):
                self.tables[0]['file']=filename;self.write_json(self.table_index,dict(tables=self.tables))
                with self.assertRaises(ValueError):self.scope().table_baseline(self.row_a)

    def symlink(self,target,alias):
        try:alias.symlink_to(target)
        except (OSError,NotImplementedError) as error:
            self.skipTest('This Windows session cannot create file symlinks: '+str(error))

    def test_same_content_inside_alias_retarget_is_detected_before_publication(self):
        alternate=self.csv_a.with_name('alternate.csv');self.write(alternate,self.csv_a.read_bytes())
        alias=self.csv_a.with_name('alias.csv');self.symlink(self.csv_a,alias)
        self.tables[0]['file']='alias.csv';self.write_json(self.table_index,dict(tables=self.tables))
        scope=self.scope();scope.stage_inputs(self.row_a,self.tools)
        alias.unlink();self.symlink(alternate,alias)
        with self.assertRaises(ValueError):scope.validate()

    def test_same_content_alias_retarget_barrier_without_symlink_privileges(self):
        # Exercise canonical alias identity even on Windows without permission
        # to create symlinks; the real-filesystem symlink cases remain separate.
        alternate=self.csv_a.with_name('alternate.csv');self.write(alternate,self.csv_a.read_bytes())
        alias=self.csv_a.with_name('alias.csv');self.write(alias,self.csv_a.read_bytes())
        self.tables[0]['file']='alias.csv';self.write_json(self.table_index,dict(tables=self.tables))
        aliases={str(alias):self.csv_a};original_resolve=Path.resolve
        def resolve(path,*args,**kwargs):
            selected=aliases.get(str(path))
            return original_resolve(selected if selected is not None else path,*args,**kwargs)
        with patch.object(Path,'resolve',resolve):
            scope=self.scope();scope.stage_inputs(self.row_a,self.tools)
            aliases[str(alias)]=alternate
            with self.assertRaises(ValueError):scope.validate()

    def test_registry_source_alias_retarget_changes_selection_and_fails_barrier(self):
        alias=self.archive_a.with_name('archive-alias.pak');self.symlink(self.archive_a,alias)
        self.tables[0]['source']['path']=str(alias);self.write_json(self.table_index,dict(tables=self.tables))
        scope=self.scope();self.assertEqual(scope.table_baseline(self.row_a)['tables'][0]['id'],'table-a')
        alias.unlink();self.symlink(self.archive_b,alias)
        with self.assertRaises(ValueError):scope.validate()
        self.assertEqual(self.scope().table_baseline(self.row_a)['state'],'foreign_only')

    def test_archive_alias_retarget_cannot_reuse_previous_table_selection(self):
        alias=self.archive_a.with_name('alias.pak');self.write(alias,self.archive_a.read_bytes())
        row=dict(self.row_a,path=str(alias))
        aliases={str(alias):self.archive_a};original_resolve=Path.resolve
        def resolve(path,*args,**kwargs):
            selected=aliases.get(str(path))
            return original_resolve(selected if selected is not None else path,*args,**kwargs)
        with patch.object(Path,'resolve',resolve):
            scope=self.scope()
            self.assertEqual(scope.table_baseline(row)['tables'][0]['id'],'table-a')
            aliases[str(alias)]=self.archive_b
            with self.assertRaises(ValueError):scope.validate()
            self.assertEqual(self.scope().table_baseline(row)['tables'][0]['id'],'table-b')

    def test_symlink_csv_and_blob_escape_is_rejected(self):
        outside=self.root/'outside.bin';self.write(outside,b'outside')
        csv_alias=self.csv_a.with_name('outside.csv');self.symlink(outside,csv_alias)
        self.tables[0]['file']='outside.csv';self.write_json(self.table_index,dict(tables=self.tables))
        with self.assertRaises(ValueError):self.scope().table_baseline(self.row_a)
        self.tables[0]['file']='a.csv';self.write_json(self.table_index,dict(tables=self.tables))
        blob_alias=self.blob_a.with_name('outside.bin');self.symlink(outside,blob_alias)
        self.write_json(self.entries_a,[dict(saved=str(blob_alias))])
        with self.assertRaises(ValueError):self.scope().stage_inputs(self.row_a,self.tools)

    def test_oversized_json_registry_is_rejected_before_parse(self):
        self.write(self.table_index,b' '*(32*1024*1024+1))
        with self.assertRaises(ValueError):self.scope().table_baseline(self.row_a)


if __name__=='__main__':
    unittest.main()
