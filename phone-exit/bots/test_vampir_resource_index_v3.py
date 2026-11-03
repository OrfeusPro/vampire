"""Fixture-only admission of cached bounded record reports, no real decoder."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).parent/'resource-tools/vampir'


def load(name):
    spec=importlib.util.spec_from_file_location('resource_index_test_'+name.replace('-','_'),HERE/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ResourceIndexV3Tests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)/'resources';self.root.mkdir()
        self.install=self.root.parent/'install';self.install.mkdir()
        self.archive=self.install/'example.pak';self.archive.write_bytes(b'x'*64)
        self.here=self.root/'tools/vampir';self.here.mkdir(parents=True)
        self.reader=self.here.parent/'rfnext/scan-pak.py';self.reader.parent.mkdir()
        self.reader.write_bytes(b'fixture reader')
        self.indexer=self.here/'index-release-archives.py';self.indexer.write_bytes(b'fixture indexer')
        self.rf=self.root/'rf';self.oodle=self.rf/'tools/oodle-data-shared.dll';self.oodle.parent.mkdir(parents=True)
        self.oodle.write_bytes(b'fixture Oodle data')
        env=patch.dict(os.environ,{'PHONEEXIT_RF_RESOURCES':str(self.rf)});env.start();self.addCleanup(env.stop)
        self.module=load('resource-index-v3');self.workflow=load('research-workflow')
        self.index=SimpleNamespace(HERE=self.here,digest=digest,
            extension=lambda name:SimpleNamespace(DECODE_LIMIT=2*1024*1024))
        self.args=SimpleNamespace(root=self.root)
        self.row=dict(path=str(self.archive),current=dict(path=str(self.archive),sha256=digest(self.archive),size=64,pak_version=11))
        self.audit_value=dict(schema=1,source=str(self.install),full_archive_coverage=True,
            exe=dict(path=str(self.install/'game.exe'),sha256='d'*64),files=[copy.deepcopy(self.row)])
        self.audit=self.save(self.root/'knowledge/update-audits',self.audit_value)
        self.dependencies=dict(tool_sha256=digest(self.indexer),reader_sha256=digest(self.reader),oodle_sha256=digest(self.oodle))
        self.entry=dict(entry=0,offset=0,end=32,bytes=4,uncompressed=4,encrypted=False,method=0,
            stored_record_sha256='e'*64,decode_status='decoded',decoded_sha256='f'*64)
        self.report_value=dict(schema=1,source=copy.deepcopy(self.row['current']),
            release_manifest_sha256=self.audit.parent.name,dependencies=self.dependencies,
            entries=[copy.deepcopy(self.entry)],index_offset=32,scan_end=32,reached_index=True,
            gaps=[],directory_index_parsed=False,decode_limit=2*1024*1024,decode_counts={'decoded':1},
            observed_path_comparison=dict(previous_observed=1))
        self.report,self.summary=self.write_report()
        self.tools=dict(recipe='fixture resource tools')

    def save(self,parent,value):
        raw=self.workflow.canonical(value);sha=hashlib.sha256(raw).hexdigest()
        path=parent/sha/'manifest.json';path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        return path

    def write_report(self,value=None,audit=None,summary_overrides=None):
        value=copy.deepcopy(self.report_value if value is None else value)
        audit=self.audit if audit is None else audit
        record=self.save(audit.parent/'record-indexes'/('a'*64),value)
        row=dict(archive=self.archive.name,report=str(record),sha256=digest(record),entries=len(value['entries']),
            reached_index=value['reached_index'],decode_counts=value['decode_counts'],gaps=len(value['gaps']))
        summary=dict(schema=1,release_manifest_sha256=audit.parent.name,
            selected_archive_sha256=self.row['current']['sha256'],dependencies=value['dependencies'],
            archives=[row],compatibility='not_established')
        if summary_overrides:summary.update(summary_overrides)
        return record,self.save(audit.parent/'index-summaries',summary)

    def find(self):return self.module.find(self.index,self.args,self.audit,self.row,self.tools)

    def finish(self):return self.module.finish(self.index,self.args)

    def test_selected_report_reused_and_invocation_inventory_parsed_once(self):
        first=self.find();self.assertEqual(first,dict(path=str(self.report.resolve()),sha256=digest(self.report)))
        self.assertEqual(self.find(),first)
        metrics=self.module.metrics(self.index,self.args)
        self.assertEqual(metrics['discovery_scans'],1)
        self.assertEqual(metrics['source_sha_reads'],1)
        self.assertEqual(metrics['selected_records'],1)
        result=self.finish()
        self.assertTrue(result['source_barrier_completed'])
        self.assertFalse(result['directory_identity_proven'])
        self.assertEqual(result['compatibility'],'not_established')
        self.assertEqual(result['inputs'][str(self.archive.resolve())],digest(self.archive))

    def test_complete_checked_audit_and_exact_caller_material_required(self):
        for change in ('missing_full','changed_sha','duplicate_row','outside_install','missing_source'):
            with self.subTest(change=change):
                self.setUp()
                if change=='missing_full':self.audit_value['full_archive_coverage']=False
                elif change=='changed_sha':self.row['current']['sha256']='0'*64
                elif change=='duplicate_row':self.audit_value['files'].append(copy.deepcopy(self.row))
                elif change=='outside_install':self.audit_value['source']=str(self.root/'other-install')
                else:self.audit_value.pop('source')
                if change!='changed_sha':self.audit=self.save(self.root/'knowledge/update-audits',self.audit_value)
                with self.assertRaises(ValueError):self.find()

    def test_same_size_restored_mtime_current_source_corruption_is_rejected(self):
        stat=self.archive.stat();self.archive.write_bytes(b'y'*64)
        os.utime(self.archive,ns=(stat.st_atime_ns,stat.st_mtime_ns))
        with self.assertRaisesRegex(ValueError,'SHA differs'):self.find()

    def test_selected_summary_or_record_corruption_is_a_blocker(self):
        for target in ('summary','report'):
            with self.subTest(target=target):
                self.setUp();path=getattr(self,target);raw=path.read_bytes();path.write_bytes(raw.replace(b'1',b'2',1))
                with self.assertRaises(ValueError):self.find()

    def test_selected_record_bound_to_its_source_audit_and_source_path(self):
        for change in ('release','path','sha','size'):
            with self.subTest(change=change):
                self.setUp();value=copy.deepcopy(self.report_value)
                if change=='release':value['release_manifest_sha256']='0'*64
                elif change=='path':value['source']['path']=str(self.install/'else.pak')
                elif change=='sha':value['source']['sha256']='0'*64
                else:value['source']['size']=63
                self.summary.unlink();self.report,self.summary=self.write_report(value)
                with self.assertRaises(ValueError):self.find()

    def test_changed_decoder_is_cache_miss_and_new_budget_cannot_reuse_old_record(self):
        self.reader.write_bytes(b'new fixture reader')
        self.assertIsNone(self.find());self.finish()
        self.setUp();self.index.extension=lambda name:SimpleNamespace(DECODE_LIMIT=1024)
        with self.assertRaisesRegex(ValueError,'budget'):self.find()

    def test_same_source_distinct_record_payloads_are_ambiguous(self):
        value=copy.deepcopy(self.report_value);value['entries'][0]['decoded_sha256']='0'*64
        self.write_report(value)
        with self.assertRaisesRegex(ValueError,'Ambiguous'):self.find()

    def test_other_installation_same_bytes_is_not_admitted_and_does_not_block_build(self):
        other_path=self.root.parent/'another-install/example.pak'
        other_path.parent.mkdir();other_path.write_bytes(self.archive.read_bytes())
        old=copy.deepcopy(self.audit_value);old['source']=str(other_path.parent)
        old['files'][0]['path']=str(other_path)
        old['files'][0]['current']['path']=str(other_path)
        other_audit=self.save(self.root/'knowledge/update-audits',old)
        value=copy.deepcopy(self.report_value);value['source']['path']=str(other_path)
        value['release_manifest_sha256']=other_audit.parent.name
        self.summary.unlink();self.write_report(value,audit=other_audit)
        self.assertIsNone(self.find())
        def execute(*args):self.write_report();return dict(state='passed')
        pointer=self.module.build(self.index,SimpleNamespace(execute_adapter=execute),self.workflow,self.args,self.audit,self.row)
        self.assertEqual(pointer,dict(path=str(self.report.resolve()),sha256=digest(self.report)))
        self.finish()

    def test_metadata_only_duplicate_reports_deduplicate_exact_current_extraction(self):
        second_audit=copy.deepcopy(self.audit_value);second_audit['note']='second immutable audit'
        other=self.save(self.root/'knowledge/update-audits',second_audit)
        value=copy.deepcopy(self.report_value);value['release_manifest_sha256']=other.parent.name
        value['observed_path_comparison']=dict(previous_observed=99)
        self.write_report(value,audit=other)
        selected=self.find();self.assertIsNotNone(selected);self.finish()

    def test_declared_output_bytes_are_pinned(self):
        for field,name in (('directory_paths_file_sha256','directory.json'),('encoded_entries_file_sha256','encoded-entries.bin')):
            with self.subTest(field=field):
                self.setUp();value=copy.deepcopy(self.report_value);payload=b'fixture output';value[field]=hashlib.sha256(payload).hexdigest()
                self.summary.unlink();self.report,self.summary=self.write_report(value)
                target=self.report.parent/name;target.write_bytes(payload)
                self.find();target.write_bytes(b'broken output!')
                with self.assertRaisesRegex(ValueError,'input SHA'):self.finish()

    def test_mid_invocation_report_source_tool_or_audit_change_blocks_finish(self):
        for target in ('report','archive','reader','audit','oodle'):
            with self.subTest(target=target):
                self.setUp();self.find();path=getattr(self,target);stat=path.stat();raw=path.read_bytes()
                path.write_bytes(bytes([raw[0]^1])+raw[1:]);os.utime(path,ns=(stat.st_atime_ns,stat.st_mtime_ns))
                with self.assertRaises(ValueError):self.finish()

    def test_new_summary_after_selection_requires_fresh_invocation(self):
        self.find();value=copy.deepcopy(self.report_value);value['observed_path_comparison']=dict(another='metadata')
        self.write_report(value)
        with self.assertRaisesRegex(ValueError,'inventory changed'):self.finish()

    def test_empty_candidate_discovery_is_miss_not_archive_absence_or_identity(self):
        self.summary.unlink();self.assertIsNone(self.find())
        result=self.finish();self.assertFalse(result['directory_identity_proven'])

    def test_build_executes_only_missing_selected_indexer_and_refreshes_new_hints(self):
        self.summary.unlink();calls=[]
        def execute(index,args,tool,argv):
            calls.append((tool,argv));self.write_report();return dict(state='passed')
        update=SimpleNamespace(execute_adapter=execute)
        self.assertIsNone(self.find())
        pointer=self.module.build(self.index,update,self.workflow,self.args,self.audit,self.row)
        self.assertEqual(pointer['sha256'],digest(self.report))
        self.assertEqual(calls,[('index-release-archives.py',[self.audit,'--archive-sha256',self.row['current']['sha256']])])
        self.module.build(self.index,update,self.workflow,self.args,self.audit,self.row)
        self.assertEqual(len(calls),1)
        self.finish()

    def test_build_failure_or_no_selected_output_is_concrete_blocker(self):
        self.summary.unlink()
        for state in ('failed','passed'):
            with self.subTest(state=state):
                update=SimpleNamespace(execute_adapter=lambda *args:dict(state=state))
                with self.assertRaises(ValueError):self.module.build(self.index,update,self.workflow,self.args,self.audit,self.row)

    def test_record_entries_and_decode_counts_validate_bounds_and_budget(self):
        for change in ('counts','bool_counts','entry_order','bool_ordinal','method','end','decoded_budget','encrypted','stored_hash','scan','directory_identity','gap'):
            with self.subTest(change=change):
                self.setUp();value=copy.deepcopy(self.report_value)
                if change=='counts':value['decode_counts']={'decoded':2}
                elif change=='bool_counts':value['decode_counts']={'decoded':True}
                elif change=='entry_order':value['entries'][0]['entry']=1
                elif change=='bool_ordinal':value['entries'][0]['entry']=False
                elif change=='method':value['entries'][0]['method']=2
                elif change=='end':value['entries'][0]['end']=65
                elif change=='decoded_budget':value['entries'][0]['uncompressed']=3*1024*1024
                elif change=='encrypted':value['entries'][0]['encrypted']=True
                elif change=='stored_hash':value['entries'][0]['stored_record_sha256']='bad'
                elif change=='scan':value['scan_end']=31
                elif change=='directory_identity':value['directory_index_parsed']=True
                else:value['gaps']=[dict(start=0,end=1)]
                self.summary.unlink();self.report,self.summary=self.write_report(value)
                with self.assertRaises(ValueError):self.find()

    def test_metadata_pointer_escape_is_never_read_as_source_data(self):
        external=self.root/'external/manifest.json';external.parent.mkdir();external.write_text('{}')
        value=json.loads(self.summary.read_text('utf-8-sig'));value['archives'][0]['report']=str(external)
        self.summary.unlink();self.summary=self.save(self.audit.parent/'index-summaries',value)
        with self.assertRaisesRegex(ValueError,'outside'):self.find()

    def test_returned_pointer_copy_cannot_poison_admitted_result(self):
        pointer=self.find();pointer['path']='untrusted'
        self.assertEqual(self.find()['path'],str(self.report.resolve()));self.finish()

    def test_resources_owning_audit_or_tools_cannot_change_inside_scope(self):
        self.find();self.tools['recipe']='changed'
        with self.assertRaisesRegex(ValueError,'tool declarations'):self.find()
        self.setUp();self.find();value=copy.deepcopy(self.audit_value);value['note']='new audit'
        self.audit=self.save(self.root/'knowledge/update-audits',value)
        with self.assertRaisesRegex(ValueError,'mixed'):self.find()

    def test_finished_or_failed_scope_is_not_reusable(self):
        self.find();self.finish()
        with self.assertRaisesRegex(ValueError,'closed'):self.find()
        self.setUp();self.find();self.archive.write_bytes(b'broken')
        with self.assertRaises(ValueError):self.finish()
        with self.assertRaisesRegex(ValueError,'closed'):self.find()


if __name__=='__main__':unittest.main()
