"""Named snapshots compare exact paths and publish only after the SHA owner."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from test_vampir_update_contracts import load
from test_vampir_resource_pipeline_v3 import ResourcePipelineV3


NAMED = load('resource-named-tables-v1')
OWNER = load('resource-owner-v4')
WORKFLOW = load('research-workflow')
PARSER = load('extract-release-tables')
CSV = load('resource-csv-v3')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class NamedTableScopeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.knowledge = self.root/'registry'
        self.knowledge.mkdir()
        (self.knowledge/'resource-owner-engine.json').write_text(
            '{"schema":4,"recipe":"resource-owner-sha-v4"}',encoding='utf-8')
        self.args = SimpleNamespace(root=self.root,knowledge=self.knowledge)
        self.archive = self.root/'installed/patch/data.pak'
        self.archive.parent.mkdir(parents=True)
        self.archive.write_bytes(b'public synthetic archive v1')
        self.directory_rules = dict(fixture='independently checked directory')
        self.directory_runtime = dict(fixture='bounded directory runtime')
        self.runtime = dict(python='fixture Python',files={},native='fixture native runtime')
        self.legacy = {}
        self.legacy_loader = Mock(side_effect=lambda index,args,owner,pointer,bridge:
            copy.deepcopy(self.legacy[pointer['sha256']]))
        self.modules = {'research-workflow':WORKFLOW,'extract-release-tables':PARSER,
            'resource-csv-v3':CSV,'resource-named-reference-v1':SimpleNamespace(load_reference=self.legacy_loader),
            'resource-directory-v1':SimpleNamespace(_runtime=lambda index:copy.deepcopy(self.runtime))}
        self.index = SimpleNamespace(HERE=NAMED.HERE,digest=digest,
            extension=lambda name:self.modules[name])
        self.rule = dict(schema=1,recipe=NAMED.RECIPE,legacy_references=[],legacy_bridge={})
        self.selector = self.knowledge/'resource-named-tables-engine.json'
        self.save_rule()
        self.current_tables = [self.table('CSV/Quest.csv','current')]
        self.unknown_entries = []
        self.current_pointer = None
        self.owner = None
        self.scope = None
        self.begin()

    def save_rule(self):
        self.selector.write_bytes(WORKFLOW.canonical(self.rule))

    def snapshot(self, category, value):
        path = WORKFLOW.snapshot(self.root,category,value)
        return dict(path=str(path),sha256=digest(path))

    def table(self, name, value, *, header=('id','name')):
        raw = ('\ufeff'+','.join(header)+'\r\n1,'+value+'\r\n').encode('utf-8')
        sha = hashlib.sha256(raw).hexdigest()
        path = self.root/'payloads'/(sha+'.csv')
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(raw)
        return dict(canonical_path='ProjectRED/Content/'+name,sha256=sha,file=str(path),
            bytes=len(raw),header=list(header),rows=1,state='verified_payload')

    def begin(self):
        if self.owner is not None and not self.owner.closed:
            self.owner.abort()
        self.owner = OWNER.begin(self.index,self.args)
        self.args.resource_directory_v1_scope = SimpleNamespace(owner=self.owner,
            rules=copy.deepcopy(self.directory_rules),runtime=copy.deepcopy(self.directory_runtime))
        self.scope = NAMED.Scope(self.index,self.args)
        self.addCleanup(lambda owner=self.owner:owner.abort() if not owner.closed else None)

    def legacy_reference(self, tables, *, rank=0, complete_names=True):
        body = dict(source=dict(archive_key=str(self.archive),sha256='a'*64),
            tables=copy.deepcopy(tables),complete_names=complete_names)
        pointer = self.snapshot('legacy-reference-fixtures',body)
        self.legacy[pointer['sha256']] = body
        self.rule['legacy_references'].append(dict(reference=pointer,rank=rank))
        self.save_rule()
        self.begin()
        return pointer

    def process(self):
        source = dict(path=str(self.archive),sha256=digest(self.archive),size=self.archive.stat().st_size)
        bindings = [dict(table,directory_identity_verified=True) for table in self.current_tables]
        entries = [dict(canonical_path=table['canonical_path'],uncompressed=table['bytes'],
            decoded_sha256=table['sha256']) for table in self.current_tables]
        entries.extend(copy.deepcopy(self.unknown_entries))
        named = dict(recipe='resource-directory-v1',authoritative_directory_for_archive=True,
            inputs=dict(source=source,rules=self.directory_rules,runtime=self.directory_runtime),
            csv_bindings=bindings,directory_entries=entries,unmatched_csv=[],path_gaps=[])
        self.current_pointer = self.snapshot('current-named-fixtures',named)
        return self.scope.process(dict(path=str(self.archive),current=source),dict(report=self.current_pointer))

    def result(self, outcome):
        return json.loads(Path(outcome['report']['path']).read_bytes())

    def capture(self, outcome):
        return json.loads(Path(outcome['capture']['path']).read_bytes())

    def cache_files(self):
        return list((self.root/'knowledge/resource-comparison-cache-v3').rglob('*.json'))

    def test_capture_and_comparison_publish_after_owner_and_warm_repeat_keeps_predecessor(self):
        previous = self.legacy_reference([self.table('CSV/Quest.csv','before')])
        first = self.process()
        self.assertEqual(first['state'],'compared')
        self.assertEqual(first['counts']['changed'],1)
        self.assertEqual(first['baseline']['reference'],previous)
        self.assertEqual(self.cache_files(),[])
        self.assertEqual(self.capture(first)['previous'],first['baseline'])
        self.owner.finish()
        self.assertEqual(len(self.cache_files()),2)
        self.begin()
        again = self.process()
        self.assertEqual(first,again)
        self.assertEqual(self.scope.metrics['captures'],0)
        self.assertEqual(self.scope.metrics['cache_hits'],1)
        self.owner.finish()

    def test_second_patch_compares_to_last_exact_named_capture(self):
        self.legacy_reference([self.table('CSV/Quest.csv','old legacy')])
        first = self.process();self.owner.finish()
        self.archive.write_bytes(b'public synthetic archive v2')
        self.current_tables = [self.table('CSV/Quest.csv','next patch')]
        self.begin();second = self.process()
        self.assertEqual(second['baseline']['kind'],'capture')
        self.assertEqual(second['baseline']['reference'],first['capture'])
        self.assertEqual(self.capture(second)['rank'],self.capture(first)['rank']+1)
        self.assertEqual(second['counts']['changed'],1)
        self.assertNotEqual(first['report'],second['report'])
        self.owner.finish()

    def test_revisited_older_source_compares_against_newest_capture_instead_of_stale_history(self):
        original_archive = self.archive.read_bytes()
        original_tables = copy.deepcopy(self.current_tables)
        first = self.process();self.owner.finish()
        self.archive.write_bytes(b'public synthetic archive v2')
        self.current_tables = [self.table('CSV/Quest.csv','second patch')]
        self.begin();second = self.process();self.owner.finish()
        self.archive.write_bytes(original_archive)
        self.current_tables = original_tables
        self.begin();revisited = self.process()
        self.assertNotEqual(first['capture'],revisited['capture'])
        self.assertEqual(revisited['baseline']['reference'],second['capture'])
        self.assertEqual(self.capture(revisited)['rank'],self.capture(second)['rank']+1)
        self.assertEqual(revisited['counts']['changed'],1)
        self.owner.finish()

    def test_same_bytes_under_another_name_are_added_and_removed_not_guessed(self):
        old = self.table('CSV/Previous.csv','shared bytes')
        self.legacy_reference([old])
        self.current_tables = [dict(old,canonical_path='ProjectRED/Content/Other/Current.csv')]
        result = self.result(self.process())
        self.assertEqual(result['counts'],dict(unchanged=0,changed=0,added=1,removed=1,unknown=0))
        self.assertEqual({row['canonical_path']:row['state'] for row in result['rows']},
            {'ProjectRED/Content/CSV/Previous.csv':'removed','ProjectRED/Content/Other/Current.csv':'added'})

    def test_unknown_hashes_and_incomplete_inventories_never_become_added_or_removed(self):
        old = [dict(self.current_tables[0],sha256=None,file=None,state='payload_hash_unknown'),
            self.table('CSV/Absent.csv','before')]
        before = dict(tables=old,complete_names=False)
        current = dict(tables=[self.current_tables[0],self.table('CSV/New.csv','after')],complete_names=False)
        rows = self.scope.compare(before,current)
        self.assertEqual({row['state'] for row in rows},{'unknown'})

    def test_unchanged_exact_hash_skips_row_diff_and_changed_header_stays_a_byte_change(self):
        unchanged = self.table('CSV/Same.csv','stable')
        before = dict(tables=[unchanged,self.table('CSV/Quest.csv','before')],complete_names=True)
        current = dict(tables=[unchanged,self.table('CSV/Quest.csv','after',header=('id','other'))],complete_names=True)
        rows = {row['canonical_path']:row for row in self.scope.compare(before,current)}
        self.assertEqual(rows[unchanged['canonical_path']]['state'],'unchanged')
        self.assertNotIn('row_diff',rows[unchanged['canonical_path']])
        changed = rows['ProjectRED/Content/CSV/Quest.csv']
        self.assertEqual(changed['state'],'changed')
        self.assertEqual(changed['row_diff']['status'],'unsupported_header')

    def test_captured_manifest_corruption_is_not_silently_rebuilt(self):
        first = self.process();self.owner.finish()
        Path(first['capture']['path']).write_bytes(b'{}')
        self.begin()
        with self.assertRaises(ValueError):
            self.process()

    def test_rehashed_capture_cannot_forge_table_metadata(self):
        first = self.process();self.owner.finish()
        changed = self.capture(first)
        changed['tables'][0]['rows'] += 1
        replacement = self.snapshot('resource-named-baselines-v1',changed)
        cache = next(path for path in self.cache_files() if path.parent.name.startswith('named-'))
        cache.write_bytes(WORKFLOW.canonical(replacement))
        self.begin()
        with self.assertRaisesRegex(ValueError,'Captured named table differs'):
            self.process()

    def test_same_source_duplicate_newest_rank_is_rejected(self):
        first = self.process();self.owner.finish()
        duplicate = dict(self.capture(first),unreviewed_note='different receipt with the same source and rank')
        pointer = self.snapshot('resource-named-baselines-v1',duplicate)
        folder = next(path.parent for path in self.cache_files() if path.parent.name.startswith('named-'))
        (folder/(pointer['sha256']+'.json')).write_bytes(WORKFLOW.canonical(pointer))
        self.begin()
        with self.assertRaisesRegex(ValueError,'ambiguous'):
            self.process()

    def test_changed_source_after_capture_prevents_all_pending_publication(self):
        self.process()
        self.archive.write_bytes(b'different synthetic archive')
        with self.assertRaisesRegex(ValueError,'input'):
            self.owner.finish()
        self.assertEqual(self.cache_files(),[])

    def test_new_baseline_pointer_midrun_prevents_publication(self):
        first = self.process()
        slot = str(self.archive)
        folder = self.root/'knowledge/resource-comparison-cache-v3'/('named-'+hashlib.sha256(slot.encode()).hexdigest())
        folder.mkdir(parents=True)
        injected = folder/'unexpected.json'
        injected.write_bytes(WORKFLOW.canonical(first['capture']))
        with self.assertRaisesRegex(ValueError,'inventory changed'):
            self.owner.finish()
        self.assertEqual(self.cache_files(),[injected])

    def test_runtime_change_after_comparison_prevents_publication(self):
        self.process()
        self.runtime['native'] = 'changed runtime in the same owner'
        with self.assertRaisesRegex(ValueError,'runtime changed'):
            self.owner.finish()
        self.assertEqual(self.cache_files(),[])

    def test_unknown_current_payload_is_preserved_without_inventing_a_hash(self):
        path = 'ProjectRED/Content/CSV/Missing.csv'
        self.unknown_entries = [dict(canonical_path=path,uncompressed=128,decoded_sha256=None)]
        first = self.process()
        table = next(table for table in self.capture(first)['tables'] if table['canonical_path']==path)
        self.assertEqual((table['sha256'],table['file'],table['state']),(None,None,'payload_hash_unknown'))
        self.assertEqual(next(row['state'] for row in self.result(first)['rows'] if row['canonical_path']==path),'unknown')
        self.owner.finish();self.begin()
        again = self.process()
        self.assertEqual(again,first)
        self.owner.finish()

    def test_hash_only_inventory_is_complete_and_proves_an_added_name_in_the_next_patch(self):
        raw = b'id,name\r\n1,without a BOM\r\n'
        path = 'ProjectRED/Content/CSV/RecordOnly.csv'
        self.unknown_entries = [dict(canonical_path=path,uncompressed=len(raw),
            decoded_sha256=hashlib.sha256(raw).hexdigest())]
        first = self.process()
        captured = self.capture(first)
        self.assertIs(captured['complete_names'],True)
        self.assertEqual(captured['name_inventory_rule'],'directory-csv-inventory-v1')
        record = next(table for table in captured['tables'] if table['canonical_path']==path)
        self.assertEqual((record['state'],record['file']),('record_hash_only',None))
        self.assertEqual(record['sha256'],hashlib.sha256(raw).hexdigest())
        self.owner.finish()
        self.archive.write_bytes(b'public synthetic archive with one added name')
        self.current_tables.append(self.table('CSV/New.csv','new table'))
        self.begin();second = self.process()
        self.assertEqual(second['baseline']['reference'],first['capture'])
        self.assertEqual(second['counts'],dict(unchanged=2,changed=0,added=1,removed=0,unknown=0))
        self.assertEqual({row['canonical_path']:row['state'] for row in self.result(second)['rows']},
            {self.current_tables[0]['canonical_path']:'unchanged',path:'unchanged',
                'ProjectRED/Content/CSV/New.csv':'added'})
        self.owner.finish()

    def test_non_csv_path_that_stops_parsing_uses_its_current_directory_hash(self):
        table = self.table('Misc/Guide.txt','previous CSV-like content')
        self.current_tables.append(table)
        first = self.process();self.owner.finish()
        self.assertNotIn('directory_records',self.capture(first))
        raw = b'new content without CSV rows or a BOM'
        self.archive.write_bytes(b'public synthetic archive with a nonparsed text payload')
        self.current_tables = [self.current_tables[0]]
        self.unknown_entries = [dict(canonical_path=table['canonical_path'],uncompressed=len(raw),
            decoded_sha256=hashlib.sha256(raw).hexdigest())]
        self.begin();second = self.process()
        rows = {row['canonical_path']:row for row in self.result(second)['rows']}
        changed = rows[table['canonical_path']]
        self.assertEqual(changed['state'],'changed')
        self.assertEqual(changed['before_sha256'],table['sha256'])
        self.assertEqual(changed['current_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertNotIn('row_diff',changed)
        self.assertEqual(second['counts'],dict(unchanged=1,changed=1,added=0,removed=0,unknown=0))
        self.assertNotIn(table['canonical_path'],{item['canonical_path'] for item in self.capture(second)['tables']})
        reloaded = self.scope.reference_body(dict(kind='capture',reference=second['capture'],
            rank=self.capture(second)['rank']))
        self.assertEqual(reloaded['directory_records'][table['canonical_path']],
            dict(canonical_path=table['canonical_path'],sha256=hashlib.sha256(raw).hexdigest(),
                bytes=len(raw),file=None))
        self.assertNotIn('directory_records',self.capture(second))
        self.owner.finish()

    def test_non_csv_path_that_starts_parsing_was_already_present_in_the_baseline(self):
        table = self.table('Misc/Guide.txt','new CSV-like content')
        raw = b'previous text which was not CSV'
        self.unknown_entries = [dict(canonical_path=table['canonical_path'],uncompressed=len(raw),
            decoded_sha256=hashlib.sha256(raw).hexdigest())]
        first = self.process();self.owner.finish()
        self.assertNotIn('directory_records',self.capture(first))
        self.assertNotIn(table['canonical_path'],{item['canonical_path'] for item in self.capture(first)['tables']})
        self.archive.write_bytes(b'public synthetic archive with a newly parsed text payload')
        self.unknown_entries = []
        self.current_tables.append(table)
        self.begin();second = self.process()
        changed = next(row for row in self.result(second)['rows'] if row['canonical_path']==table['canonical_path'])
        self.assertEqual(changed['state'],'changed')
        self.assertEqual(changed['before_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(changed['current_sha256'],table['sha256'])
        self.assertNotIn('row_diff',changed)
        self.assertEqual(second['counts'],dict(unchanged=1,changed=1,added=0,removed=0,unknown=0))
        legacy_without_directory = dict(tables=[],complete_names=True)
        uncertain = self.scope.compare(legacy_without_directory,dict(tables=[table],complete_names=True))
        self.assertEqual(uncertain[0]['state'],'unknown')
        self.owner.finish()

    def test_legacy_capture_bridge_only_accepts_the_registered_self_producer_change(self):
        self.unknown_entries = [dict(canonical_path='ProjectRED/Content/CSV/RecordOnly.csv',
            uncompressed=13,decoded_sha256='b'*64)]
        first = self.process();self.owner.finish()
        legacy = self.capture(first)
        legacy.pop('name_inventory_rule')
        legacy['complete_names'] = False
        own = str(NAMED.HERE/'resource-named-tables-v1.py')
        current_sha = legacy['producer'][own]
        old_sha = hashlib.sha256(b'synthetic previous capture producer').hexdigest()
        legacy['producer'][own] = old_sha
        pointer = self.snapshot('legacy-named-capture-fixtures',legacy)
        recorded = Path(pointer['path']).read_bytes()
        descriptor = dict(kind='capture',reference=pointer,rank=legacy['rank'])
        self.rule['capture_bridge'] = {old_sha:current_sha}
        self.save_rule();self.begin()
        verified = self.scope.reference_body(descriptor)
        self.assertIs(verified['recorded_complete_names'],False)
        self.assertIs(verified['complete_names'],True)
        self.assertIs(verified['captured_producer_revalidated'],True)
        self.assertEqual(Path(pointer['path']).read_bytes(),recorded)
        self.owner.finish()
        foreign = next(path for path in legacy['producer'] if path!=own)
        changed_other = copy.deepcopy(legacy)
        changed_other['producer'][foreign] = 'e'*64
        unregistered = copy.deepcopy(legacy)
        unregistered['producer'][own] = 'f'*64
        for body in (changed_other,unregistered):
            bad = self.snapshot('legacy-named-capture-fixtures',body)
            self.begin()
            with self.subTest(producer=body['producer']),self.assertRaisesRegex(ValueError,'producer'):
                self.scope.reference_body(dict(descriptor,reference=bad))
        self.rule['capture_bridge'] = {old_sha:'a'*64}
        self.save_rule();self.begin()
        with self.assertRaisesRegex(ValueError,'producer'):
            self.scope.reference_body(descriptor)

    def test_malformed_capture_metadata_is_rejected_as_an_invalid_capture(self):
        first = self.process();self.owner.finish()
        captured = self.capture(first)
        own = str(NAMED.HERE/'resource-named-tables-v1.py')
        producers = [[],{},None,dict(captured['producer'],**{own:[]}),
            dict(captured['producer'],**{own:None}),dict(captured['producer'],**{own:'not a SHA'})]
        for producer in producers:
            body = dict(captured,producer=producer)
            pointer = self.snapshot('malformed-named-capture-fixtures',body)
            self.begin()
            with self.subTest(producer=producer),self.assertRaisesRegex(ValueError,'producer'):
                self.scope.reference_body(dict(kind='capture',reference=pointer,rank=body['rank']))
        for field in ('schema','rank'):
            pointer = self.snapshot('malformed-named-capture-fixtures',dict(captured,**{field:True}))
            self.begin()
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'order'):
                self.scope.reference_body(dict(kind='capture',reference=pointer,rank=captured['rank']))

    def test_selector_absence_and_unreviewed_shapes_are_rejected_without_execution(self):
        self.selector.unlink()
        self.assertFalse(NAMED.enabled(self.index,self.args))
        for value in (dict(self.rule,schema=True),dict(self.rule,recipe='unknown'),
                dict(self.rule,legacy_references=[dict(reference={},rank=-1)])):
            self.selector.write_bytes(WORKFLOW.canonical(value))
            with self.subTest(rule=value),self.assertRaises(ValueError):
                NAMED.enabled(self.index,self.args)


class NamedTablePipelineTests(ResourcePipelineV3):
    def named_hook(self, state='compared', unknown=0):
        self.enable_owner()
        for name in ('resource-directory-engine.json','resource-named-tables-engine.json'):
            (self.args.knowledge/name).write_text('{}',encoding='utf-8')
        directory = self.snapshot('named-hook-directory',dict(fixture='independent directory'))
        report = self.snapshot('named-hook-comparison',dict(state=state,
            counts=dict(unchanged=1,changed=0,added=0,removed=0,unknown=unknown),rows=[]))
        capture = self.snapshot('named-hook-capture',dict(fixture='current named baseline'))
        self.directory_hook = SimpleNamespace(enabled=lambda *args:True,
            process=Mock(return_value=dict(report=directory,state='bound')),close=Mock(return_value={}))
        self.named = SimpleNamespace(enabled=lambda *args:True,process=Mock(return_value=dict(
            report=report,capture=capture,state=state,counts=dict(unknown=unknown))))
        original = self.index.extension
        modules = {'resource-directory-v1':self.directory_hook,'resource-named-tables-v1':self.named}
        self.index.extension = lambda name:modules[name] if name in modules else original(name)
        return directory,report,capture

    def test_named_comparison_replaces_legacy_schema_comparison_and_preserves_unknown_blocker(self):
        directory,report,_ = self.named_hook(unknown=9)
        pipeline = self.pipeline()
        pipeline._table_comparison = Mock(side_effect=AssertionError('Legacy schema comparison must not run'))
        result = pipeline.process(self.row)
        self.named.process.assert_called_once_with(self.index,self.args,self.row,
            dict(report=directory,state='bound'))
        self.assertEqual(result['table_comparison'],report)
        self.assertIn('named_table_reference_hashes_incomplete',result['reasons'])
        self.assertNotIn('matching_table_baseline_missing',result['reasons'])
        self.assertEqual(result['current_csv'],self.csv_ptr)
        self.assertFalse(result['resource_identity_proven'])
        pipeline.finish()

    def test_first_missing_named_baseline_retains_capture_and_current_csv(self):
        _,report,capture = self.named_hook(state='baseline_missing',unknown=1)
        pipeline = self.pipeline()
        original = pipeline._table_comparison
        pipeline._table_comparison = Mock(wraps=original)
        result = pipeline.process(self.row)
        pipeline._table_comparison.assert_called_once()
        self.assertEqual(result['named_tables']['capture'],capture)
        self.assertEqual(result['named_tables']['report'],report)
        self.assertEqual(result['current_csv'],self.csv_ptr)
        self.assertIn('matching_table_baseline_missing',result['reasons'])
        pipeline.finish()


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(loader.loadTestsFromTestCase(NamedTableScopeTests))
    names = sorted(name for name in NamedTablePipelineTests.__dict__ if name.startswith('test_'))
    suite.addTests(NamedTablePipelineTests(name) for name in names)
    return suite


if __name__=='__main__':
    unittest.main()
