"""Изолированная оркестрация именования ресурсов и общего SHA/cache барьера."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_vampir_update_contracts import load
from test_vampir_resource_pipeline_v3 import ResourcePipelineV3


DIRECTORY = load('resource-directory-v1')
OWNER = load('resource-owner-v4')
FORMAT = load('resource-directory-format-v1')
WORKFLOW = load('research-workflow')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ResourceDirectoryV1Tests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.knowledge = self.root/'registry'
        self.knowledge.mkdir()
        self.args = SimpleNamespace(root=self.root,knowledge=self.knowledge)
        (self.knowledge/'resource-owner-engine.json').write_text(
            '{"schema":4,"recipe":"resource-owner-sha-v4"}',encoding='utf-8')
        self.key_proof = self.snapshot('directory-key-fixtures',dict(fixture='not an executable key proof'))
        self.selector = self.knowledge/'resource-directory-engine.json'
        self.rule = dict(schema=1,recipe=DIRECTORY.RECIPE,key_proof=self.key_proof)
        self.selector.write_bytes(WORKFLOW.canonical(self.rule))
        runtime = self.root/'fixture-runtime.bin'
        runtime.write_bytes(b'synthetic runtime bytes')
        self.runtime = dict(portable=dict(python='fixture',files={str(runtime):digest(runtime)}),
            native=dict(capstone='fixture'),cryptography=dict(version='fixture',record_sha256='a'*64,
                binary=dict(path=str(runtime),sha256=digest(runtime))))
        mocked = patch.object(DIRECTORY,'_runtime',side_effect=lambda index:copy.deepcopy(self.runtime))
        mocked.start();self.addCleanup(mocked.stop)
        self.prefixes = {}
        self.format = SimpleNamespace(entry_prefix=lambda encoded,at:copy.deepcopy(self.prefixes[at]),
            canonical_path=FORMAT.canonical_path)
        self.csv_api = SimpleNamespace(load_checked=Mock(side_effect=self.checked_csv))
        self.modules = {'research-workflow':WORKFLOW,'resource-directory-format-v1':self.format,
            'recover-pak-game-config':SimpleNamespace(),'resource-csv-v3':self.csv_api}
        self.index = SimpleNamespace(HERE=DIRECTORY.HERE,digest=digest,
            read_json=lambda p:json.loads(Path(p).read_bytes()),extension=lambda name:self.modules[name])
        self.archive = self.root/'current.pak'
        self.archive.write_bytes(b'bounded synthetic current archive'*16)
        self.source = dict(path=str(self.archive),sha256=digest(self.archive),size=self.archive.stat().st_size)
        self.row = dict(path=str(self.archive),current=dict(self.source,pak_version=11))
        csv_file = self.root/'fixture.csv'
        csv_file.write_bytes(b'\xef\xbb\xbfid,name\r\n1,value\r\n')
        table = dict(file=str(csv_file),sha256=digest(csv_file),entry=7,offset=0,
            bytes=csv_file.stat().st_size,header=['id','name'],rows=1,internal_path=None)
        self.tables = [table]
        self.records = [dict(entry=7,offset=0,bytes=16,uncompressed=table['bytes'],method=1,
            encrypted=False,decoded_sha256=table['sha256'])]
        self.prefixes[0] = dict(offset=0,bytes=16,uncompressed=table['bytes'],method=1,
            encrypted=False,blocks=2)
        self.entries = [dict(path='CSV/Fixture.csv',encoded_entry_offset=0)]
        self.metadata = dict(mount='../../../ProjectRED/Content/RED/Data/')
        self.proof = dict(fixture='authenticated directory fixture')
        self.owner = None
        self.scope = None
        self.begin()

    def snapshot(self, category, value):
        path = WORKFLOW.snapshot(self.root,category,value)
        return dict(path=str(path),sha256=digest(path))

    def begin(self):
        self.owner = OWNER.begin(self.index,self.args)
        self.scope = DIRECTORY.Scope(self.index,self.args)
        self.scope.directory = Mock(side_effect=lambda archive:(copy.deepcopy(self.metadata),b'encoded fixture',
            dict(entries=copy.deepcopy(self.entries)),copy.deepcopy(self.proof)))
        self.addCleanup(lambda owner=self.owner:owner.abort() if not owner.closed else None)

    def checked_csv(self, index, args, pointer):
        value = self.scope.read(pointer)
        for table in value['tables']:
            self.owner.expect(table['file'],table['sha256'])
        return value

    def inputs(self, *, record_source=None, csv_source=None):
        record = dict(source=record_source or self.source,index_offset=400,
            entries=copy.deepcopy(self.records))
        record_pointer = self.snapshot('directory-record-fixtures',record)
        csv = dict(source=csv_source or self.source,record_index=record_pointer,tables=copy.deepcopy(self.tables))
        return record_pointer,self.snapshot('directory-csv-fixtures',csv)

    def process(self, **kwargs):
        pointers = self.inputs(**kwargs)
        return self.scope.process(self.row,*pointers)

    def result(self, outcome):
        return self.scope.read(outcome['report'])

    def cache_files(self):
        return list((self.root/'knowledge/resource-comparison-cache-v3').glob('directory-*.json'))

    def test_exact_offset_binds_multiblock_csv_and_retains_same_hash_different_names(self):
        second = dict(self.tables[0],offset=64,entry=8)
        self.tables.append(second)
        self.records.append(dict(self.records[0],offset=64,entry=8))
        self.prefixes[12] = dict(self.prefixes[0],offset=64)
        self.entries.append(dict(path='CSV/Second.csv',encoded_entry_offset=12))
        value = self.result(self.process())
        self.assertEqual(value['state'],'bound')
        self.assertEqual([row['internal_path'] for row in value['csv_bindings']],['CSV/Fixture.csv','CSV/Second.csv'])
        self.assertEqual([row['offset'] for row in value['csv_bindings']],[0,64])
        self.assertEqual(len({row['sha256'] for row in value['csv_bindings']}),1)
        self.assertEqual(value['directory_entries'][0]['blocks'],2)
        self.assertTrue(all(row['directory_identity_verified'] for row in value['csv_bindings']))
        self.assertFalse(value['runtime_activated'])
        self.assertEqual(value['compatibility'],'not_established')

    def test_unnamed_csv_is_explicitly_unmatched_without_header_guess(self):
        self.entries = []
        value = self.result(self.process())
        self.assertEqual(value['state'],'partial')
        self.assertEqual(value['csv_bindings'],[])
        self.assertEqual(value['unmatched_csv'],[dict(entry=7,offset=0,sha256=self.tables[0]['sha256'],
            reason='csv_record_not_named_in_authenticated_directory')])

    def test_unsupported_other_logical_path_keeps_proved_csv_binding(self):
        self.prefixes[12] = dict(self.prefixes[0],offset=64)
        raw_path = '/ShaderArchive-Fixture.ushaderbytecode'
        self.entries.append(dict(path=raw_path,encoded_entry_offset=12))
        outcome = self.process();value = self.result(outcome)
        self.assertEqual(value['state'],'partial')
        self.assertEqual(outcome['bound_csv'],1)
        self.assertEqual(outcome['path_gaps'],1)
        self.assertEqual(value['csv_bindings'][0]['internal_path'],'CSV/Fixture.csv')
        self.assertEqual(value['unmatched_csv'],[])
        self.assertEqual(value['path_gaps'],[dict(path=raw_path,reason='unsupported_logical_path_form')])
        self.assertEqual(value['directory_entries'][1]['path'],raw_path)
        self.assertIsNone(value['directory_entries'][1]['canonical_path'])

    def test_csv_with_unsupported_logical_path_stays_unmatched(self):
        self.entries[0]['path'] = '/CSV/Fixture.csv'
        outcome = self.process();value = self.result(outcome)
        self.assertEqual(value['state'],'partial')
        self.assertEqual(outcome['bound_csv'],0)
        self.assertEqual(outcome['unmatched_csv'],1)
        self.assertEqual(value['csv_bindings'],[])
        self.assertEqual(value['unmatched_csv'],[dict(entry=7,offset=0,sha256=self.tables[0]['sha256'],
            reason='unsupported_logical_path_form')])
        self.assertIsNone(value['directory_entries'][0]['canonical_path'])

    def test_duplicate_record_offsets_are_rejected(self):
        self.records.append(dict(self.records[0],entry=8))
        with self.assertRaisesRegex(ValueError,'offsets are ambiguous'):
            self.process()

    def test_multiple_names_for_one_csv_offset_are_rejected(self):
        self.entries.append(dict(path='CSV/Alias.csv',encoded_entry_offset=0))
        with self.assertRaisesRegex(ValueError,'one CSV record'):
            self.process()

    def test_duplicate_canonical_names_at_different_offsets_are_rejected(self):
        self.prefixes[12] = dict(self.prefixes[0],offset=64)
        self.entries.append(dict(path='CSV/Fixture.csv',encoded_entry_offset=12))
        with self.assertRaisesRegex(ValueError,'[Dd]uplicate|ambiguous|unique'):
            self.process()

    def test_authenticated_prefix_mismatch_is_rejected(self):
        original = copy.deepcopy(self.prefixes[0])
        for key,value in (('bytes',17),('uncompressed',self.tables[0]['bytes']+1),('method',0),('encrypted',True)):
            self.prefixes[0] = dict(original,**{key:value})
            with self.subTest(field=key),self.assertRaisesRegex(ValueError,'prefix disagree'):
                self.process()

    def test_source_csv_record_and_archive_size_must_match(self):
        for label,record_source,csv_source,delta in (
                ('csv path',self.source,dict(self.source,path=str(self.root/'foreign.pak')),0),
                ('csv SHA',self.source,dict(self.source,sha256='b'*64),0),
                ('record SHA',dict(self.source,sha256='c'*64),self.source,0),
                ('archive size',self.source,self.source,1)):
            self.row['current'] = dict(self.source,size=self.source['size']+delta)
            with self.subTest(field=label),self.assertRaisesRegex(ValueError,'identity differs'):
                self.process(record_source=record_source,csv_source=csv_source)

    def test_named_csv_entry_and_decoded_hash_must_match(self):
        original = copy.deepcopy(self.records)
        for changed in ('entry','decoded_sha256'):
            self.records = copy.deepcopy(original)
            self.records[0][changed] = 8 if changed=='entry' else 'd'*64
            with self.subTest(field=changed),self.assertRaisesRegex(ValueError,'CSV|payload'):
                self.process()

    def test_cache_assignment_waits_for_owner_finish_and_names_are_only_metadata(self):
        first = self.process()
        self.assertEqual(self.cache_files(),[])
        second = self.process()
        self.assertEqual(first['report'],second['report'])
        self.assertEqual(self.scope.metrics['cache_hits'],1)
        self.assertEqual(self.scope.metrics['cache_writes'],1)
        self.assertFalse((self.root/'ProjectRED').exists())
        self.assertFalse((self.root/'CSV').exists())
        done = self.owner.finish()
        self.assertTrue(done['barrier_completed'])
        self.assertEqual(done['metrics']['assigned_caches'],1)
        self.assertEqual(len(self.cache_files()),1)

    def test_warm_new_owner_reuses_identical_authenticated_report(self):
        first = self.process();self.owner.finish()
        self.begin()
        second = self.process()
        self.assertEqual(first,second)
        self.assertEqual(self.scope.metrics['cache_hits'],1)
        self.assertEqual(self.scope.metrics['cache_writes'],0)
        self.scope.directory.assert_called_once()
        self.owner.finish()

    def test_cache_pointer_to_different_immutable_result_is_rejected(self):
        self.process();self.owner.finish()
        wrong = self.snapshot('directory-results-fixtures',dict(fixture='not the authenticated result'))
        self.cache_files()[0].write_bytes(WORKFLOW.canonical(wrong))
        self.begin()
        with self.assertRaisesRegex(ValueError,'Cached resource directory result differs'):
            self.process()

    def test_mutated_source_prevents_all_pending_cache_assignment(self):
        self.process()
        self.archive.write_bytes(b'x'*self.archive.stat().st_size)
        with self.assertRaisesRegex(ValueError,'input'):
            self.owner.finish()
        self.assertEqual(self.cache_files(),[])

    def test_runtime_change_after_processing_prevents_publication(self):
        self.process()
        self.runtime['native']['capstone'] = 'different fixture runtime'
        with self.assertRaisesRegex(ValueError,'runtime changed'):
            self.owner.finish()
        self.assertEqual(self.cache_files(),[])

    def test_exact_report_pointer_and_full_bytes_are_required(self):
        pointer = self.snapshot('directory-read-fixtures',dict(fixture='bytes protected'))
        self.assertEqual(self.scope.read(pointer),dict(fixture='bytes protected'))
        with self.assertRaisesRegex(ValueError,'exact manifest pointer'):
            self.scope.read(dict(pointer,extra=True))
        outside = dict(path=str(self.root.parent/'manifest.json'),sha256='e'*64)
        with self.assertRaisesRegex(ValueError,'outside immutable library'):
            self.scope.read(outside)
        Path(pointer['path']).write_bytes(b'{}')
        with self.assertRaises(ValueError):
            self.scope.read(pointer)

    def test_selector_is_optional_but_malformed_rules_are_rejected(self):
        for value in (dict(self.rule,schema=True),dict(self.rule,recipe='unknown'),
                dict(self.rule,key_proof=dict(path='relative.json',sha256='a'*64)),
                dict(self.rule,key_proof=dict(path=str(self.root/'proof'),sha256='short'))):
            self.selector.write_bytes(WORKFLOW.canonical(value))
            with self.subTest(rule=value),self.assertRaises(ValueError):
                DIRECTORY.enabled(self.index,self.args)
        self.selector.unlink()
        self.assertFalse(DIRECTORY.enabled(self.index,self.args))

    def test_close_drops_in_memory_key_and_returns_independent_metrics(self):
        self.scope.key = b'fixture private bytes'
        self.args.resource_directory_v1_scope = self.scope
        metrics = DIRECTORY.close(self.args)
        self.assertIsNone(self.scope.key)
        metrics['archives'] = 999
        self.assertEqual(self.scope.metrics['archives'],0)

    def encrypted_directory_fixture(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        key = bytes(range(32))
        def string(value):
            raw = value.encode('utf-8')+b'\0'
            return struct.pack('<i',len(raw))+raw
        def padded(raw):
            return raw+bytes((-len(raw))%16)
        def encrypt(raw):
            cipher = Cipher(algorithms.AES(key),modes.ECB()).encryptor()
            return cipher.update(raw)+cipher.finalize()
        encoded = struct.pack('<III',3<<30,0,self.tables[0]['bytes'])
        directory = padded(struct.pack('<I',1)+string('CSV/')+struct.pack('<I',1)+
            string('Fixture.csv')+struct.pack('<i',0))
        directory_offset = 80
        main = string(self.metadata['mount'])+struct.pack('<IQ',1,17)
        for offset,raw in ((64,bytes(16)),(directory_offset,directory)):
            main += struct.pack('<IQQ',1,offset,len(raw))+hashlib.sha1(raw).digest()
        main = padded(main+struct.pack('<I',len(encoded))+encoded+struct.pack('<I',0))
        main_offset = directory_offset+len(directory)
        footer = (bytes(16)+b'\x01'+struct.pack('<IiQQ',0x5a6f12e1,11,main_offset,len(main))+
            hashlib.sha1(main).digest())
        raw = bytes(80)+encrypt(directory)+encrypt(main)+footer
        self.archive.write_bytes(raw)
        self.scope.core = load('recover-pak-game-config')
        self.scope.candidate_key = Mock(return_value=key)
        # Restore the real method, bypassing only historical key extraction.
        self.scope.directory = DIRECTORY.Scope.directory.__get__(self.scope,DIRECTORY.Scope)
        return dict(raw=raw,directory=directory,encoded=encoded,main=main,
            directory_offset=directory_offset,main_offset=main_offset,footer_offset=len(raw)-len(footer))

    def test_real_aes_directory_round_trip_preserves_authenticated_hash_proof(self):
        fixture = self.encrypted_directory_fixture()
        metadata,encoded,directory,proof = self.scope.directory(self.archive)
        self.assertEqual(metadata['mount'],self.metadata['mount'])
        self.assertEqual(metadata['entry_count'],1)
        self.assertEqual(encoded,fixture['encoded'])
        self.assertEqual(directory['entries'],[dict(path='CSV/Fixture.csv',encoded_entry_offset=0)])
        self.assertEqual(proof['main']['sha1'],hashlib.sha1(fixture['main']).hexdigest())
        self.assertEqual(proof['directory']['sha1'],hashlib.sha1(fixture['directory']).hexdigest())
        self.assertEqual(proof['decrypted_directory_sha256'],hashlib.sha256(fixture['directory']).hexdigest())
        self.assertEqual(proof['encoded_entries_sha256'],hashlib.sha256(fixture['encoded']).hexdigest())
        self.assertEqual(FORMAT.entry_prefix(encoded,0)['uncompressed'],self.tables[0]['bytes'])
        self.scope.candidate_key.assert_called_once_with()

    def test_real_directory_rejects_corrupt_ciphertext_and_main_hash(self):
        fixture = self.encrypted_directory_fixture()
        for label,at in (('directory ciphertext',fixture['directory_offset']+3),
                ('main hash',len(fixture['raw'])-1)):
            raw = bytearray(fixture['raw']);raw[at] ^= 1
            self.archive.write_bytes(raw)
            with self.subTest(corruption=label),self.assertRaisesRegex(ValueError,'SHA1 mismatch'):
                self.scope.directory(self.archive)

    def test_real_directory_rejects_unsupported_version_and_encryption_footer(self):
        fixture = self.encrypted_directory_fixture()
        for label,at,value in (('version',fixture['footer_offset']+21,10),
                ('encryption flag',fixture['footer_offset']+16,0)):
            raw = bytearray(fixture['raw']);raw[at] = value
            self.archive.write_bytes(raw)
            with self.subTest(footer=label),self.assertRaisesRegex(ValueError,'Unsupported.*footer'):
                self.scope.directory(self.archive)


class ResourceDirectoryPipelineTests(ResourcePipelineV3):
    def directory_hook(self):
        self.enable_owner()
        (self.args.knowledge/'resource-directory-engine.json').write_text('{}',encoding='utf-8')
        pointer = self.snapshot('directory-hook-fixtures',dict(state='bound',fixture='hook'))
        self.hook = SimpleNamespace(enabled=Mock(return_value=True),
            process=Mock(return_value=dict(report=pointer,state='bound',bound_csv=1,unmatched_csv=0)),
            close=Mock(return_value=dict(archives=1)))
        original = self.index.extension
        self.index.extension = lambda name:self.hook if name=='resource-directory-v1' else original(name)
        return pointer

    def test_enabled_directory_hook_receives_exact_current_reports(self):
        pointer = self.directory_hook();p = self.pipeline();result = p.process(self.row)
        self.hook.process.assert_called_once_with(self.index,self.args,self.row,self.record_ptr,self.csv_ptr)
        self.assertEqual(result['directory']['report'],pointer)
        self.assertFalse(result['resource_identity_proven'])
        self.assertNotIn('resource_directory_incomplete',result['reasons'])
        finished = p.finish()
        self.assertEqual(finished['directory'],dict(archives=1))
        self.hook.close.assert_called_with(self.args)

    def test_directory_rejection_keeps_current_csv_and_records_specific_blocker(self):
        self.directory_hook()
        self.hook.process.side_effect = ValueError('fixture directory SHA mismatch')
        p = self.pipeline();result = p.process(self.row)
        self.assertEqual(result['directory']['state'],'requires_review')
        self.assertEqual(result['directory']['reason'],'fixture directory SHA mismatch')
        self.assertIn('resource_directory_incomplete',result['reasons'])
        self.assertEqual(result['current_csv'],self.csv_ptr)
        self.csv_api.extract.assert_called_once()
        p.finish();self.hook.close.assert_called_with(self.args)


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(loader.loadTestsFromTestCase(ResourceDirectoryV1Tests))
    # Reuse the existing factory without rerunning its unchanged pipeline cases.
    names = sorted(name for name in ResourceDirectoryPipelineTests.__dict__ if name.startswith('test_'))
    suite.addTests(ResourceDirectoryPipelineTests(name) for name in names)
    return suite


if __name__=='__main__':
    unittest.main()
