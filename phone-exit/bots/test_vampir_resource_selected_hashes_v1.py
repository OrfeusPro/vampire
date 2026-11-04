"""Selected record hashes are bounded, source-bound and published by one owner."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_vampir_update_contracts import load


SELECTED=load('resource-selected-hashes-v1')
CSV=load('resource-csv-v3')
OWNER=load('resource-owner-v4')
WORKFLOW=load('research-workflow')
INDEXER=load('index-release-archives')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class CheckedSelectedHeaderTests(unittest.TestCase):
    def plain(self):
        entry=dict(entry=0,offset=10,end=71,bytes=8,uncompressed=8,method=0,encrypted=False)
        header=dict(pos=10,end=71,size=8,usize=8,method=0,encrypted=False,hs=53,blocks=[],blocksize=0)
        return entry,header

    def compressed(self):
        entry=dict(entry=0,offset=10,end=104,bytes=5,uncompressed=10,method=1,encrypted=False)
        header=dict(pos=10,end=104,size=5,usize=10,method=1,encrypted=False,hs=89,
            blocks=[(89,92),(92,94)],blocksize=6)
        return entry,header

    def checked(self,entry,header):
        reader=SimpleNamespace(header=Mock(return_value=copy.deepcopy(header)))
        value=SELECTED.checked_header(reader,io.BytesIO(bytes(256)),entry,256)
        reader.header.assert_called_once()
        return value

    def test_exact_plain_and_compressed_layouts_are_accepted(self):
        for entry,header in (self.plain(),self.compressed()):
            with self.subTest(method=entry['method']):self.assertEqual(self.checked(entry,header),header)

    def test_fresh_header_must_match_every_bound_record_field(self):
        entry,header=self.plain()
        for field,value in (('pos',11),('end',72),('size',9),('usize',9),('method',1),('encrypted',True)):
            with self.subTest(field=field),self.assertRaises(ValueError):
                self.checked(entry,dict(header,**{field:value}))
        with self.assertRaises(ValueError):self.checked(entry,None)

    def test_plain_mismatched_size_blocks_and_header_bounds_are_rejected(self):
        entry,header=self.plain()
        for changed in (dict(hs=52),dict(hs=62),dict(blocks=[(53,61)])):
            with self.subTest(changed=changed),self.assertRaises(ValueError):
                self.checked(entry,dict(header,**changed))
        wrong=dict(entry,uncompressed=9)
        with self.assertRaises(ValueError):self.checked(wrong,dict(header,usize=9))

    def test_compressed_count_size_gaps_overlap_and_types_are_rejected(self):
        entry,header=self.compressed()
        changes=(dict(blocksize=0),dict(blocksize=True),dict(blocksize=SELECTED.LIMIT+1),
            dict(blocksize=10),dict(blocks=[]),dict(blocks=[(89,94)]),dict(blocks=[(90,92),(92,94)]),
            dict(blocks=[(89,93),(92,94)]),dict(blocks=[(89,91),(92,94)]),
            dict(blocks=[(89,92),(92,95)]),dict(blocks=[(89,92),(92,93)]),
            dict(blocks=[(89,92),(True,94)]),dict(blocks=[(89,92),(92,94,95)]))
        for changed in changes:
            with self.subTest(changed=changed),self.assertRaises(ValueError):
                self.checked(entry,dict(header,**changed))

    def test_truncated_reader_header_is_reported_as_a_layout_error(self):
        entry,_=self.plain()
        for error in (struct.error('short header'),IndexError('short flags')):
            reader=SimpleNamespace(header=Mock(side_effect=error))
            with self.subTest(error_type=type(error).__name__),self.assertRaises(ValueError):
                SELECTED.checked_header(reader,io.BytesIO(b''),entry,256)

    def test_record_stream_rejects_short_or_out_of_bounds_reads_and_seeks(self):
        wrapped=SELECTED.ExactRecordStream(io.BytesIO(b'0123456789'),2,8)
        wrapped.seek(2);self.assertEqual(wrapped.read(6),b'234567')
        for operation in (lambda:wrapped.seek(1),lambda:wrapped.seek(9),lambda:wrapped.seek(0,2),
                lambda:wrapped.read(1),lambda:wrapped.read(-1),lambda:wrapped.read(True)):
            with self.assertRaises(ValueError):operation()
        truncated=SELECTED.ExactRecordStream(io.BytesIO(b'abc'),0,5)
        with self.assertRaises(ValueError):truncated.read(5)


class SelectedRecordHashTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.knowledge=self.root/'registry';self.knowledge.mkdir()
        (self.knowledge/'resource-owner-engine.json').write_bytes(WORKFLOW.canonical(dict(schema=4,recipe='resource-owner-sha-v4')))
        self.selector=self.knowledge/'resource-selected-hashes.json';self.selector.write_bytes(WORKFLOW.canonical(SELECTED.RULE))
        self.rf=self.root/'decoder';oodle=self.rf/'tools/oodle-data-shared.dll';oodle.parent.mkdir(parents=True)
        oodle.write_bytes(b'public synthetic non-executable decoder identity')
        self.addCleanup(patch.stopall)
        patch.dict(os.environ,{'PHONEEXIT_RF_RESOURCES':str(self.rf)}).start()
        self.data=b'public synthetic payload';stored=b'H'*53+self.data
        self.archive=self.root/'current.pak';self.archive.write_bytes(stored+b'index placeholder')
        self.entry=dict(entry=0,offset=0,end=len(stored),bytes=len(self.data),uncompressed=len(self.data),
            method=0,encrypted=False,stored_record_sha256=hashlib.sha256(stored).hexdigest(),decode_status='size_skipped')
        self.record=dict(schema=1,source=dict(path=str(self.archive),sha256=digest(self.archive),
            size=self.archive.stat().st_size,pak_version=11),index_offset=len(stored),reached_index=True,
            dependencies=dict(reader_sha256=digest(CSV.HERE.parent/'rfnext/scan-pak.py'),
                oodle_sha256=digest(oodle),tool_sha256=digest(CSV.HERE/'index-release-archives.py')),
            entries=[copy.deepcopy(self.entry)])
        self.modules={'research-workflow':WORKFLOW,'resource-csv-v3':CSV,'index-release-archives':INDEXER}
        self.index=SimpleNamespace(HERE=SELECTED.HERE,digest=digest,extension=lambda name:self.modules[name],
            read_json=lambda p:json.loads(Path(p).read_bytes()))
        self.args=SimpleNamespace(root=self.root,knowledge=self.knowledge)
        self.reader=SimpleNamespace(header=Mock(side_effect=self.header),decode=Mock(side_effect=lambda stream,header:self.data))
        self.loader=patch.object(CSV,'_load_reader',return_value=self.reader).start()
        self.owner=None;self.save_record();self.begin()

    def snapshot(self,category,value):
        path=WORKFLOW.snapshot(self.root,category,value)
        return dict(path=str(path),sha256=digest(path))

    def save_record(self):
        self.pointer=self.snapshot('knowledge/selected-hash-record-fixtures',self.record)
        self.directory=dict(inputs=dict(record_index=self.pointer))
        self.row=dict(path=str(self.archive),current=copy.deepcopy(self.record['source']))
        self.named_entry=dict(self.record['entries'][0],canonical_path='ProjectRED/Content/QuestAsset.uexp')

    def begin(self):
        if self.owner is not None and not self.owner.closed:self.owner.abort()
        self.owner=OWNER.begin(self.index,self.args)
        self.addCleanup(lambda owner=self.owner:owner.abort() if not owner.closed else None)
        self.scope=SELECTED.Scope(self.index,self.args)

    def header(self,stream,offset,limit):
        entry=next(e for e in self.record['entries'] if e['offset']==offset)
        return dict(pos=entry['offset'],end=entry['end'],size=entry['bytes'],usize=entry['uncompressed'],
            method=entry['method'],encrypted=entry['encrypted'],hs=53,blocks=[],blocksize=0)

    def resolve(self,entry=None):
        return self.scope.resolve(self.row,self.directory,self.named_entry if entry is None else entry)

    def cache_files(self):
        return list((self.root/'knowledge/resource-comparison-cache-v3').glob('selected-hash-*.json'))

    def test_exact_source_hash_only_receipt_and_deferred_cache_publication(self):
        result=self.resolve();body=json.loads(Path(result['proof']['path']).read_bytes())
        self.assertEqual(result['sha256'],hashlib.sha256(self.data).hexdigest())
        self.assertEqual(body['inputs']['source'],dict(path=str(self.archive),sha256=digest(self.archive),size=self.archive.stat().st_size))
        self.assertEqual(body['inputs']['record_index'],self.pointer)
        self.assertEqual(body['inputs']['record']['stored_record_sha256'],self.entry['stored_record_sha256'])
        self.assertIs(body['payload_saved'],False);self.assertIs(body['runtime_activated'],False)
        self.assertEqual(self.cache_files(),[])
        self.assertEqual(len(self.owner.pending),1)
        self.owner.finish();self.assertEqual(len(self.cache_files()),1)
        self.assertEqual(list(self.root.rglob('*.uexp')),[])

    def test_multiple_consumers_deduplicate_by_source_and_offset(self):
        first=self.resolve();other=dict(self.named_entry,canonical_path='ProjectRED/Content/MapAssetAlias.uexp')
        self.assertEqual(self.resolve(other),first)
        self.assertEqual(self.reader.decode.call_count,1)
        self.assertEqual(self.scope.metrics['unique_records'],1)
        self.assertEqual(self.scope.metrics['memo_hits'],1)
        self.owner.finish()

    def test_memo_cannot_hide_changed_directory_record_metadata(self):
        self.resolve()
        for field,value in (('bytes',self.entry['bytes']+1),('uncompressed',self.entry['uncompressed']+1),
                ('method',1),('encrypted',True)):
            with self.subTest(field=field),self.assertRaises(ValueError):
                self.resolve(dict(self.named_entry,**{field:value}))
        self.assertEqual(self.reader.decode.call_count,1)

    def test_source_memo_rejects_changed_current_sha_and_record_pointer(self):
        self.resolve()
        bad=dict(self.row,current=dict(self.row['current'],sha256='b'*64))
        with self.assertRaises(ValueError):self.scope.resolve(bad,self.directory,self.named_entry)
        changed=copy.deepcopy(self.record);changed['fixture_note']='new record proof'
        pointer=self.snapshot('knowledge/selected-hash-record-fixtures',changed)
        with self.assertRaises(ValueError):self.scope.resolve(self.row,dict(inputs=dict(record_index=pointer)),self.named_entry)
        self.assertEqual(self.reader.decode.call_count,1)

    def test_warm_owner_rechecks_inputs_without_loading_or_decoding(self):
        first=self.resolve();self.owner.finish();self.reader.decode.reset_mock();self.loader.reset_mock()
        self.begin();again=self.resolve();self.owner.finish()
        self.assertEqual(first,again);self.reader.decode.assert_not_called();self.loader.assert_not_called()
        self.assertEqual(self.scope.metrics['cache_hits'],1);self.assertEqual(self.scope.metrics['decodes'],0)

    def test_fresh_header_mismatch_is_rejected_before_decode_or_publication(self):
        self.reader.header.side_effect=lambda *unused:dict(pos=0,end=self.entry['end'],size=self.entry['bytes']+1,
            usize=self.entry['uncompressed'],method=0,encrypted=False,hs=53,blocks=[],blocksize=0)
        with self.assertRaises(ValueError):self.resolve()
        self.reader.decode.assert_not_called();self.assertEqual(self.owner.pending,{})

    def test_stored_record_sha_mismatch_is_rejected_before_decode(self):
        self.record['entries'][0]['stored_record_sha256']='a'*64;self.save_record();self.begin()
        with self.assertRaises(ValueError):self.resolve()
        self.reader.decode.assert_not_called();self.assertEqual(self.owner.pending,{})

    def test_wrong_source_sha_and_mutated_record_pointer_are_rejected(self):
        self.row['current']['sha256']='b'*64
        with self.assertRaises(ValueError):self.resolve()
        self.row['current']=copy.deepcopy(self.record['source']);self.begin()
        p=Path(self.pointer['path']);p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaises(ValueError):self.resolve()
        self.reader.decode.assert_not_called()

    def test_directory_record_field_mismatch_and_known_hash_are_rejected(self):
        for entry in (dict(self.named_entry,bytes=self.entry['bytes']+1),dict(self.named_entry,decoded_sha256='a'*64)):
            with self.subTest(entry=entry),self.assertRaises(ValueError):self.resolve(entry)
        self.reader.decode.assert_not_called()

    def test_missing_index_encryption_and_size_budget_remain_explicit_blockers(self):
        missing=dict(self.named_entry,offset=1)
        result=self.resolve(missing);self.assertEqual(result,dict(state='blocked',reason='selected_record_missing_from_index'))
        self.record['entries'][0]['encrypted']=True;self.save_record();self.begin()
        self.assertEqual(self.resolve(),dict(state='blocked',reason='selected_record_encrypted'))
        self.record['entries'][0].update(encrypted=False,uncompressed=SELECTED.LIMIT+1)
        self.save_record();self.begin()
        self.assertEqual(self.resolve(),dict(state='blocked',reason='selected_record_size_budget'))
        self.reader.decode.assert_not_called()

    def test_decoded_length_and_type_must_match_exact_record(self):
        for data in (self.data[:-1],None,bytearray(self.data)):
            self.begin();self.reader.decode.side_effect=None;self.reader.decode.return_value=data
            with self.subTest(data_type=type(data).__name__),self.assertRaises(ValueError):self.resolve()
            self.assertEqual(self.owner.pending,{})

    def test_source_change_after_hash_prevents_cache_assignment(self):
        self.resolve();self.archive.write_bytes(self.archive.read_bytes()+b'changed')
        with self.assertRaises(ValueError):self.owner.finish()
        self.assertEqual(self.cache_files(),[])

    def test_runtime_or_selector_changes_prevent_cache_assignment(self):
        self.resolve();self.selector.write_bytes(self.selector.read_bytes()+b' ')
        with self.assertRaises(ValueError):self.owner.finish()
        self.assertEqual(self.cache_files(),[])

    def test_changed_runtime_metadata_prevents_cache_assignment(self):
        self.resolve()
        original=CSV._runtime
        def changed(index,args):
            value=original(index,args);value['implementation']='different runtime';return value
        with patch.object(CSV,'_runtime',side_effect=changed),self.assertRaises(ValueError):self.owner.finish()
        self.assertEqual(self.cache_files(),[])

    def test_total_and_record_count_budgets_do_not_decode_or_publish(self):
        self.scope.rule=dict(self.scope.rule,total_decoded_bytes=len(self.data)-1)
        self.assertEqual(self.resolve(),dict(state='blocked',reason='selected_record_total_budget'))
        self.reader.decode.assert_not_called();self.assertEqual(self.owner.pending,{})
        self.begin();self.scope.rule=dict(self.scope.rule,max_records=0)
        self.assertEqual(self.resolve(),dict(state='blocked',reason='selected_record_count_budget'))
        self.reader.decode.assert_not_called();self.assertEqual(self.owner.pending,{})

    def test_corrupted_warm_hash_report_is_rejected_without_decoding(self):
        result=self.resolve();self.owner.finish();p=Path(result['proof']['path']);p.write_bytes(p.read_bytes()+b' ')
        self.reader.decode.reset_mock();self.begin()
        with self.assertRaises(ValueError):self.resolve()
        self.reader.decode.assert_not_called()

    def test_fixed_rule_shape_and_budgets_are_not_silently_overridden(self):
        for rule in (dict(SELECTED.RULE,schema=True),dict(SELECTED.RULE,record_bytes=1),dict(SELECTED.RULE,extra=True)):
            self.selector.write_bytes(WORKFLOW.canonical(rule))
            with self.subTest(rule=rule),self.assertRaises(ValueError):SELECTED.configuration(self.args)


if __name__=='__main__':unittest.main()
