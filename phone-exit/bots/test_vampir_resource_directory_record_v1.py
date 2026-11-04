"""Missing-index hashes require exact directory and fresh serialized headers."""
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
from unittest.mock import Mock,patch

from test_vampir_update_contracts import load

DIRECT=load('resource-directory-record-v1')
CSV=load('resource-csv-v3')
OWNER=load('resource-owner-v4')
WORKFLOW=load('research-workflow')
INDEXER=load('index-release-archives')
SELECTED=load('resource-selected-hashes-v1')


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def serialized(data=b'public direct payload',*,method=0,stored=None,flags=0,offset=0):
    stored=data if stored is None else stored
    base=struct.pack('<qqqI',offset,len(stored),len(data),method)+hashlib.sha1(stored).digest()
    if method:
        header=base+struct.pack('<iqqBI',1,73,73+len(stored),flags,len(data))
    else:header=base+struct.pack('<BI',flags,0)
    entry=dict(canonical_path='ProjectRED/Content/Missing.uplugin',offset=0,bytes=len(stored),
        uncompressed=len(data),method=method,blocks=int(bool(method)),encrypted=False)
    return header+stored,entry


class DirectHeaderTests(unittest.TestCase):
    def test_plain_compressed_and_empty_have_exact_sizes(self):
        for data,method,stored,hs in ((b'plain',0,None,53),(b'decoded',1,b'compressed',73),(b'',0,None,53)):
            raw,entry=serialized(data,method=method,stored=stored)
            header=DIRECT.parse_header(io.BytesIO(raw),entry,len(raw))
            self.assertEqual((header['hs'],header['end'],header['usize']),(hs,len(raw),len(data)))
            self.assertEqual(header['header_sha256'],hashlib.sha256(raw[:hs]).hexdigest())
            self.assertEqual(header['stored_sha1'],hashlib.sha1(raw[hs:]).hexdigest())

    def test_every_header_prefix_is_rejected_when_truncated(self):
        for method,hs in ((0,53),(1,73)):
            raw,entry=serialized(method=method)
            for size in range(hs):
                with self.subTest(method=method,size=size),self.assertRaises(ValueError):
                    DIRECT.parse_header(io.BytesIO(raw[:size]),entry,len(raw))

    def test_directory_scalars_and_local_offset_must_match(self):
        raw,entry=serialized()
        for field,value in (('offset',True),('bytes',-1),('uncompressed',1),('method',2),('blocks',True),('encrypted',True)):
            with self.subTest(field=field),self.assertRaises(ValueError):
                DIRECT.parse_header(io.BytesIO(raw),dict(entry,**{field:value}),len(raw))
        wrong,_=serialized(offset=123)
        with self.assertRaises(ValueError):DIRECT.parse_header(io.BytesIO(wrong),entry,len(wrong))

    def test_neighbor_or_index_boundary_cannot_cut_header_or_payload(self):
        for method in (0,1):
            raw,entry=serialized(method=method)
            for limit in (0,1,47,52,len(raw)-1):
                with self.subTest(method=method,limit=limit),self.assertRaises(ValueError):
                    DIRECT.parse_header(io.BytesIO(raw),entry,limit)

    def test_encrypted_deleted_or_unknown_flags_are_rejected(self):
        for method in (0,1):
            for flags in (1,2,3,128):
                raw,entry=serialized(method=method,flags=flags)
                with self.subTest(method=method,flags=flags),self.assertRaises(ValueError):
                    DIRECT.parse_header(io.BytesIO(raw),entry,len(raw))

    def test_plain_and_empty_require_zero_blocksize_and_matching_lengths(self):
        raw,entry=serialized()
        changed=bytearray(raw);struct.pack_into('<I',changed,49,1)
        with self.assertRaises(ValueError):DIRECT.parse_header(io.BytesIO(changed),entry,len(raw))
        with self.assertRaises(ValueError):DIRECT.parse_header(io.BytesIO(raw),dict(entry,blocks=1),len(raw))
        changed=bytearray(raw);struct.pack_into('<q',changed,16,len(raw)-54)
        different=dict(entry,uncompressed=len(raw)-54)
        with self.assertRaises(ValueError):DIRECT.parse_header(io.BytesIO(changed),different,len(raw))

    def test_compressed_count_blocksize_spans_and_stored_sum_are_strict(self):
        raw,entry=serialized(b'12345',method=1,stored=b'abc')
        mutations=[(48,'<i',0),(48,'<i',1025),(48,'<i',2),(52,'<q',72),(52,'<q',74),
            (60,'<q',73),(60,'<q',75),(60,'<q',77),(69,'<I',0),(69,'<I',4),(69,'<I',DIRECT.LIMIT+1)]
        for offset,code,value in mutations:
            changed=bytearray(raw);struct.pack_into(code,changed,offset,value)
            with self.subTest(offset=offset,value=value),self.assertRaises(ValueError):
                DIRECT.parse_header(io.BytesIO(changed),entry,len(changed))
        with self.assertRaises(ValueError):DIRECT.parse_header(io.BytesIO(raw),dict(entry,blocks=2),len(raw))

    def test_record_budget_is_checked_before_payload_allocation(self):
        raw,entry=serialized()
        for field in ('bytes','uncompressed'):
            with self.assertRaises(ValueError):DIRECT.parse_header(io.BytesIO(raw),dict(entry,**{field:DIRECT.LIMIT+1}),len(raw))


class DirectoryRecordScopeTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.knowledge=self.root/'registry';self.knowledge.mkdir()
        (self.knowledge/'resource-owner-engine.json').write_bytes(WORKFLOW.canonical(dict(schema=4,recipe='resource-owner-sha-v4')))
        self.primary_files=[]
        for name in ('source','package','nuspec'):
            path=self.root/'primary'/name;path.parent.mkdir(exist_ok=True);path.write_bytes(('public fixture '+name).encode())
            self.primary_files.append(dict(path=str(path),sha256=digest(path)))
        self.primary=dict(schema=1,recipe='pak-serialized-entry-layout-v1',
            rules=dict(v11_plain_header_bytes=53,v11_compressed_header_bytes='57 + 16 * block_count'),
            **dict(zip(('source','package','nuspec'),self.primary_files)))
        self.rule=dict(DIRECT.BASE,format_proof=self.snapshot('knowledge/header-primary-fixtures',self.primary))
        self.selector=self.knowledge/'resource-directory-record.json';self.selector.write_bytes(WORKFLOW.canonical(self.rule))
        self.rf=self.root/'decoder';self.oodle=self.rf/'tools/oodle-data-shared.dll';self.oodle.parent.mkdir(parents=True)
        self.oodle.write_bytes(b'public synthetic decoder identity, never executable')
        env=patch.dict(os.environ,{'PHONEEXIT_RF_RESOURCES':str(self.rf)});env.start();self.addCleanup(env.stop)
        self.modules={'research-workflow':WORKFLOW,'resource-csv-v3':CSV,'index-release-archives':INDEXER,
            'resource-selected-hashes-v1':SELECTED}
        self.index=SimpleNamespace(HERE=DIRECT.HERE,digest=digest,extension=lambda n:self.modules[n],
            read_json=lambda p:json.loads(Path(p).read_bytes()))
        self.args=SimpleNamespace(root=self.root,knowledge=self.knowledge)
        self.archive=self.root/'current.pak';self.data=b'public direct payload';self.method=0;self.stored=None
        self.record_entries=[];self.neighbors=[];self.directory_rules=dict(fixture='checked directory rules')
        self.directory_runtime=dict(fixture='checked directory runtime')
        self.owner=None
        self.reader=SimpleNamespace(decode=Mock(side_effect=lambda stream,header:self.data))
        loader=patch.object(CSV,'_load_reader',return_value=self.reader);self.loader=loader.start();self.addCleanup(loader.stop)
        self.save_source();self.begin()

    def snapshot(self,category,value):
        path=WORKFLOW.snapshot(self.root,category,value)
        return dict(path=str(path),sha256=digest(path))

    def save_source(self):
        self.raw,self.entry=serialized(self.data,method=self.method,stored=self.stored)
        self.archive.write_bytes(self.raw+b'public index placeholder')
        self.record=dict(schema=1,source=dict(path=str(self.archive),sha256=digest(self.archive),
            size=self.archive.stat().st_size,pak_version=11),index_offset=len(self.raw),entries=copy.deepcopy(self.record_entries),
            dependencies=dict(reader_sha256=digest(CSV.HERE.parent/'rfnext/scan-pak.py'),
                oodle_sha256=digest(self.oodle),tool_sha256=digest(CSV.HERE/'index-release-archives.py')))
        self.save_proofs()

    def save_proofs(self):
        self.record_pointer=self.snapshot('knowledge/direct-record-fixtures',self.record)
        self.row=dict(path=str(self.archive),current=copy.deepcopy(self.record['source']))
        self.directory=dict(recipe='resource-directory-v1',authoritative_directory_for_archive=True,
            inputs=dict(source=copy.deepcopy(self.record['source']),record_index=self.record_pointer,
                rules=self.directory_rules,runtime=self.directory_runtime),
            directory_entries=[copy.deepcopy(self.entry),*copy.deepcopy(self.neighbors)],path_gaps=[],unmatched_csv=[])
        self.pointer=self.snapshot('knowledge/direct-directory-fixtures',self.directory)

    def begin(self):
        if self.owner is not None and not self.owner.closed:self.owner.abort()
        self.owner=OWNER.begin(self.index,self.args)
        self.args.resource_directory_v1_scope=SimpleNamespace(owner=self.owner,rules=self.directory_rules,runtime=self.directory_runtime)
        self.addCleanup(lambda owner=self.owner:owner.abort() if not owner.closed else None)
        self.scope=DIRECT.Scope(self.index,self.args)

    def resolve(self,entry=None,pointer=None,row=None):
        return self.scope.resolve(self.row if row is None else row,self.pointer if pointer is None else pointer,
            self.entry if entry is None else entry)

    def caches(self):
        return list((self.root/'knowledge/resource-comparison-cache-v3').glob('directory-record-*.json'))

    def test_plain_source_bound_sha1_and_sha256_are_deferred_until_owner(self):
        result=self.resolve();body=json.loads(Path(result['proof']['path']).read_bytes())
        self.assertEqual(result['sha256'],hashlib.sha256(self.data).hexdigest())
        self.assertEqual(body['header']['stored_sha1'],hashlib.sha1(self.data).hexdigest())
        self.assertEqual(body['stored_record_sha256'],hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(body['inputs']['directory'],self.pointer)
        self.assertEqual(body['inputs']['record_index'],self.record_pointer)
        self.assertIs(body['payload_saved'],False);self.assertIs(body['runtime_activated'],False)
        self.assertEqual(self.caches(),[]);self.owner.finish();self.assertEqual(len(self.caches()),1)
        self.reader.decode.assert_not_called();self.loader.assert_not_called()

    def test_compressed_payload_uses_fixed_decoder_after_stored_sha1_check(self):
        self.method=1;self.stored=b'public compressed fixture';self.save_source();self.begin()
        result=self.resolve();self.owner.finish()
        self.assertEqual(result['sha256'],hashlib.sha256(self.data).hexdigest())
        self.assertEqual(self.scope.metrics['compressed_decodes'],1)
        self.assertEqual(self.scope.metrics['plain_reads'],0)
        self.loader.assert_called_once();self.reader.decode.assert_called_once()

    def test_empty_record_has_explicit_empty_sha_without_native_decoder(self):
        self.data=b'';self.save_source();self.begin();result=self.resolve();self.owner.finish()
        self.assertEqual(result['sha256'],hashlib.sha256(b'').hexdigest())
        self.assertEqual(self.scope.metrics['empty_records'],1)
        self.assertEqual(self.scope.metrics['decoded_bytes'],0)
        self.reader.decode.assert_not_called();self.loader.assert_not_called()

    def test_warm_compressed_result_rechecks_proofs_without_decode(self):
        self.method=1;self.stored=b'public compressed fixture';self.save_source();self.begin()
        first=self.resolve();self.owner.finish();self.loader.reset_mock();self.reader.decode.reset_mock()
        self.begin();second=self.resolve();self.owner.finish()
        self.assertEqual(first,second);self.assertEqual(self.scope.metrics['cache_hits'],1)
        self.reader.decode.assert_not_called();self.loader.assert_not_called()

    def test_exact_same_source_offset_is_memoized_across_requests(self):
        first=self.resolve();self.assertEqual(self.resolve(),first)
        self.assertEqual(self.scope.metrics['unique_records'],1);self.assertEqual(self.scope.metrics['memo_hits'],1)
        self.assertEqual(self.scope.metrics['plain_reads'],1)

    def test_caller_entry_source_or_directory_pointer_cannot_drift_after_memo(self):
        self.resolve()
        with self.assertRaises(ValueError):self.resolve(entry=dict(self.entry,bytes=self.entry['bytes']+1))
        with self.assertRaises(ValueError):self.resolve(row=dict(self.row,current=dict(self.row['current'],sha256='a'*64)))
        changed=copy.deepcopy(self.directory);changed['fixture_note']='different proof'
        pointer=self.snapshot('knowledge/direct-directory-fixtures',changed)
        with self.assertRaises(ValueError):self.resolve(pointer=pointer)

    def test_same_offset_directory_alias_cannot_change_metadata_after_memo(self):
        conflicting=dict(self.entry,canonical_path='ProjectRED/Content/Conflicting.uplugin',bytes=self.entry['bytes']+1)
        self.neighbors=[conflicting];self.save_proofs();self.begin()
        with self.assertRaises(ValueError):
            self.resolve()
            self.resolve(entry=conflicting)

    def test_indexed_record_cannot_be_replaced_by_direct_recipe(self):
        self.record_entries=[dict(entry=0,offset=0,end=len(self.raw),bytes=len(self.data),uncompressed=len(self.data),
            method=0,encrypted=False,stored_record_sha256=hashlib.sha256(self.raw).hexdigest())]
        self.save_source();self.begin()
        with self.assertRaises(ValueError):self.resolve()
        self.assertEqual(self.owner.pending,{})

    def test_stored_payload_sha1_mismatch_is_rejected_before_decoder(self):
        self.method=1;self.stored=b'public compressed fixture';self.save_source()
        raw=bytearray(self.archive.read_bytes());raw[28]^=1;self.archive.write_bytes(raw)
        self.record['source'].update(sha256=digest(self.archive));self.save_proofs();self.begin()
        with self.assertRaises(ValueError):self.resolve()
        self.reader.decode.assert_not_called();self.assertEqual(self.owner.pending,{})

    def test_neighbor_boundary_prevents_payload_escape(self):
        self.neighbors=[dict(self.entry,canonical_path='ProjectRED/Content/Next.bin',offset=len(self.raw)-1)]
        self.save_proofs();self.begin()
        with self.assertRaises(ValueError):self.resolve()
        self.assertEqual(self.owner.pending,{})

    def test_header_source_version_and_directory_provenance_are_exact(self):
        variants=[('source',lambda d:d['inputs']['source'].update(sha256='a'*64)),
            ('rules',lambda d:d['inputs'].update(rules={})),('runtime',lambda d:d['inputs'].update(runtime={})),
            ('authority',lambda d:d.update(authoritative_directory_for_archive=False)),
            ('gap',lambda d:d.update(path_gaps=[{}])),('unmatched',lambda d:d.update(unmatched_csv=[{}]))]
        for label,change in variants:
            self.begin();d=copy.deepcopy(self.directory);change(d);p=self.snapshot('knowledge/direct-directory-fixtures',d)
            with self.subTest(label=label),self.assertRaises(ValueError):self.resolve(pointer=p)
        self.record['source']['pak_version']=10;self.save_proofs();self.begin()
        with self.assertRaises(ValueError):self.resolve()

    def test_different_owner_and_ambiguous_directory_are_rejected(self):
        self.args.resource_directory_v1_scope.owner=object()
        with self.assertRaises(ValueError):self.resolve()
        self.begin();d=copy.deepcopy(self.directory);d['directory_entries'].append(copy.deepcopy(self.entry))
        p=self.snapshot('knowledge/direct-directory-fixtures',d)
        with self.assertRaises(ValueError):self.resolve(pointer=p)

    def test_directory_and_record_pointer_corruption_is_rejected(self):
        for pointer in (self.pointer,self.record_pointer):
            self.begin();p=Path(pointer['path']);raw=p.read_bytes();p.write_bytes(raw+b' ')
            with self.subTest(path=p.name),self.assertRaises(ValueError):self.resolve()
            p.write_bytes(raw)
        self.reader.decode.assert_not_called()

    def test_corrupted_warm_hash_is_not_silently_rebuilt(self):
        result=self.resolve();self.owner.finish();p=Path(result['proof']['path']);p.write_bytes(p.read_bytes()+b' ')
        self.begin()
        with self.assertRaises(ValueError):self.resolve()
        self.assertEqual(self.scope.metrics['plain_reads'],0)

    def test_primary_source_selector_or_archive_change_blocks_assignment(self):
        for target in (Path(self.primary_files[0]['path']),self.selector,self.archive):
            self.begin();self.resolve();raw=target.read_bytes();target.write_bytes(raw+b' ')
            with self.subTest(target=target.name),self.assertRaises(ValueError):self.owner.finish()
            target.write_bytes(raw)
            self.assertEqual(self.caches(),[])

    def test_runtime_metadata_change_blocks_assignment(self):
        self.resolve();original=CSV._runtime
        def different(index,args):
            result=original(index,args);result['implementation']='changed';return result
        with patch.object(CSV,'_runtime',side_effect=different),self.assertRaises(ValueError):self.owner.finish()
        self.assertEqual(self.caches(),[])

    def test_decoder_length_and_type_are_checked(self):
        self.method=1;self.stored=b'public compressed fixture';self.save_source()
        for bad in (None,bytearray(self.data),self.data[:-1]):
            self.begin();self.reader.decode.side_effect=None;self.reader.decode.return_value=bad
            with self.subTest(type=type(bad).__name__),self.assertRaises(ValueError):self.resolve()
            self.assertEqual(self.owner.pending,{})

    def test_fixed_primary_recipe_and_budget_config_are_not_inferred(self):
        for rule in (dict(self.rule,schema=True),dict(self.rule,record_bytes=3),dict(self.rule,extra=True)):
            self.selector.write_bytes(WORKFLOW.canonical(rule))
            with self.assertRaises(ValueError):DIRECT.configuration(self.args)
        self.selector.write_bytes(WORKFLOW.canonical(self.rule))
        for primary in (dict(self.primary,recipe='other'),dict(self.primary,schema=True),dict(self.primary,rules={})):
            p=self.snapshot('knowledge/header-primary-fixtures',primary)
            rule=dict(self.rule,format_proof=p);self.selector.write_bytes(WORKFLOW.canonical(rule))
            with self.assertRaises(ValueError):DIRECT.Scope(self.index,self.args)


if __name__=='__main__':unittest.main()
