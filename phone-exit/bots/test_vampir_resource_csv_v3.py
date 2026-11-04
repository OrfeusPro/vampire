"""Bounded current CSV extraction never depends on historical table identity."""
import copy
import csv
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_vampir_update_contracts import load


CSV = load('resource-csv-v3')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Fixture:
    def __init__(self, directory):
        self.root = Path(directory).resolve()
        self.args = SimpleNamespace(root=self.root)
        self.index = SimpleNamespace(digest=digest)
        self.rf = self.root/'rf'
        oodle = self.rf/'tools/oodle-data-shared.dll'
        oodle.parent.mkdir(parents=True); oodle.write_bytes(b'bounded decoder fixture')
        self.environment = patch.dict(os.environ, {'PHONEEXIT_RF_RESOURCES': str(self.rf)})
        self.environment.start()
        self.archive = self.root/'current.pak'
        self.archive.write_bytes(b'bounded archive fixture'*64)
        self.data = b'\xef\xbb\xbfID,Text\n1,one\n2,two\n'
        self.entry = dict(entry=0, offset=0, end=256, bytes=len(self.data),
            uncompressed=len(self.data), method=0, encrypted=False,
            decoded_sha256=hashlib.sha256(self.data).hexdigest(), decode_status='decoded', uasset=False)
        self.record = dict(schema=1, source=dict(path=str(self.archive), sha256=digest(self.archive),
            size=self.archive.stat().st_size, pak_version=11), index_offset=512, reached_index=True,
            decode_limit=2*1024*1024, dependencies=dict(
                reader_sha256=digest(CSV.HERE.parent/'rfnext/scan-pak.py'),
                oodle_sha256=digest(oodle), tool_sha256=digest(CSV.HERE/'index-release-archives.py')),
            entries=[copy.deepcopy(self.entry)])
        self.reader = SimpleNamespace(ROOT=self.rf, header=Mock(side_effect=self.header),
            decode=Mock(side_effect=lambda stream, header:self.data))
        self.pointer = self.save_record()
        self.loader = patch.object(CSV, '_load_reader', return_value=self.reader)
        self.loader.start()

    def close(self):
        self.loader.stop(); self.environment.stop()

    def header(self, stream, offset, limit):
        entry = next(row for row in self.record['entries'] if row['offset'] == offset)
        return dict(pos=entry['offset'], end=entry['end'], size=entry['bytes'],
            usize=entry['uncompressed'], method=entry['method'], encrypted=entry['encrypted'],
            hs=53, blocks=[], blocksize=0)

    def save(self, folder, value):
        raw = CSV._canonical(value)
        sha = hashlib.sha256(raw).hexdigest()
        path = folder/sha/'manifest.json'; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return dict(path=str(path), sha256=sha)

    def save_record(self):
        self.pointer = self.save(self.root/'knowledge/record-fixture', self.record)
        return self.pointer

    def extract(self, **kwargs):
        return CSV.extract(self.index, self.args, self.pointer, **kwargs)

    def checked(self, pointer):
        return CSV.load_checked(self.index, self.args, pointer)

    def legacy(self, *, extra=None, tables=None):
        csv_sha = hashlib.sha256(self.data).hexdigest()
        old = Path(self.pointer['path']).parent/'csv-blobs'/(csv_sha+'.csv')
        old.parent.mkdir(parents=True, exist_ok=True); old.write_bytes(self.data)
        parser = load('extract-release-tables')
        header, rows = parser.parse_csv(self.data)
        table = dict(file=str(old), entry=self.entry['entry'], offset=self.entry['offset'],
            sha256=csv_sha, bytes=len(self.data), header=header, rows=rows, internal_path=None,
            identical_previous_files=['missing-history.csv'], unique_schema_candidate='missing-other.csv')
        value = dict(schema=1, source=copy.deepcopy(self.record['source']),
            tool_sha256=digest(CSV.HERE/'extract-release-tables.py'),
            record_index_sha256=self.pointer['sha256'], dependencies=copy.deepcopy(self.record['dependencies']),
            tables=[table] if tables is None else tables, errors=[], skipped=0,
            previous_table_index='does-not-exist.json', previous_table_index_sha256='a'*64,
            scope=CSV.LEGACY_SCOPE, compatibility='not_established')
        value.update(extra or {})
        return self.save(Path(self.pointer['path']).parent/'table-snapshots', value)


class ResourceCsvV3Tests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.f = Fixture(folder.name); self.addCleanup(self.f.close)

    @staticmethod
    def mutate_same_stat(path):
        path = Path(path); before = path.stat(); raw = path.read_bytes()
        path.write_bytes(bytes([raw[0] ^ 1])+raw[1:])
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))

    def test_current_csv_extracts_without_any_old_table_index(self):
        f = self.f
        foreign = f.root/'table-study/index.json'; foreign.parent.mkdir()
        foreign.write_text('{"tables":[{"source":{"path":"foreign.pak"}}]}', 'utf-8')
        pointer = f.extract(source_sha256=f.record['source']['sha256'])
        report = f.checked(pointer)
        self.assertEqual(report['state'], 'extracted')
        self.assertEqual(report['compatibility'], 'not_established')
        self.assertEqual(len(report['tables']), 1)
        table = report['tables'][0]
        self.assertEqual(table['header'], ['ID', 'Text']); self.assertEqual(table['rows'], 2)
        self.assertIsNone(table['internal_path'])
        self.assertEqual(Path(table['file']).read_bytes(), f.data)
        self.assertNotIn('previous_table_index', report['inputs'])

    def test_warm_report_rechecks_output_but_does_not_decode_again(self):
        f = self.f
        first = f.extract(); calls = f.reader.decode.call_count
        self.assertEqual(f.extract(), first)
        self.assertEqual(f.reader.decode.call_count, calls)
        table = f.checked(first)['tables'][0]
        self.mutate_same_stat(table['file'])
        with self.assertRaisesRegex(ValueError, 'CSV blob'):
            f.extract()
        self.assertEqual(f.reader.decode.call_count, calls)

    def previous_producer(self):
        f=self.f
        current=f.extract()
        value=json.loads(Path(current['path']).read_bytes())
        producer=str(Path(CSV.__file__).resolve())
        value['inputs']['tools'][producer]='a'*64
        value['input_sha256']=CSV._input_sha(value['inputs'])
        previous=f.save(f.root/'knowledge'/CSV.CATEGORY,value)
        old_cache=f.root/'knowledge/resource-csv-v3-cache'/(value['input_sha256']+'.json')
        old_cache.write_bytes(CSV._canonical(previous))
        current_inputs=CSV.inputs(f.index,f.args,f.pointer)
        cache=f.root/'knowledge/resource-csv-v3-cache'/(CSV._input_sha(current_inputs)+'.json')
        cache.unlink()
        f.args.knowledge=f.root/'registry';f.args.knowledge.mkdir()
        registry=f.args.knowledge/'resource-csv-reuse.json'
        registry.write_bytes(CSV._canonical(dict(schema=1,recipe='csv-prepared-inputs-reuse-v1',
            previous_producer_sha256='a'*64)))
        return previous,old_cache,cache,registry

    def test_warm_extract_prepares_once_and_still_hashes_archive_at_final_barrier(self):
        f=self.f;first=f.extract()
        f.index.digest=Mock(side_effect=digest)
        self.assertEqual(f.extract(),first)
        reads=[c for c in f.index.digest.call_args_list if Path(c.args[0]).resolve()==f.archive]
        self.assertEqual(len(reads),2)
        f.index.digest.reset_mock();f.checked(first)
        reads=[c for c in f.index.digest.call_args_list if Path(c.args[0]).resolve()==f.archive]
        self.assertEqual(len(reads),2)

    def begin_owner(self):
        f=self.f
        f.args.knowledge=f.root/'registry'
        f.args.knowledge.mkdir(exist_ok=True)
        (f.args.knowledge/'resource-owner-engine.json').write_bytes(CSV._canonical(
            dict(schema=4,recipe='resource-owner-sha-v4')))
        f.index.extension=load
        return load('resource-owner-v4').begin(f.index,f.args)

    def test_owner_keeps_csv_cache_pending_and_reuses_pending_result(self):
        f=self.f;f.index.digest=Mock(side_effect=digest);owner=self.begin_owner()
        pointer=f.extract();calls=f.reader.decode.call_count
        self.assertEqual(f.extract(),pointer)
        self.assertEqual(f.reader.decode.call_count,calls)
        self.assertFalse(list((f.root/'knowledge/resource-csv-v3-cache').glob('*.json')))
        reads=lambda:sum(Path(c.args[0]).resolve()==f.archive for c in f.index.digest.call_args_list)
        self.assertEqual(reads(),1)
        result=owner.finish();self.assertTrue(result['barrier_completed'])
        self.assertEqual(reads(),2)
        self.assertEqual(len(list((f.root/'knowledge/resource-csv-v3-cache').glob('*.json'))),1)
        f.args.resource_owner=None
        self.assertEqual(f.checked(pointer)['tables'][0]['header'],['ID','Text'])

    def test_owner_final_barrier_rejects_late_pak_and_blob_changes_without_cache(self):
        f=self.f;owner=self.begin_owner();pointer=f.extract()
        table=json.loads(Path(pointer['path']).read_bytes())['tables'][0]
        for path in (f.archive,Path(table['file'])):
            before=path.read_bytes();self.mutate_same_stat(path)
            with self.assertRaises(ValueError):owner.finish()
            self.assertFalse(list((f.root/'knowledge/resource-csv-v3-cache').glob('*.json')))
            path.write_bytes(before)
            if path==f.archive:
                owner=load('resource-owner-v4').begin(f.index,f.args)
                f.extract()

    def test_registered_previous_producer_reuses_outputs_and_creates_current_cache(self):
        f=self.f;previous,_,cache,_=self.previous_producer()
        calls=f.reader.decode.call_count
        result=f.extract();report=f.checked(result)
        self.assertEqual(report['producer_reuse']['previous_report'],previous)
        self.assertTrue(report['producer_reuse']['cold_migration_only'])
        self.assertEqual(json.loads(cache.read_bytes()),result)
        self.assertEqual(f.extract(),result)
        self.assertEqual(f.reader.decode.call_count,calls)

    def test_producer_reuse_preserves_legacy_bridge_accounting(self):
        self.f.legacy()
        self.previous_producer()
        result=self.f.checked(self.f.extract())
        self.assertEqual(result['legacy_bridge']['method'],'checked_legacy_current_csv')
        self.assertEqual(result['skipped'],0)
        self.assertIn('producer_reuse',result)

    def test_producer_reuse_rejects_changed_inputs_and_record_pointer(self):
        f=self.f
        previous,old_cache,cache,_=self.previous_producer()
        for field in ('runtime','record_index'):
            report=json.loads(Path(previous['path']).read_bytes())
            if field=='runtime':report['inputs']['runtime']['python']='another runtime'
            else:report['record_index']=dict(report['record_index'],sha256='b'*64)
            corrupt=f.save(f.root/'knowledge'/CSV.CATEGORY,report)
            old_cache.write_bytes(CSV._canonical(corrupt))
            with self.subTest(field=field),self.assertRaises(ValueError):f.extract()
            self.assertFalse(cache.exists())

    def test_producer_reuse_checks_late_archive_registry_cache_and_output_mutations(self):
        f=self.f;_,old_cache,cache,registry=self.previous_producer()
        outputs=CSV._outputs
        for filename in (f.archive,registry,old_cache):
            before=filename.read_bytes()
            def mutate(*args,**kwargs):
                outputs(*args,**kwargs)
                self.mutate_same_stat(filename)
            with self.subTest(filename=filename),patch.object(CSV,'_outputs',side_effect=mutate):
                with self.assertRaises(ValueError):f.extract()
            filename.write_bytes(before)
            self.assertFalse(cache.exists())
        old=json.loads(old_cache.read_bytes())
        table=json.loads(Path(old['path']).read_bytes())['tables'][0]
        self.mutate_same_stat(table['file'])
        with self.assertRaisesRegex(ValueError,'CSV blob'):f.extract()
        self.assertFalse(cache.exists())

    def test_producer_reuse_rejects_malformed_reports_and_oversized_cache(self):
        f=self.f;_,old_cache,cache,_=self.previous_producer()
        for value in ([],None,dict(schema=3)):
            pointer=f.save(f.root/'knowledge'/CSV.CATEGORY,value)
            old_cache.write_bytes(CSV._canonical(pointer))
            with self.subTest(value=value):
                with self.assertRaises(ValueError):f.extract()
                with self.assertRaises(ValueError):f.checked(pointer)
            self.assertFalse(cache.exists())
        old_cache.write_bytes(b' '*4097)
        with self.assertRaisesRegex(ValueError,'cache'):f.extract()
        self.assertFalse(cache.exists())

    def test_inputs_are_stable_and_do_not_include_file_mtime(self):
        f = self.f
        before = CSV.inputs(f.index, f.args, f.pointer)
        stat = f.archive.stat(); os.utime(f.archive, ns=(stat.st_atime_ns, stat.st_mtime_ns+1000000))
        self.assertEqual(CSV.inputs(f.index, f.args, f.pointer), before)
        before['tools']['poison'] = 'a'*64
        self.assertNotIn('poison', CSV.inputs(f.index, f.args, f.pointer)['tools'])

    def test_wrong_archive_sha_is_rejected_before_decode(self):
        with self.assertRaisesRegex(ValueError, 'другой SHA'):
            self.f.extract(source_sha256='f'*64)
        self.f.reader.decode.assert_not_called()

    def test_source_content_change_with_same_size_mtime_is_not_a_valid_input(self):
        f = self.f
        self.mutate_same_stat(f.archive)
        with self.assertRaisesRegex(ValueError, 'SHA'):
            f.extract()
        f.reader.decode.assert_not_called()

    def test_decoder_and_reader_dependency_changes_are_not_accepted(self):
        f = self.f
        for key in ('reader_sha256', 'oodle_sha256'):
            with self.subTest(key=key):
                old = f.record['dependencies'][key]; f.record['dependencies'][key] = 'f'*64
                f.save_record()
                with self.assertRaisesRegex(ValueError, 'декодера'):
                    f.extract()
                f.record['dependencies'][key] = old
        f.reader.decode.assert_not_called()

    def test_record_index_and_pointer_corruption_are_rejected(self):
        f = self.f
        path = Path(f.pointer['path']); original = path.read_bytes()
        self.mutate_same_stat(path)
        with self.assertRaisesRegex(ValueError, 'Manifest'):
            f.extract()
        path.write_bytes(original)
        with self.assertRaisesRegex(ValueError, 'pointer'):
            CSV.extract(f.index, f.args, dict(f.pointer, other=True))

    def test_header_mismatch_is_fatal_before_decoding_or_new_report(self):
        f = self.f
        f.reader.header.side_effect = lambda stream, offset, limit: dict(f.header(stream, offset, limit), usize=999)
        with self.assertRaisesRegex(ValueError, 'Fresh record header'):
            f.extract()
        f.reader.decode.assert_not_called()
        self.assertFalse(list((f.root/'knowledge/resource-csv-v3').glob('*/manifest.json')))

    def test_decoded_sha_size_and_csv_errors_are_partial_reports(self):
        f = self.f
        for mode in ('hash', 'size', 'unicode'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                other = Fixture(directory)
                try:
                    if mode == 'hash':
                        other.reader.decode.side_effect = lambda stream, header:b'x'*len(other.data)
                    elif mode == 'size':
                        other.reader.decode.side_effect = lambda stream, header:b'x'
                    else:
                        other.data = b'\xef\xbb\xbfID,Text\n1,\xff\n'
                        other.record['entries'][0].update(bytes=len(other.data), uncompressed=len(other.data),
                            decoded_sha256=hashlib.sha256(other.data).hexdigest())
                        other.save_record()
                    pointer = other.extract(); report = other.checked(pointer)
                    self.assertEqual(report['state'], 'partial')
                    self.assertEqual(len(report['errors']), 1)
                    self.assertEqual(report['tables'], [])
                    calls = other.reader.decode.call_count
                    self.assertEqual(other.extract(), pointer)
                    self.assertEqual(other.reader.decode.call_count, calls)
                finally:
                    other.close()

    def test_encrypted_and_oversize_records_are_skipped_without_decode(self):
        f = self.f
        f.record['entries'] = [dict(f.entry, entry=0, encrypted=True),
            dict(f.entry, entry=1, offset=256, end=512, uncompressed=CSV.LIMIT+1)]
        f.save_record()
        report = f.checked(f.extract())
        self.assertEqual(report['skipped'], 2)
        self.assertEqual(report['skip_reasons'], dict(encrypted=1, size_budget=1))
        f.reader.header.assert_not_called(); f.reader.decode.assert_not_called()

    def test_non_csv_records_do_not_gain_names_or_table_identity(self):
        f = self.f
        f.data = b'ordinary bytes, not BOM CSV'
        f.record['entries'][0].update(bytes=len(f.data), uncompressed=len(f.data),
            decoded_sha256=hashlib.sha256(f.data).hexdigest())
        f.save_record()
        report = f.checked(f.extract())
        self.assertEqual(report['tables'], [])
        self.assertEqual(report['non_csv_records'], 1)
        self.assertFalse(report['logical_paths_assumed'])

    def test_uasset_magic_reuses_only_strict_verified_producer_classification(self):
        f = self.f
        f.record['entries'][0]['uasset'] = True; f.save_record()
        report = f.checked(f.extract())
        self.assertEqual(report['skip_reasons'], dict(proven_uasset_magic=1))
        f.reader.decode.assert_not_called()
        for mode in ('unknown_producer', 'integer_flag', 'wrong_limit', 'not_decoded'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                other = Fixture(directory)
                try:
                    other.record['entries'][0]['uasset'] = True
                    if mode == 'unknown_producer': other.record['dependencies']['tool_sha256'] = 'f'*64
                    if mode == 'integer_flag': other.record['entries'][0]['uasset'] = 1
                    if mode == 'wrong_limit': other.record['decode_limit'] = 1024
                    if mode == 'not_decoded': other.record['entries'][0]['decode_status'] = 'size_skipped'
                    other.save_record(); actual = other.checked(other.extract())
                    self.assertEqual(len(actual['tables']), 1)
                    other.reader.decode.assert_called_once()
                finally:
                    other.close()

    def test_existing_current_legacy_csv_bridges_without_reading_history_or_decoding(self):
        f = self.f
        legacy = f.legacy()
        report = f.checked(f.extract())
        self.assertEqual(len(report['tables']), 1)
        self.assertEqual(report['legacy_bridge']['reports'], [legacy])
        self.assertFalse(report['legacy_bridge']['previous_comparison_inputs_read'])
        f.reader.decode.assert_not_called()
        # A later warm report depends on its copied blobs, not old comparison files.
        self.assertFalse((f.root/'does-not-exist.json').exists())

    def test_legacy_wrong_source_or_tool_falls_back_to_current_decode(self):
        for mode in ('source', 'tool', 'record'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                f = Fixture(directory)
                try:
                    extra = dict(source=dict(f.record['source'], sha256='f'*64)) if mode == 'source' else (
                        dict(tool_sha256='f'*64) if mode == 'tool' else dict(record_index_sha256='f'*64))
                    f.legacy(extra=extra)
                    report = f.checked(f.extract())
                    self.assertNotIn('legacy_bridge', report)
                    f.reader.decode.assert_called_once()
                finally:
                    f.close()

    def test_corrupt_current_legacy_blob_blocks_bridge_instead_of_hiding_corruption(self):
        f = self.f
        legacy = f.legacy(); value = json.loads(Path(legacy['path']).read_text('utf-8'))
        self.mutate_same_stat(value['tables'][0]['file'])
        with self.assertRaisesRegex(ValueError, 'legacy CSV'):
            f.extract()
        f.reader.decode.assert_not_called()

    def test_conflicting_eligible_legacy_reports_are_an_explicit_blocker(self):
        f = self.f
        f.legacy(); f.legacy(tables=[])
        with self.assertRaisesRegex(ValueError, 'противоречат'):
            f.extract()
        f.reader.decode.assert_not_called()

    def test_existing_content_addressed_csv_corruption_is_not_overwritten(self):
        f = self.f
        target = CSV._blob(f.root, hashlib.sha256(f.data).hexdigest())
        target.parent.mkdir(parents=True); target.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'blob повреждён'):
            f.extract()
        self.assertEqual(target.read_bytes(), b'corrupt')

    def test_mutation_during_decode_is_caught_by_fresh_final_sha_barrier(self):
        f = self.f
        def decode(stream, header):
            self.mutate_same_stat(f.archive)
            return f.data
        f.reader.decode.side_effect = decode
        with self.assertRaisesRegex(ValueError, 'Вход CSV изменился'):
            f.extract()
        self.assertFalse(list((f.root/'knowledge/resource-csv-v3-cache').glob('*.json')))

    def test_load_checked_pins_all_outputs_and_expected_input_identity(self):
        f = self.f
        pointer = f.extract(); expected = CSV.inputs(f.index, f.args, f.pointer)
        value = CSV.load_checked(f.index, f.args, pointer, expected_inputs=expected)
        changed = copy.deepcopy(expected); changed['budgets']['decoded_bytes'] += 1
        with self.assertRaisesRegex(ValueError, 'Входы CSV'):
            CSV.load_checked(f.index, f.args, pointer, expected_inputs=changed)
        changed_report = copy.deepcopy(value); changed_report['tables'][0]['file'] = str(f.archive)
        forged = CSV._save(f.root, changed_report)
        with self.assertRaisesRegex(ValueError, 'вне content-addressed'):
            f.checked(forged)

    def test_load_checked_rejects_forged_counters_and_duplicate_error_entries(self):
        f = self.f
        report = f.checked(f.extract())
        for change in (dict(non_csv_records=1), dict(state='partial'), dict(skipped=1),
                dict(logical_paths_assumed=True), dict(errors=[dict(entry=0, offset=0, error_type='ValueError')])):
            with self.subTest(change=change):
                pointer = CSV._save(f.root, dict(copy.deepcopy(report), **change))
                with self.assertRaisesRegex(ValueError, 'CSV|ошибки'):
                    f.checked(pointer)

    def test_compressed_blocks_cannot_exceed_the_read_budget(self):
        f = self.f
        f.record['entries'][0]['method'] = 1
        f.save_record()
        f.reader.header.side_effect = lambda stream, offset, limit:dict(f.header(stream, offset, limit),
            blocks=[(53, 100), (100, CSV.LIMIT+100)], blocksize=65536)
        with self.assertRaisesRegex(ValueError, 'Compressed record'):
            f.extract()
        f.reader.decode.assert_not_called()

    def test_csv_field_limit_is_restored_and_parsing_is_serialized_between_workers(self):
        observed, active, peak = [], [0], [0]
        original = csv.field_size_limit()
        def parse(data):
            active[0] += 1; peak[0] = max(peak[0], active[0])
            observed.append(csv.field_size_limit())
            time.sleep(0.01)
            active[0] -= 1
            return ['ID', 'Value'], 1
        parser = SimpleNamespace(parse_csv=parse)
        threads = [threading.Thread(target=CSV._parse, args=(parser, b'anything')) for _ in range(4)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(observed, [CSV.FIELD_LIMIT]*4)
        self.assertEqual(peak[0], 1)
        self.assertEqual(csv.field_size_limit(), original)


if __name__ == '__main__':
    unittest.main()
