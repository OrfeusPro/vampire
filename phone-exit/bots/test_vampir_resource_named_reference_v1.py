"""Captured named-reference admission with explicit synthetic immutable proofs."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_vampir_update_contracts import load


REFERENCE = load('resource-named-reference-v1')
CURRENT_SOURCE = Path(REFERENCE.__file__).with_name('index-release-archives.py').read_bytes()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class FixtureOwner:
    def __init__(self):
        self.inputs = {}

    def check(self, index, args):
        pass

    def remember(self, path, raw):
        value = digest(raw)
        self.inputs[str(Path(path).resolve())] = value
        return value


class NamedReferenceTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.here = self.root/'tools'
        self.here.mkdir()
        self.args = SimpleNamespace(root=self.root)
        self.index = SimpleNamespace(HERE=self.here, extension=load)
        self.slot = str(self.root/'absent-historical.pak')
        self.archive_sha, self.exe_sha = 'a'*64, 'b'*64
        self.payload = b'\xef\xbb\xbfId,Value\n1,fixture\n'
        self.payload_file = self.root/'csv/payload.csv'
        self.payload_file.parent.mkdir()
        self.payload_file.write_bytes(self.payload)
        self.current_sha = self.file(self.here/'index-release-archives.py', CURRENT_SOURCE)['sha256']
        self.old = self.file(self.root/'producers/legacy.py',
            CURRENT_SOURCE + b'\nraise AssertionError("Historical code must not execute")\n')
        self.bridge = {self.old['sha256']:self.current_sha}
        reader = self.file(self.here.parent/'rfnext/scan-pak.py', b'# Captured reader fixture\n')
        oodle = self.file(self.root/'rf-resources/tools/oodle-data-shared.dll', b'Pinned fixture dependency')
        environment = patch.dict(REFERENCE.os.environ, {'PHONEEXIT_RF_RESOURCES':str(self.root/'rf-resources')})
        environment.start()
        self.addCleanup(environment.stop)
        self.dependencies = dict(tool_sha256=self.old['sha256'], reader_sha256=reader['sha256'],
            oodle_sha256=oodle['sha256'])
        rows = [dict(entry=0, offset=0, bytes=len(self.payload), uncompressed=len(self.payload),
                    method=0, encrypted=False, decode_status='decoded', decoded_sha256=digest(self.payload)),
            dict(entry=1, offset=200, bytes=25, uncompressed=25, method=0, encrypted=False,
                decode_status='decoded', decoded_sha256='c'*64),
            dict(entry=2, offset=400, bytes=3*1024*1024, uncompressed=3*1024*1024, method=0,
                encrypted=False, decode_status='size_skipped')]
        self.record = dict(source=dict(path=self.slot, sha256=self.archive_sha), entries=rows,
            dependencies=self.dependencies, reached_index=True, scan_end=5000000, index_offset=5000000)
        record = self.document('records', self.record)
        agreeing = self.document('agreeing', self.record)
        audit = self.document('audits', dict(exe=dict(sha256=self.exe_sha),
            files=[dict(path=self.slot, current=dict(sha256=self.archive_sha))]))
        encoded = b''.join(struct.pack('<III', (1 << 31) | (1 << 30), row['offset'], row['uncompressed'])
            for row in rows)
        self.encoded = self.file(self.root/'directory/encoded.bin', encoded)
        paths = dict(file_count=3, entries=[dict(path='CSV/'+name+'.csv', encoded_entry_offset=12*number)
            for number, name in enumerate(('First', 'HashOnly', 'Unknown'))])
        self.paths = self.file(self.root/'directory/paths.json', self.json(paths))
        self.directory = dict(archive_sha256=self.archive_sha, exe_sha256=self.exe_sha,
            release_manifest_sha256=audit['sha256'], authoritative_directory_for_archive=True,
            encoded_entries_file_sha256=self.encoded['sha256'], directory_paths_file_sha256=self.paths['sha256'],
            main_metadata=dict(mount='../../../ProjectRED/Content/RED/Data/', entry_count=3))
        directory = self.document('directories', self.directory)
        self.body = dict(schema=1, recipe=REFERENCE.RECIPE,
            source=dict(archive_key=self.slot, sha256=self.archive_sha, exe_sha256=self.exe_sha),
            proof=dict(directory=directory, record_index=record, agreeing_record_index=agreeing,
                encoded_entries=self.encoded, directory_paths=self.paths, release_audit=audit,
                legacy_indexer=self.old, reviewed_current_indexer_sha256=self.current_sha,
                reader=reader, oodle=oodle),
            tables=[dict(canonical_path='ProjectRED/Content/RED/Data/CSV/First.csv',
                    bytes=len(self.payload), sha256=digest(self.payload), file=str(self.payload_file),
                    state='verified_payload', header=['Id', 'Value'], rows=1),
                dict(canonical_path='ProjectRED/Content/RED/Data/CSV/HashOnly.csv', bytes=25,
                    sha256='c'*64, file=None, state='record_hash_only'),
                dict(canonical_path='ProjectRED/Content/RED/Data/CSV/Unknown.csv', bytes=3*1024*1024,
                    sha256=None, file=None, state='payload_hash_unknown')])

    def json(self, value):
        return (json.dumps(value, sort_keys=True, ensure_ascii=False)+'\n').encode()

    def file(self, path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return dict(path=str(path), sha256=digest(raw))

    def document(self, category, value):
        raw = self.json(value)
        return self.file(self.root/category/digest(raw)/'manifest.json', raw)

    def load(self, body=None, bridge=None):
        self.owner = FixtureOwner()
        pointer = self.document('references', body if body is not None else self.body)
        return REFERENCE.load_reference(self.index, self.args, self.owner, pointer,
            self.bridge if bridge is None else bridge)

    def replace_document(self, field, value):
        self.body['proof'][field] = self.document(field, value)

    def test_valid_partial_reference_is_captured_and_never_reads_old_pak_or_executes_old_script(self):
        before = copy.deepcopy(self.body)
        with patch('subprocess.run', side_effect=AssertionError('No producer execution')):
            result = self.load()
        self.assertEqual(result['validation_scope'], 'captured_evidence')
        self.assertIs(result['historical_archive_freshly_hashed'], False)
        self.assertFalse(Path(self.slot).exists())
        self.assertEqual(result['tables'], self.body['tables'])
        self.assertEqual(self.body, before)
        result['tables'][0]['header'][0] = 'Mutated result'
        self.assertEqual(self.body['tables'][0]['header'][0], 'Id')
        self.assertIn(str(self.payload_file), self.owner.inputs)

    def test_exact_pointer_shape_location_and_content_address_are_required(self):
        pointer = self.document('references', self.body)
        variants = [dict(pointer, extra=True), dict(path='relative.json', sha256=pointer['sha256']),
            dict(pointer, sha256='short'), dict(pointer, sha256='f'*64)]
        outside = self.root.parent/'outside-reference.json'
        variants.append(dict(path=str(outside), sha256='f'*64))
        for value in variants:
            with self.subTest(pointer=value), self.assertRaises(ValueError):
                REFERENCE.load_reference(self.index, self.args, FixtureOwner(), value, self.bridge)

    def test_unknown_schema_recipe_or_relative_archive_slot_is_rejected(self):
        for field, value in (('schema', True), ('schema', 2), ('recipe', 'other')):
            body = copy.deepcopy(self.body)
            body[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.load(body)
        self.body['source']['archive_key'] = 'relative.pak'
        with self.assertRaises(ValueError):
            self.load()

    def test_source_audit_and_second_record_inventory_must_agree(self):
        for field, value in (('entries', []), ('source', dict(path=self.slot, sha256='f'*64)),
                ('dependencies', {})):
            body = copy.deepcopy(self.body)
            record = copy.deepcopy(self.record)
            record[field] = value
            body['proof']['agreeing_record_index'] = self.document('changed-agreeing', record)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load(body)
        self.body['source']['sha256'] = 'f'*64
        with self.assertRaises(ValueError):
            self.load()

    def test_audit_must_contain_one_exact_archive_source_and_directory_release_digest(self):
        audit = dict(exe=dict(sha256=self.exe_sha), files=[dict(path=self.slot, current=dict(sha256='f'*64))])
        self.replace_document('release_audit', audit)
        self.directory['release_manifest_sha256'] = self.body['proof']['release_audit']['sha256']
        self.replace_document('directory', self.directory)
        with self.assertRaisesRegex(ValueError, 'release audit'):
            self.load()

    def test_artifact_digest_and_directory_metadata_are_cross_checked(self):
        self.directory['encoded_entries_file_sha256'] = 'f'*64
        self.replace_document('directory', self.directory)
        with self.assertRaisesRegex(ValueError, 'directory artifacts'):
            self.load()

    def test_legacy_bridge_and_current_producer_hash_are_explicit(self):
        with self.assertRaisesRegex(ValueError, 'not registered'):
            self.load(bridge={})
        (self.here/'index-release-archives.py').write_bytes(CURRENT_SOURCE+b'\n# changed code\n')
        with self.assertRaisesRegex(ValueError, 'current producer'):
            self.load()

    def test_registered_legacy_hash_cannot_hide_changed_decoder_ast(self):
        value = CURRENT_SOURCE.replace(b'DECODE_LIMIT = 2 * 1024 * 1024', b'DECODE_LIMIT = 3 * 1024 * 1024')
        changed = self.file(self.root/'producers/changed.py', value)
        self.body['proof']['legacy_indexer'] = changed
        record = copy.deepcopy(self.record)
        record['dependencies']['tool_sha256'] = changed['sha256']
        self.replace_document('record_index', record)
        self.replace_document('agreeing_record_index', record)
        with self.assertRaisesRegex(ValueError, 'decoder changed'):
            self.load(bridge={changed['sha256']:self.current_sha})

    def test_reader_dependency_and_payload_bytes_receive_fresh_sha_checks(self):
        path = Path(self.body['proof']['reader']['path'])
        path.write_bytes(b'# changed reader')
        with self.assertRaisesRegex(ValueError, 'SHA'):
            self.load()
        path.write_bytes(b'# Captured reader fixture\n')
        self.payload_file.write_bytes(self.payload.replace(b'fixture', b'altered'))
        with self.assertRaisesRegex(ValueError, 'SHA'):
            self.load()

    def test_encoded_prefix_must_match_the_exact_record_offset_and_fields(self):
        raw = Path(self.encoded['path']).read_bytes()
        changed = raw[:8]+struct.pack('<I', len(self.payload)+1)+raw[12:]
        self.encoded = self.file(Path(self.encoded['path']), changed)
        self.body['proof']['encoded_entries'] = self.encoded
        self.directory['encoded_entries_file_sha256'] = self.encoded['sha256']
        self.replace_document('directory', self.directory)
        with self.assertRaisesRegex(ValueError, 'prefix and record'):
            self.load()

    def test_reference_names_must_bijectively_cover_authenticated_csv_names(self):
        for change in ('missing', 'duplicate', 'renamed'):
            body = copy.deepcopy(self.body)
            if change == 'missing':
                body['tables'].pop()
            elif change == 'duplicate':
                body['tables'].append(copy.deepcopy(body['tables'][0]))
            else:
                body['tables'][0]['canonical_path'] = 'ProjectRED/Content/RED/Data/CSV/Invented.csv'
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.load(body)

    def test_table_hash_size_and_state_cannot_be_inferred_from_another_payload(self):
        for field, value in (('sha256', 'f'*64), ('bytes', 1), ('state', 'record_hash_only')):
            body = copy.deepcopy(self.body)
            body['tables'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load(body)
        self.body['tables'][2]['sha256'] = 'c'*64
        with self.assertRaisesRegex(ValueError, 'unknown record'):
            self.load()

    def test_payload_locations_and_csv_metadata_are_validated(self):
        for field, value in (('header', ['Invented', 'Value']), ('rows', 42), ('file', None)):
            body = copy.deepcopy(self.body)
            body['tables'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load(body)
        self.body['tables'][0]['file'] = str(self.root.parent/'outside.csv')
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.load()

    def test_optional_record_metadata_and_completeness_cannot_elevate_partial_evidence(self):
        for field, value in (('offset', 42), ('record_entry', 7)):
            body = copy.deepcopy(self.body)
            body['tables'][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'record metadata'):
                self.load(body)
        for field, value in (('complete', True), ('complete_payload', True),
                ('complete_names', False), ('names_complete', 1)):
            body = copy.deepcopy(self.body)
            body[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'completeness'):
                self.load(body)

    def test_non_bom_or_oversized_csv_payload_is_not_accepted(self):
        payload = b'Id,Value\n1,fixture\n'
        self.payload_file.write_bytes(payload)
        self.body['tables'][0].update(bytes=len(payload), sha256=digest(payload))
        record = copy.deepcopy(self.record)
        record['entries'][0].update(bytes=len(payload), uncompressed=len(payload), decoded_sha256=digest(payload))
        self.replace_document('record_index', record)
        self.replace_document('agreeing_record_index', record)
        raw = Path(self.encoded['path']).read_bytes()
        self.encoded = self.file(Path(self.encoded['path']), raw[:8]+struct.pack('<I', len(payload))+raw[12:])
        self.body['proof']['encoded_entries'] = self.encoded
        self.directory['encoded_entries_file_sha256'] = self.encoded['sha256']
        self.replace_document('directory', self.directory)
        with self.assertRaisesRegex(ValueError, 'BOM CSV'):
            self.load()
        with patch.object(REFERENCE, 'CSV_LIMIT', 5), self.assertRaisesRegex(ValueError, 'budget'):
            self.load()


if __name__ == '__main__':
    unittest.main()
