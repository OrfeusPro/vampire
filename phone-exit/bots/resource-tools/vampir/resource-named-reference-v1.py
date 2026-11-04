"""Exact captured named-table evidence; no historical PAK reads or code execution."""
import ast
import copy
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import threading


RECIPE = 'named-table-reference-v1'
LIMIT = 32 * 1024 * 1024
CSV_LIMIT = 16 * 1024 * 1024
SHA = re.compile('[0-9a-f]{64}')
_CSV_LOCK = csv.__dict__.setdefault('_phone_exit_resource_csv_lock_v3', threading.RLock())


def _sha(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ValueError('Named reference requires a full SHA256')
    return value


def _same_ast(before, after):
    trees = [ast.parse(raw) for raw in (before, after)]
    for name in ('discover', 'record_digest', 'compare_observed_paths', 'DECODE_LIMIT', 'NEEDLES'):
        selected = []
        for tree in trees:
            nodes = [node for node in tree.body if
                (isinstance(node, ast.FunctionDef) and node.name == name)
                or (isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                    and target.id == name for target in node.targets))]
            if len(nodes) != 1:
                raise ValueError('Named reference legacy producer definition is missing or ambiguous')
            selected.append(ast.dump(nodes[0], include_attributes=False))
        if selected[0] != selected[1]:
            raise ValueError('Named reference legacy producer decoder changed')


def load_reference(index, args, owner, pointer, legacy_bridge):
    """Validate a registered captured reference using one caller-owned SHA scope."""
    owner.check(index, args)
    root = Path(args.root).resolve()
    files = {}
    def read(item, *, manifest=False, limit=LIMIT, allowed=None):
        if (not isinstance(item, dict) or set(item) != {'path', 'sha256'}
                or not isinstance(item['path'], str) or not Path(item['path']).is_absolute()):
            raise ValueError('Named reference needs an exact absolute pointer')
        expected = _sha(item['sha256'])
        path = Path(item['path']).resolve()
        if ((allowed is not None and path != Path(allowed).resolve())
                or (allowed is None and not path.is_relative_to(root))
                or (manifest and (path.name != 'manifest.json' or path.parent.name != expected))):
            raise ValueError('Named reference input is outside its immutable library')
        with path.open('rb') as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit or owner.remember(item['path'], raw) != expected:
            raise ValueError('Named reference input SHA or byte budget differs')
        files[str(path)] = expected
        return raw
    def document(item):
        value = json.loads(read(item, manifest=True).decode('utf-8-sig'))
        if not isinstance(value, dict):
            raise ValueError('Named reference document must be an object')
        return value
    result = document(pointer)
    source = result.get('source')
    if (result.get('schema') != 1 or type(result.get('schema')) is not int
            or result.get('recipe') != RECIPE or not isinstance(source, dict)
            or not isinstance(source.get('archive_key'), str)
            or not Path(source['archive_key']).is_absolute()
            or not isinstance(result.get('tables'), list)
            or len(result['tables']) > 100000):
        raise ValueError('Unknown named table reference schema')
    archive_sha, exe_sha = _sha(source.get('sha256')), _sha(source.get('exe_sha256'))
    proof = result.get('proof')
    required = {'directory', 'record_index', 'agreeing_record_index', 'encoded_entries',
        'directory_paths', 'release_audit', 'legacy_indexer',
        'reviewed_current_indexer_sha256', 'reader', 'oodle'}
    if not isinstance(proof, dict) or set(proof) != required:
        raise ValueError('Named reference proof fields differ')
    directory = document(proof['directory'])
    record, agreeing = (document(proof[field]) for field in ('record_index', 'agreeing_record_index'))
    audit = document(proof['release_audit'])
    record_source = record.get('source') or {}
    dependencies = record.get('dependencies') or {}
    slot = Path(source['archive_key']).resolve()
    if (directory.get('archive_sha256') != archive_sha or directory.get('exe_sha256') != exe_sha
            or record_source.get('sha256') != archive_sha
            or Path(record_source.get('path', '')).resolve() != slot
            or record.get('entries') != agreeing.get('entries')
            or record.get('source') != agreeing.get('source')
            or dependencies != agreeing.get('dependencies')
            or record.get('reached_index') is not True
            or record.get('scan_end') != record.get('index_offset')
            or audit.get('exe', {}).get('sha256') != exe_sha
            or directory.get('release_manifest_sha256') != proof['release_audit']['sha256']
            or directory.get('authoritative_directory_for_archive') is not True):
        raise ValueError('Named reference source and captured proofs disagree')
    audit_rows = [row for row in audit.get('files', [])
        if Path(row.get('path', '')).resolve() == slot]
    if len(audit_rows) != 1 or (audit_rows[0].get('current') or {}).get('sha256') != archive_sha:
        raise ValueError('Named reference source is not in its exact release audit')
    if (proof['encoded_entries']['sha256'] != directory.get('encoded_entries_file_sha256')
            or proof['directory_paths']['sha256'] != directory.get('directory_paths_file_sha256')):
        raise ValueError('Named reference directory artifacts disagree with their proof')
    encoded = read(proof['encoded_entries'])
    paths = json.loads(read(proof['directory_paths']).decode('utf-8-sig'))
    metadata = directory.get('main_metadata') or {}
    if (not isinstance(paths, dict) or not isinstance(paths.get('entries'), list)
            or type(metadata.get('entry_count')) is not int
            or not 0 < metadata['entry_count'] <= 100000
            or len(paths['entries']) != metadata['entry_count']
            or paths.get('file_count') != metadata['entry_count']):
        raise ValueError('Named reference directory count differs')
    legacy_sha, current_sha = (_sha(dependencies.get('tool_sha256')),
        _sha(proof['reviewed_current_indexer_sha256']))
    if (not isinstance(legacy_bridge, dict) or legacy_bridge.get(legacy_sha) != current_sha
            or proof['legacy_indexer']['sha256'] != legacy_sha):
        raise ValueError('Named reference legacy producer is not registered')
    old_code = read(proof['legacy_indexer'])
    current_path = Path(index.HERE)/'index-release-archives.py'
    with current_path.open('rb') as stream:
        current_code = stream.read(LIMIT + 1)
    if len(current_code) > LIMIT or owner.remember(current_path, current_code) != current_sha:
        raise ValueError('Named reference reviewed current producer changed')
    _same_ast(old_code, current_code)
    for field, dependency in (('reader', 'reader_sha256'), ('oodle', 'oodle_sha256')):
        if proof[field]['sha256'] != dependencies.get(dependency):
            raise ValueError('Named reference decoder dependency differs')
        allowed = (Path(index.HERE).parent/'rfnext/scan-pak.py' if field == 'reader' else
            Path(os.environ.get('PHONEEXIT_RF_RESOURCES', 'F:/PhoneExit Resources/RF Online Next'))/'tools/oodle-data-shared.dll')
        read(proof[field], allowed=allowed)
    fmt = index.extension('resource-directory-format-v1')
    parser = index.extension('extract-release-tables')
    record_rows = record.get('entries')
    if not isinstance(record_rows, list) or len(record_rows) > 100000:
        raise ValueError('Named reference record inventory is invalid')
    by_offset = {}
    for row in record_rows:
        if (not isinstance(row, dict) or type(row.get('offset')) is not int or row['offset'] < 0
                or row['offset'] in by_offset):
            raise ValueError('Named reference record offsets are ambiguous')
        by_offset[row['offset']] = row
    expected, all_names = {}, set()
    for entry in paths['entries']:
        if not isinstance(entry, dict) or not isinstance(entry.get('path'), str):
            raise ValueError('Named reference directory entry is invalid')
        canonical = fmt.canonical_path(metadata.get('mount'), entry['path'])
        if canonical in all_names:
            raise ValueError('Named reference directory names are ambiguous')
        all_names.add(canonical)
        prefix = fmt.entry_prefix(encoded, entry.get('encoded_entry_offset'))
        row = by_offset.get(prefix['offset'])
        if row is None or any(prefix[key] != row.get(key)
                for key in ('bytes', 'uncompressed', 'method', 'encrypted')):
            raise ValueError('Named reference encoded prefix and record disagree')
        if canonical.lower().endswith('.csv'):
            expected[canonical] = row
    seen, payloads = set(), {}
    for table in result['tables']:
        if not isinstance(table, dict):
            raise ValueError('Named reference table must be an object')
        name = table.get('canonical_path')
        if not isinstance(name, str) or name in seen or name not in expected:
            raise ValueError('Named reference table names are not bijective')
        seen.add(name)
        row = expected[name]
        if type(table.get('bytes')) is not int or table['bytes'] != row['uncompressed']:
            raise ValueError('Named reference table size differs from its exact record')
        if ('offset' in table and table['offset'] != row['offset']) or (
                'record_entry' in table and table['record_entry'] != row.get('entry')):
            raise ValueError('Named reference table record metadata differs')
        sha, file, state = table.get('sha256'), table.get('file'), table.get('state')
        decoded_sha = row.get('decoded_sha256')
        if decoded_sha is None:
            if state != 'payload_hash_unknown' or sha is not None or file is not None:
                raise ValueError('Named reference unknown record cannot acquire a payload hash')
            continue
        _sha(decoded_sha)
        if sha != decoded_sha or state not in ('verified_payload', 'record_hash_only'):
            raise ValueError('Named reference table SHA differs from captured record')
        if state == 'record_hash_only':
            if file is not None:
                raise ValueError('Named reference hash-only table cannot contain a payload')
            continue
        if not isinstance(file, str):
            raise ValueError('Named reference verified payload file is missing')
        if sha not in payloads:
            raw = read(dict(path=file, sha256=sha), limit=CSV_LIMIT)
            if len(raw) != table['bytes']:
                raise ValueError('Named reference payload size differs')
            with _CSV_LOCK:
                previous_limit = csv.field_size_limit()
                try:
                    csv.field_size_limit(1024 * 1024)
                    parsed = parser.parse_csv(raw)
                finally:
                    csv.field_size_limit(previous_limit)
            if parsed is None:
                raise ValueError('Named reference payload is not supported UTF-8 BOM CSV')
            payloads[sha] = parsed
        else:
            # Each supplied location is an input, even when content hashes repeat.
            raw = read(dict(path=file, sha256=sha), limit=CSV_LIMIT)
            if len(raw) != table['bytes']:
                raise ValueError('Named reference payload size differs')
        if ('header' in table and table['header'] != payloads[sha][0]) or (
                'rows' in table and table['rows'] != payloads[sha][1]):
            raise ValueError('Named reference payload CSV metadata differs')
    if seen != set(expected):
        raise ValueError('Named reference CSV inventory is incomplete')
    complete_hashes = all(table.get('sha256') is not None for table in result['tables'])
    complete_payload = all(table.get('state') == 'verified_payload' for table in result['tables'])
    for field, actual in (('complete', complete_hashes), ('complete_payload', complete_payload),
            ('complete_names', True), ('names_complete', True)):
        if field in result and (type(result[field]) is not bool or result[field] != actual):
            raise ValueError('Named reference completeness claim differs from captured evidence')
    value = copy.deepcopy(result)
    value['validation_scope'] = 'captured_evidence'
    value['historical_archive_freshly_hashed'] = False
    value['validated_inputs'] = copy.deepcopy(files)
    return value
