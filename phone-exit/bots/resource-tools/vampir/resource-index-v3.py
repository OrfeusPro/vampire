"""Выбранный SHA-bound record index без чтения исторических saved blobs.

Discovery summaries — только подсказки. Допуск относится к ограниченному
record discovery прежнего decoder, а не к directory names или совместимости.
Владелец обязан вызвать finish() перед публикацией результата прохода.
"""
import copy
import hashlib
import json
import os
from collections import Counter
from pathlib import Path
import re
import time

JSON_LIMIT = 32 * 1024 * 1024
MAX_SUMMARIES = 4096
MAX_ENTRIES = 1_000_000
SHA = re.compile('[0-9a-f]{64}')
DEPENDENCIES = {'tool_sha256', 'reader_sha256', 'oodle_sha256'}


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode('utf-8')


def _sha(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ValueError('Resource index requires a full SHA256')
    return value


def _state(index, args):
    current = getattr(args, '_resource_index_v3_state', None)
    if current is None:
        current = _State(index, args)
        args._resource_index_v3_state = current
    current.ownership(index, args)
    return current


def find(index, args, audit_manifest, row, resource_tools):
    return _state(index, args).find(audit_manifest, row, resource_tools)


def build(index, update, workflow, args, audit_manifest, row):
    state = _state(index, args)
    existing = state.find(audit_manifest, row, state.resource_tools or {})
    if existing is not None:
        return existing
    state.metrics['index_adapter_calls'] += 1
    result = update.execute_adapter(index, args, 'index-release-archives.py',
        [audit_manifest, '--archive-sha256', row['current']['sha256']])
    if result.get('state') != 'passed':
        raise ValueError('Resource record indexing failed: ' + str(result.get('reason') or result.get('state')))
    state.inventory(allow_new=True)
    state.found.clear()
    approved = state.find(audit_manifest, row, state.resource_tools or {})
    if approved is None:
        raise ValueError('No approved resource record after the index adapter')
    return approved


def finish(index, args):
    return _state(index, args).finish()


def metrics(index, args):
    return copy.deepcopy(_state(index, args).metrics)


class _State:
    def __init__(self, index, args):
        self.index, self.args = index, args
        self.root = Path(args.root).resolve()
        store = getattr(args, 'source_store', None)
        self.original = store.index if store is not None else index
        self.digest = self.original.digest
        if getattr(self.digest, '__self__', None) is store and store is not None:
            raise ValueError('Resource index needs an original uncached digest')
        self.store = store
        self.closed = False
        self.files, self.aliases, self.documents, self.sources = {}, {}, {}, {}
        self.inventory_files, self.hints, self.found = None, {}, {}
        self.audit_pointer, self.resource_tools = None, None
        self.dependencies, self.decode_limit = None, None
        self.metrics = dict(find_calls=0, discovery_scans=0, discovery_json_reads=0,
            discovery_invalid_hints=0, discovery_seconds=0.0, validation_seconds=0.0,
            source_sha_reads=0, source_cache_hits=0, report_cache_hits=0,
            selected_records=0, index_adapter_calls=0, file_sha_reads=0,
            file_sha_cache_hits=0, barrier_sha_reads=0, barrier_seconds=0.0)
        self.pin(Path(__file__), kind='tool')

    def ownership(self, index, args):
        if self.closed:
            raise ValueError('Resource index scope is closed; start a fresh invocation')
        if (Path(args.root).resolve() != self.root or args is not self.args
                or getattr(args, 'source_store', None) is not self.store):
            raise ValueError('Resource index owner or root changed')

    def resolve(self, filename):
        if not isinstance(filename,(str,os.PathLike)):
            raise ValueError('Resource index path is not an explicit filesystem path')
        lexical = str(Path(filename).absolute())
        if lexical in self.aliases:
            return self.aliases[lexical]
        path = Path(filename).resolve()
        self.aliases[lexical] = path
        return path

    def allowed(self, filename):
        path = self.resolve(filename)
        roots = (self.root/'knowledge/update-audits', self.root/'release-snapshots')
        if not any(path.is_relative_to(root) for root in roots):
            raise ValueError('Resource record metadata is outside the public audit namespaces')
        return path

    def pin(self, filename, expected=None, *, kind='input'):
        path = self.resolve(filename)
        if expected is not None:
            _sha(expected)
        if path in self.files:
            actual = self.files[path]
            self.metrics['file_sha_cache_hits'] += 1
        else:
            actual = self.digest(path)
            self.files[path] = actual
            self.metrics['file_sha_reads'] += 1
        if expected is not None and actual != expected:
            raise ValueError('Resource index ' + kind + ' SHA differs: ' + str(path))
        return actual

    def json(self, filename, expected=None):
        path = self.resolve(filename)
        if path in self.documents:
            if expected is not None and self.files[path] != expected:
                raise ValueError('Resource index JSON expected SHA conflicts')
            self.metrics['report_cache_hits'] += 1
            return self.documents[path]
        with path.open('rb') as stream:
            raw = stream.read(JSON_LIMIT + 1)
        if len(raw) > JSON_LIMIT:
            raise ValueError('Resource record JSON exceeds the 32 MiB budget')
        actual = hashlib.sha256(raw).hexdigest()
        if expected is not None and actual != _sha(expected):
            raise ValueError('Resource index selected JSON SHA differs: ' + str(path))
        if path in self.files and self.files[path] != actual:
            raise ValueError('Resource index JSON changed while reading')
        self.files[path] = actual
        value = json.loads(raw.decode('utf-8-sig'))
        self.documents[path] = value
        self.metrics['file_sha_reads'] += 1
        return value

    def checked(self, filename, expected=None):
        path = self.allowed(filename)
        if path.name != 'manifest.json' or not SHA.fullmatch(path.parent.name):
            raise ValueError('Resource index manifest is not content-addressed')
        if expected is not None and expected != path.parent.name:
            raise ValueError('Resource record pointer SHA differs from its address')
        return self.json(path, expected or path.parent.name)

    def decoder(self):
        if self.dependencies is None:
            here = Path(self.index.HERE).resolve()
            indexer = here/'index-release-archives.py'
            reader = here.parent/'rfnext/scan-pak.py'
            oodle = Path(os.environ.get('PHONEEXIT_RF_RESOURCES',
                'F:/PhoneExit Resources/RF Online Next'))/'tools/oodle-data-shared.dll'
            self.dependencies = dict(tool_sha256=self.pin(indexer, kind='indexer'),
                reader_sha256=self.pin(reader, kind='reader'), oodle_sha256=self.pin(oodle, kind='Oodle'))
            self.decode_limit = self.index.extension('index-release-archives').DECODE_LIMIT
            if type(self.decode_limit) is not int or not 0 < self.decode_limit <= 64*1024*1024:
                raise ValueError('Unsupported record decoder byte budget')
        return self.dependencies

    def summary_paths(self):
        paths = set((self.root/'knowledge/update-audits').glob('*/index-summaries/*/manifest.json'))
        paths.update((self.root/'release-snapshots').glob('*/index-summaries/*/manifest.json'))
        if len(paths) > MAX_SUMMARIES:
            raise ValueError('Resource summary discovery budget exceeded')
        return sorted(paths)

    def inventory(self, *, allow_new=False):
        started = time.perf_counter()
        paths = self.summary_paths()
        canonical = {self.allowed(path) for path in paths}
        if self.inventory_files is not None:
            if (not allow_new and canonical != set(self.inventory_files)) or not set(self.inventory_files).issubset(canonical):
                raise ValueError('Resource summary inventory changed during the invocation')
        found = dict(self.inventory_files or {})
        for filename in paths:
            path = self.allowed(filename)
            if path in found:
                continue  # Existing immutable hints retain their original guard until finish().
            with path.open('rb') as stream:
                raw = stream.read(JSON_LIMIT + 1)
            if len(raw) > JSON_LIMIT:
                raise ValueError('Resource summary exceeds discovery budget')
            actual = hashlib.sha256(raw).hexdigest()
            found[path] = actual
            try:
                value = json.loads(raw.decode('utf-8-sig'))
                requested = value.get('selected_archive_sha256')
                archives = value.get('archives')
                if not isinstance(archives, list):raise ValueError('Bad discovery list')
                if requested is not None and not SHA.fullmatch(str(requested)):
                    raise ValueError('Bad discovery digest')
                for row in archives:
                    if not isinstance(row, dict) or not isinstance(row.get('archive'), str):
                        raise ValueError('Bad discovery archive')
                    self.hints.setdefault((requested, row['archive']), []).append((path, copy.deepcopy(row)))
            except (ValueError, TypeError, AttributeError):
                self.metrics['discovery_invalid_hints'] += 1
            self.metrics['discovery_json_reads'] += 1
        self.inventory_files = found
        self.metrics['discovery_scans'] += 1
        self.metrics['discovery_seconds'] += round(time.perf_counter()-started, 6)

    def audit(self, filename, row):
        path = self.allowed(filename)
        value = self.checked(path)
        pointer = (str(path), self.files[path])
        if self.audit_pointer is not None and self.audit_pointer != pointer:
            raise ValueError('Resource index invocation mixed different current audits')
        self.audit_pointer = pointer
        if value.get('full_archive_coverage') is not True or not isinstance(value.get('files'), list):
            raise ValueError('Resource index requires a complete full-SHA current audit')
        if not isinstance(value.get('source'),str) or not Path(value['source']).is_absolute():
            raise ValueError('Resource audit requires an absolute installation source')
        archive = self.resolve(row['path'])
        if not archive.is_relative_to(self.resolve(value.get('source', ''))):
            raise ValueError('Resource archive is outside its audited installation')
        matching = [item for item in value['files'] if self.resolve(item['path']) == archive]
        if len(matching) != 1:
            raise ValueError('Missing or ambiguous archive in the current full audit')
        material = lambda current: None if current is None else {
            key:current.get(key) for key in ('sha256', 'size', 'pak_version')}
        current = row.get('current')
        if material(matching[0].get('current')) != material(current) or current is None:
            raise ValueError('Caller archive differs from its checked current audit')
        _sha(current.get('sha256'))
        if (current.get('pak_version') != 11 or type(current.get('size')) is not int
                or current['size'] <= 0):
            raise ValueError('Unsupported archive identity or format')
        if archive not in self.sources:
            if self.pin(archive, current['sha256'], kind='installed archive') != current['sha256']:
                raise ValueError('Current archive SHA differs')
            if archive.stat().st_size != current['size']:
                raise ValueError('Current archive size differs from its full audit')
            self.sources[archive] = current['sha256']
            self.metrics['source_sha_reads'] += 1
        else:
            if self.sources[archive] != current['sha256']:
                raise ValueError('Resource source changed between selected archives')
            self.metrics['source_cache_hits'] += 1
        return archive, current

    def record_shape(self, report, summary_row, size):
        if (report.get('schema') != 1 or report.get('directory_index_parsed') is not False
                or report.get('decode_limit') != self.decode_limit):
            raise ValueError('Resource record decoder schema or byte budget differs')
        entries = report.get('entries')
        if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
            raise ValueError('Resource record entry budget differs')
        limit, scan = report.get('index_offset'), report.get('scan_end')
        if (type(limit) is not int or not 0 < limit <= size or type(scan) is not int
                or not 0 <= scan <= limit or type(report.get('reached_index')) is not bool
                or report['reached_index'] != (scan == limit)):
            raise ValueError('Resource record scan bounds differ')
        previous_end, observed_gaps = 0, []
        for number, entry in enumerate(entries):
            if not isinstance(entry, dict) or type(entry.get('entry')) is not int or entry['entry'] != number:
                raise ValueError('Resource record ordinal differs')
            for name in ('offset', 'end', 'bytes', 'uncompressed'):
                if type(entry.get(name)) is not int:raise ValueError('Resource record bounds are not integers')
            if not previous_end <= entry['offset'] < entry['end'] <= limit or min(entry['bytes'], entry['uncompressed']) <= 0:
                raise ValueError('Resource record overlaps or escapes its index boundary')
            if entry['offset'] != previous_end:
                observed_gaps.append(dict(start=previous_end,end=entry['offset']))
            previous_end = entry['end']
            _sha(entry.get('stored_record_sha256'))
            if type(entry.get('method')) is not int or entry['method'] not in (0,1):
                raise ValueError('Resource record compression method differs')
            status = entry.get('decode_status')
            if type(entry.get('encrypted')) is not bool or status not in ('decoded','encrypted_skipped','size_skipped','error'):
                raise ValueError('Resource record decode status differs')
            if status == 'encrypted_skipped' and not entry['encrypted']:
                raise ValueError('Resource encrypted skip lacks an encrypted record')
            if status != 'encrypted_skipped' and entry['encrypted']:
                raise ValueError('Resource encrypted record was decoded')
            oversized = max(entry['bytes'],entry['uncompressed']) > self.decode_limit
            if status == 'size_skipped' and not oversized:
                raise ValueError('Resource size skip differs from the decoder budget')
            if status in ('decoded','error') and oversized:
                raise ValueError('Resource decoded entry exceeds the reviewed budget')
            if status == 'decoded':_sha(entry.get('decoded_sha256'))
            if status == 'error' and not isinstance(entry.get('error_type'),str):
                raise ValueError('Resource decode error lacks its explicit type')
        if entries and scan != previous_end:
            raise ValueError('Resource scan end differs from the last record')
        counts = dict(Counter(entry['decode_status'] for entry in entries))
        if (not isinstance(report.get('decode_counts'),dict)
                or any(type(value) is not int or value < 0 for value in report['decode_counts'].values())
                or report['decode_counts'] != counts):
            raise ValueError('Resource record decode counts differ')
        gaps = report.get('gaps')
        if not isinstance(gaps,list) or any(not isinstance(g,dict)
                or type(g.get('start')) is not int or type(g.get('end')) is not int
                or not 0 <= g['start'] < g['end'] <= limit for g in gaps):
            raise ValueError('Resource gap bounds differ')
        if gaps != observed_gaps:
            raise ValueError('Resource record gaps disagree with the ordered headers')
        if (type(summary_row.get('entries')) is not int or summary_row['entries'] != len(entries)
                or type(summary_row.get('reached_index')) is not bool or summary_row['reached_index'] != report['reached_index']
                or summary_row.get('decode_counts') != counts or type(summary_row.get('gaps')) is not int
                or summary_row['gaps'] != len(gaps)):
            raise ValueError('Resource summary disagrees with its selected record')

    def candidate(self, summary_path, hint, archive, current):
        summary = self.checked(summary_path)
        if (summary.get('schema') != 1 or not isinstance(summary.get('archives'),list)
                or summary.get('selected_archive_sha256') not in (None,current['sha256'])):
            raise ValueError('Selected resource summary provenance differs')
        if hint not in summary['archives']:
            raise ValueError('Resource discovery hint is not in the checked summary')
        expected = _sha(hint.get('sha256'))
        record_path = self.allowed(hint.get('report'))
        report = self.checked(record_path, expected)
        source = report.get('source')
        if not isinstance(source,dict):raise ValueError('Resource record lacks its source')
        if not isinstance(source.get('path'),str) or not Path(source['path']).is_absolute():
            raise ValueError('Resource record source path is not absolute')
        if source.get('sha256') != current['sha256']:
            if summary.get('selected_archive_sha256') is None:return None
            raise ValueError('Selected resource record has another source SHA')
        source_path = self.resolve(source.get('path',''))
        if (source.get('size') != current['size'] or source.get('pak_version') != 11):
            raise ValueError('Resource record belongs to another installed archive')
        release = _sha(summary.get('release_manifest_sha256'))
        if report.get('release_manifest_sha256') != release:
            raise ValueError('Resource record and summary refer to different source audits')
        old_audit_path = summary_path.parent.parent.parent/'manifest.json'
        if old_audit_path.parent.name != release:
            raise ValueError('Resource summary source audit path differs')
        old_audit = self.checked(old_audit_path, release)
        source_rows = [item for item in old_audit.get('files',[]) if
            self.resolve(item.get('path','')) == source_path and
            {key:(item.get('current') or {}).get(key) for key in ('sha256','size','pak_version')} ==
            {key:source.get(key) for key in ('sha256','size','pak_version')}]
        if len(source_rows) != 1:
            raise ValueError('Resource record source is not bound to its historical full SHA')
        if source_path != archive:
            # Another installation can legitimately contain the same bytes.
            # It cannot supply this installation's record pointer; a fresh
            # build must remain possible instead of treating it as corruption.
            return None
        if report.get('dependencies') != summary.get('dependencies') or set(report.get('dependencies') or {}) != DEPENDENCIES:
            raise ValueError('Resource summary decoder dependencies disagree')
        if report['dependencies'] != self.decoder():
            return None  # A changed decoder requires a new extraction, never a silent old admission.
        self.record_shape(report, hint, current['size'])
        for key, name in (('directory_paths_file_sha256','directory.json'),('encoded_entries_file_sha256','encoded-entries.bin')):
            if key in report:
                self.pin(record_path.parent/name, _sha(report[key]), kind='declared output')
        projection = copy.deepcopy(report)
        projection.pop('release_manifest_sha256',None)
        projection.pop('observed_path_comparison',None)
        projection['source'] = {key:source.get(key) for key in ('path','sha256','size','pak_version')}
        projection['source']['path'] = str(archive)
        return dict(path=str(record_path),sha256=expected), _canonical(projection)

    def find(self, audit_manifest, row, resource_tools):
        started = time.perf_counter()
        self.metrics['find_calls'] += 1
        if self.resource_tools is None:self.resource_tools=copy.deepcopy(resource_tools)
        elif self.resource_tools != resource_tools:raise ValueError('Resource tool declarations changed during invocation')
        archive,current = self.audit(audit_manifest,row)
        self.decoder()
        key = (archive,current['sha256'])
        if key in self.found:
            self.metrics['report_cache_hits'] += 1
            return copy.deepcopy(self.found[key])
        if self.inventory_files is None:self.inventory()
        candidates = [*self.hints.get((current['sha256'],archive.name),[]),
            *self.hints.get((None,archive.name),[])]
        results = {}
        for summary,hint in candidates:
            approved = self.candidate(summary,hint,archive,current)
            if approved is not None:
                pointer,projection=approved
                results.setdefault(projection,[]).append(pointer)
        if len(results)>1:raise ValueError('Ambiguous resource record indexes for the same source and decoder')
        result = None if not results else min(next(iter(results.values())),key=lambda item:item['path'])
        self.found[key]=copy.deepcopy(result)
        self.metrics['selected_records'] += int(result is not None)
        self.metrics['validation_seconds'] += round(time.perf_counter()-started,6)
        return copy.deepcopy(result)

    def finish(self):
        started=time.perf_counter()
        try:
            if self.inventory_files is not None:
                if {self.allowed(path) for path in self.summary_paths()} != set(self.inventory_files):
                    raise ValueError('Resource discovery summary inventory changed before final barrier')
                for path,expected in self.inventory_files.items():
                    if self.digest(path)!=expected:raise ValueError('Resource discovery summary changed before final barrier')
                    self.metrics['barrier_sha_reads'] += 1
            for lexical,path in self.aliases.items():
                if Path(lexical).resolve()!=path:raise ValueError('Resource index path alias changed before final barrier')
            for path,expected in self.files.items():
                if self.digest(path)!=expected:raise ValueError('Resource record input SHA changed before final barrier: '+str(path))
                self.metrics['barrier_sha_reads'] += 1
            for lexical,path in self.aliases.items():
                if Path(lexical).resolve()!=path:raise ValueError('Resource index alias changed during final barrier')
            self.metrics['barrier_seconds'] += round(time.perf_counter()-started,6)
            return dict(validation_scope='bounded_source_record_indexes_only',compatibility='not_established',
                directory_identity_proven=False,source_barrier_completed=True,
                inputs={str(path):sha for path,sha in self.files.items()},metrics=copy.deepcopy(self.metrics))
        finally:
            self.closed=True
