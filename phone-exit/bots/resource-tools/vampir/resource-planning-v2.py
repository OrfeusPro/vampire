"""Снимок resource inputs на один проход с полным заключительным SHA-барьером.

Формат stage inputs совпадает с legacy update-run. Кэш не переносится между
проходами и не принимает изменения файлов, сделанные даже своим адаптером:
после такой смены входов нужен новый Scope. Статистика файлов не заменяет SHA.
"""
import copy
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import time


JSON_LIMIT = 32 * 1024 * 1024


class Scope:
    def __init__(self, index, args):
        self.index, self.args = index, args
        # Keep the original digest, never this Scope's memoized digest. The
        # orchestrator supplies the original index, before SourceStore wrapping.
        self._digest = index.digest
        self._root = Path(args.root)
        self._cwd = Path.cwd()
        self._aliases, self._files, self._json = {}, {}, {}
        self._stages, self._tables, self._rows = {}, {}, {}
        self._catalogue = None
        self._collectors = []
        self._config_exe_sha = None
        self.metrics = dict(digest_reads=0, digest_cache_hits=0,
            json_reads=0, json_cache_hits=0, path_resolves=0, path_cache_hits=0,
            stage_cache_hits=0, table_cache_hits=0, barrier_digest_reads=0,
            barrier_path_resolves=0, barriers=0, barrier_seconds=0.0,
            json_bytes_read=0)

    @staticmethod
    def _dependencies():
        return dict(files=set(), aliases=set())

    @contextmanager
    def _capture(self):
        dependencies = self._dependencies()
        self._collectors.append(dependencies)
        try:
            yield dependencies
        finally:
            self._collectors.pop()

    def _note(self, kind, value):
        for dependencies in self._collectors:
            dependencies[kind].add(value)

    def _reuse_dependencies(self, dependencies):
        for kind, values in dependencies.items():
            for value in values:
                self._note(kind, value)

    def _lexical(self, path):
        path = Path(path)
        if not path.is_absolute():
            if Path.cwd() != self._cwd:
                raise ValueError('Resource working directory changed during invocation')
            # Preserve lexical '..' until resolve(): normalizing it first can
            # change the meaning of a path containing a symlink/junction.
            path = self._cwd / path
        return str(path)

    def _resolve(self, path):
        lexical = self._lexical(path)
        if lexical in self._aliases:
            self.metrics['path_cache_hits'] += 1
        else:
            self._aliases[lexical] = str(Path(lexical).resolve())
            self.metrics['path_resolves'] += 1
        self._note('aliases', lexical)
        return Path(self._aliases[lexical])

    def _probe(self, path):
        canonical = self._resolve(path)
        key = str(canonical)
        if key not in self._files:
            is_file, exists = canonical.is_file(), canonical.exists()
            self._files[key] = dict(is_file=is_file, exists=exists, sha256=None)
        self._note('files', key)
        return canonical, self._files[key]

    def _sha(self, path):
        canonical, record = self._probe(path)
        if not record['is_file']:
            self.metrics['digest_cache_hits'] += 1
            return None
        if record['sha256'] is None:
            record['sha256'] = self._digest(canonical)
            self.metrics['digest_reads'] += 1
        else:
            self.metrics['digest_cache_hits'] += 1
        return record['sha256']

    def _read_json(self, path):
        canonical, record = self._probe(path)
        key = str(canonical)
        if key in self._json:
            self.metrics['json_cache_hits'] += 1
            return self._json[key]
        if not record['is_file']:
            raise ValueError('Resource JSON input is missing: ' + key)
        with canonical.open('rb') as stream:
            raw = stream.read(JSON_LIMIT + 1)
        if len(raw) > JSON_LIMIT:
            raise ValueError('Resource JSON exceeds index budget: ' + key)
        actual = hashlib.sha256(raw).hexdigest()
        if record['sha256'] is not None and record['sha256'] != actual:
            raise ValueError('Resource JSON changed while reading: ' + key)
        if record['sha256'] is None:
            self.metrics['digest_reads'] += 1
        record['sha256'] = actual
        value = json.loads(raw.decode('utf-8-sig'))
        self._json[key] = value
        self.metrics['json_reads'] += 1
        self.metrics['json_bytes_read'] += len(raw)
        return value

    def _bind_row(self, archive, dependencies):
        key = str(archive)
        merged = self._rows.setdefault(key, self._dependencies())
        for kind, values in dependencies.items():
            merged[kind].update(values)

    def _table_catalogue(self):
        if self._catalogue is None:
            with self._capture() as dependencies:
                path = self._root / 'table-study/index.json'
                _, record = self._probe(path)
                groups = {}
                rows = []
                if record['is_file']:
                    rows = self._read_json(path).get('tables', [])
                    for item in rows:
                        source = self._resolve(item.get('source', {}).get('path', ''))
                        # Keep native Path equality, including Windows casing
                        # for a missing final component (resolve preserves it).
                        groups.setdefault(source, []).append(item)
                self._catalogue = dict(path=path, exists=record['is_file'],
                    nonempty=bool(rows), groups=groups, dependencies=dependencies)
        self._reuse_dependencies(self._catalogue['dependencies'])
        return self._catalogue

    def table_baseline(self, row):
        """Return the exact legacy projection, preserving order and duplicates."""
        with self._capture() as dependencies:
            archive = self._resolve(row['path'])
            key = str(archive)
            if key in self._tables:
                self.metrics['table_cache_hits'] += 1
                value, saved = self._tables[key]
                self._reuse_dependencies(saved)
            else:
                catalogue = self._table_catalogue()
                path = catalogue['path']
                if not catalogue['exists']:
                    value = dict(path=str(path), state='missing', tables=[])
                else:
                    matching = []
                    parent = None
                    for original in catalogue['groups'].get(archive, []):
                        item = dict(original)
                        file = self._resolve(path.parent / item['file'])
                        if parent is None:
                            parent = self._resolve(path.parent)
                        if not file.is_relative_to(parent):
                            raise ValueError('Historical CSV outside table directory')
                        item['file'] = str(file)
                        matching.append(item)
                    value = dict(path=str(path), state='foreign_only'
                        if catalogue['nonempty'] and not matching else 'selected', tables=matching)
                self._tables[key] = (value, dependencies)
        self._bind_row(archive, dependencies)
        return copy.deepcopy(value)

    def stage_inputs(self, row, tools, *, source_sha=None, audit_sha=None):
        """Build byte-for-byte equivalent legacy resource_stage_inputs data."""
        cache_key = json.dumps(dict(row=row, tools=tools, source_sha=source_sha,
            audit_sha=audit_sha), sort_keys=True, separators=(',', ':'), allow_nan=False)
        with self._capture() as dependencies:
            archive = self._resolve(row['path'])
            if cache_key in self._stages:
                self.metrics['stage_cache_hits'] += 1
                value, saved = self._stages[cache_key]
                self._reuse_dependencies(saved)
            else:
                def material(item):
                    if item is None:
                        return None
                    return {key: item.get(key) for key in ('sha256', 'size', 'pak_version')}

                entries = self._root / 'pak-extracted' / Path(row['path']).stem / 'entries.json'
                historical = [entries]
                cached = row.get('cached_index') or {}
                if cached.get('path'):
                    historical.append(Path(cached['path']))
                _, entries_record = self._probe(entries)
                if entries_record['is_file']:
                    parent = self._resolve(entries.parent)
                    for item in self._read_json(entries):
                        if item.get('saved'):
                            path = self._resolve(item['saved'])
                            if not path.is_relative_to(parent):
                                raise ValueError('Historical blob outside extraction directory')
                            historical.append(path)
                tables = self.table_baseline(row)
                historical.extend(Path(item['file']) for item in tables['tables'])
                config = Path(row['path']).name in ('ProjectRED-Windows.pak', 'pakchunk0-Windows.pak')
                if config:
                    if self._config_exe_sha is None:
                        self._config_exe_sha = self.index.extension('recover-pak-game-config').EXE_SHA256
                    historical.extend([
                        self._root / 'resource-config-snapshots/393c0697115ec6beceeb0e822bed0f6907eab83dfe9a47f81e9c7875deff35db/manifest.json',
                        self._root / 'client-code-snapshots' / self._config_exe_sha / 'ProjectRED-Win64-Shipping.exe'])
                hashes = {}
                for path in historical:
                    canonical = self._resolve(path)
                    hashes[str(canonical)] = self._sha(canonical)
                value = dict(archive=str(archive), current=material(row.get('current')),
                    baseline=material(row.get('baseline')), cached_index=cached,
                    table_baseline=tables, historical=hashes, tools=tools)
                if config:
                    value['config_source_sha256'] = source_sha
                if any(item is not None and not re.fullmatch('[0-9a-f]{64}', str(item.get('sha256', '')))
                        for item in (row.get('current'), row.get('baseline'))):
                    value['incomplete_material_audit_sha256'] = audit_sha
                # Never retain caller-owned row/tools dictionaries in a memo.
                value = copy.deepcopy(value)
                self._stages[cache_key] = (value, dependencies)
        self._bind_row(archive, dependencies)
        return copy.deepcopy(value)

    def validate(self, row=None):
        """Fresh SHA of all consumed files, or only one prepared archive's set.

        Alias paths are re-resolved before and after reading bytes. An unchanged
        size/mtime or identical bytes at a substituted target never authorizes
        a changed path. Missing inputs are part of the barrier as well.
        """
        started = time.perf_counter()
        if row is None:
            dependencies = dict(files=set(self._files), aliases=set(self._aliases))
        else:
            lexical = self._lexical(row['path'])
            canonical = self._aliases.get(lexical)
            if canonical is None or canonical not in self._rows:
                raise ValueError('Resource row was not prepared in this Scope')
            dependencies = self._rows[canonical]

        def aliases():
            for lexical in sorted(dependencies['aliases']):
                self.metrics['barrier_path_resolves'] += 1
                if str(Path(lexical).resolve()) != self._aliases[lexical]:
                    raise ValueError('Resource path alias changed before final barrier: ' + lexical)

        try:
            aliases()
            for filename in sorted(dependencies['files']):
                path = Path(filename)
                expected = self._files[filename]
                if (path.is_file(), path.exists()) != (expected['is_file'], expected['exists']):
                    raise ValueError('Resource input appeared or disappeared before final barrier: ' + filename)
                if expected['is_file']:
                    self.metrics['barrier_digest_reads'] += 1
                    actual = self._digest(path)
                    if expected['sha256'] is None or actual != expected['sha256']:
                        raise ValueError('Resource input SHA changed before final barrier: ' + filename)
                    if not path.is_file():
                        raise ValueError('Resource input disappeared during final barrier: ' + filename)
            aliases()
            self.metrics['barriers'] += 1
        finally:
            self.metrics['barrier_seconds'] += round(time.perf_counter() - started, 6)
        return copy.deepcopy(self.metrics)
