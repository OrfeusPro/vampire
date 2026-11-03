"""Общий SHA-барьер владельца для выбранных batch-материалов обновления.

retain() сохраняет только provisional declaration уже прочитанного Scope. Это
не самостоятельный допуск: новые квитанции / next-use pointers разрешены лишь
после finish(), перечитывающего всю использованную closure и SourceStore.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import time
import uuid


RECIPE = 'update-owner-scope-v3'
SHA = re.compile('[0-9a-f]{64}')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode('utf-8')


class Owner:
    def __init__(self, index, args, source_store):
        self.index, self.args, self.source_store = index, args, source_store
        self.root, self.knowledge = Path(args.root).resolve(), Path(args.knowledge).resolve()
        self._digest = index.digest
        if not callable(self._digest) or getattr(self._digest, '__self__', None) is source_store:
            raise ValueError('Owner requires the original uncached digest')
        self.owner_id = uuid.uuid4().hex
        self._state = 'open'
        self._files, self._aliases, self._sources, self._scopes = {}, {}, {}, []
        self.metrics = dict(retained_scopes=0, retained_input_occurrences=0,
            unique_files=0, source_barriers=0, barrier_digest_reads=0,
            barrier_bytes=0, barrier_seconds=0.0)
        self._check_ownership()
        self._sources = {sha: self._source_path(sha) for sha in source_store._sources}
        helper = Path(__file__).resolve()
        self.helper_guard = {str(helper): self._full_sha(self._digest(helper))}
        self._files[helper] = dict(sha256=self.helper_guard[str(helper)], kinds={'tool'})
        self._aliases[str(helper)] = helper
        self.metrics['unique_files'] = 1

    @property
    def closed(self):
        return self._state != 'open'

    @property
    def finished(self):
        return self._state == 'validated'

    @staticmethod
    def _full_sha(value):
        if not isinstance(value, str) or not SHA.fullmatch(value):
            raise ValueError('Owner requires a full SHA256')
        return value

    def _check_ownership(self):
        if (Path(self.args.root).resolve() != self.root
                or Path(self.args.knowledge).resolve() != self.knowledge
                or Path(self.source_store.root).resolve() != self.root
                or getattr(self.args, 'source_store', self.source_store) is not self.source_store):
            raise ValueError('Owner root, knowledge or SourceStore identity changed')
        if not isinstance(getattr(self.source_store, '_sources', None), dict):
            raise ValueError('Owner requires an explicit frozen SourceStore')

    def _source_path(self, sha):
        sha = self._full_sha(sha)
        prefix = self.root / 'client-code-snapshots'
        expected = prefix / sha / 'ProjectRED-Win64-Shipping.exe'
        actual = expected.resolve()
        if not actual.is_relative_to(prefix):
            raise ValueError('Owner source escapes the source snapshot prefix')
        return actual

    def _ensure_open(self):
        if self.closed:
            raise ValueError('Owner is closed; a fresh invocation is required')
        self._check_ownership()

    def _current_sources(self):
        if not set(self._sources).issubset(self.source_store._sources):
            raise ValueError('Owner retained source disappeared from SourceStore')
        sources = {sha: self._source_path(sha) for sha in self.source_store._sources}
        if any(sources[sha] != path for sha, path in self._sources.items()):
            raise ValueError('Owner source path alias changed before publication')
        return sources

    def retain(self, scope):
        """Keep verified initial bytes, without earning a completed admission."""
        self._ensure_open()
        if (scope.source_store is not self.source_store
                or Path(scope.root).resolve() != self.root
                or Path(scope.knowledge).resolve() != self.knowledge):
            raise ValueError('Scope belongs to another Owner root or SourceStore')
        source = self._source_path(scope.source_sha256)
        if Path(scope.source_path).resolve() != source:
            raise ValueError('Scope source path differs from its exact SHA snapshot')
        if scope.source_sha256 not in self.source_store._sources:
            raise ValueError('Scope source has not entered its frozen SourceStore')

        # Validate the declaration in memory first. A conflicting batch cannot
        # partly extend the owner's union or change previously returned copies.
        files, aliases = {}, {}
        for filename, row in scope._files.items():
            lexical = str(Path(filename).absolute())
            path = Path(filename).resolve()
            expected = self._full_sha(row.get('sha256'))
            raw, kind = row.get('raw'), row.get('kind')
            if (not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != expected
                    or not isinstance(kind, str) or not kind):
                raise ValueError('Scope retained bytes or input kind differ')
            if path in self._files and self._files[path]['sha256'] != expected:
                raise ValueError('Conflicting SHA between Owner batches: ' + str(path))
            if path in files and files[path]['sha256'] != expected:
                raise ValueError('Conflicting SHA inside one Owner batch: ' + str(path))
            if lexical in self._aliases and self._aliases[lexical] != path:
                raise ValueError('Owner input path alias changed between batches')
            files[path] = dict(sha256=expected, kind=kind)
            aliases[lexical] = path

        sources = self._current_sources()
        inputs = {str(path): row['sha256'] for path, row in files.items()}
        inputs.update({str(path): sha for sha, path in sources.items()})
        declaration = dict(schema=3, recipe=RECIPE, state='provisional',
            owner_id=self.owner_id, pending_owner=True, admission_completed=False,
            source_barrier_completed=False, file_barrier_completed=False,
            source_sha256=scope.source_sha256, source=str(source),
            ordered_addresses=list(scope.addresses), question_id=scope.question_id,
            selected_context=copy.deepcopy(scope.context),
            selected_functions=copy.deepcopy(scope.functions),
            runtime=copy.deepcopy(scope.runtime), helper_guard=dict(self.helper_guard),
            inputs=inputs, consumed_materials=[dict(path=str(path), **row)
                for path, row in sorted(files.items(), key=lambda item: str(item[0]))]
                + [dict(path=str(path), sha256=sha, kind='source')
                    for sha, path in sorted(sources.items())],
            validation_scope='selected_materials_only', global_history_verified=False,
            metrics=dict(scope.metrics, source_store=dict(self.source_store.metrics)))
        for path, row in files.items():
            record = self._files.setdefault(path, dict(sha256=row['sha256'], kinds=set()))
            record['kinds'].add(row['kind'])
        self._aliases.update(aliases)
        self._sources.update(sources)
        # The caller keeps the provisional body. The owner only needs the
        # compact selected closure; do not keep another copy of pseudocode.
        self._scopes.append(dict(source_sha256=scope.source_sha256,
            ordered_addresses=list(scope.addresses), inputs=dict(inputs)))
        self.metrics['retained_scopes'] += 1
        self.metrics['retained_input_occurrences'] += len(files)
        self.metrics['unique_files'] = len(self._files)
        return copy.deepcopy(declaration)

    def _check_aliases(self):
        for lexical, expected in self._aliases.items():
            if Path(lexical).resolve() != expected:
                raise ValueError('Owner input path alias changed before publication')

    def finish(self):
        """Fresh bytes of the union, including sources added after retain()."""
        self._ensure_open()
        self._state = 'validating'
        started = time.perf_counter()
        try:
            self._check_aliases()
            # Capture object references as well as all late source identities.
            # A concurrent addition/replacement cannot evade this final barrier.
            frozen_sources = dict(self.source_store._sources)
            sources = self._current_sources()
            source_metrics = self.source_store.validate()
            self.metrics['source_barriers'] += 1
            if (set(self.source_store._sources) != set(frozen_sources)
                    or any(self.source_store._sources[sha] is not raw
                        for sha, raw in frozen_sources.items())):
                raise ValueError('Owner source set changed during its final barrier')
            if self._current_sources() != sources:
                raise ValueError('Owner source paths changed during its final barrier')
            for path, row in self._files.items():
                actual = self._digest(path)
                self.metrics['barrier_digest_reads'] += 1
                if actual != row['sha256']:
                    raise ValueError('Owner input SHA changed before publication: ' + str(path))
                self.metrics['barrier_bytes'] += path.stat().st_size
            self._check_ownership()
            self._check_aliases()
            if self._current_sources() != sources:
                raise ValueError('Owner source paths changed before publication')
            self.metrics['barrier_seconds'] += round(time.perf_counter() - started, 6)
            inputs = {str(path): row['sha256'] for path, row in self._files.items()}
            inputs.update({str(path): sha for sha, path in sources.items()})
            admission = dict(schema=3, recipe=RECIPE, state='validated',
                owner_id=self.owner_id, pending_owner=False, admission_completed=True,
                source_barrier_completed=True, file_barrier_completed=True,
                helper_guard=dict(self.helper_guard), inputs=inputs,
                consumed_materials=[dict(path=str(path), sha256=row['sha256'],
                    kinds=sorted(row['kinds'])) for path, row in
                    sorted(self._files.items(), key=lambda item: str(item[0]))]
                    + [dict(path=str(path), sha256=sha, kinds=['source'])
                        for sha, path in sorted(sources.items())],
                source_identities=sorted(sources), scopes=len(self._scopes),
                validation_scope='selected_materials_only', global_history_verified=False,
                coverage=dict(selected_source_addresses_only=True, global_history_checked=False,
                    role_transfer=False, client_semantics_proven=False, online_admission=False))
            result = dict(**admission,
                validation_sha256=hashlib.sha256(canonical(admission)).hexdigest(),
                metrics=copy.deepcopy(self.metrics), source_store=source_metrics)
            self._state = 'validated'
            return result
        except BaseException:
            self._state = 'failed'
            self.metrics['barrier_seconds'] += round(time.perf_counter() - started, 6)
            raise
