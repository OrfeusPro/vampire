"""Явный immutable reference старых blobs для сравнения content hashes.

Импорт фиксирует фактические bytes legacy-файлов в момент импорта. Исходная
версия клиента и ресурсная идентичность неизвестны; совместимость не заявляется.
Рабочий reference не обновляется при изменении старых mutable файлов скрытно.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
RECIPE = 'resource-reference-v3'
CATEGORY = 'resource-reference-v3-snapshots'
CHECKPOINT_CATEGORY = 'resource-reference-v3-checkpoints'
ACTIVATION_CATEGORY = 'resource-reference-v3-activations'
SHA = re.compile('[0-9a-f]{64}')
JSON_LIMIT = 256 * 1024 * 1024
METADATA_LIMIT = 32 * 1024 * 1024
CHECKPOINT_INTERVAL = 256
MAX_ARCHIVES = 4096
MAX_BLOBS = 2_000_000


class ReferenceInterrupted(InterruptedError):
    """Импорт остановлен; активный reference не назначен."""


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
        allow_nan=False) + '\n').encode('utf-8')


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _sha(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ValueError('Reference requires a full SHA256')
    return value


def _digest(index):
    value = index.digest
    owner = getattr(value, '__self__', None)
    if not callable(value) or (owner is not None and hasattr(owner, '_sources')):
        raise ValueError('Reference requires the original uncached digest')
    return value


def _tools(index):
    paths = {HERE/name for name in ('resource-reference-v3.py',
        'knowledge-index.py', 'research-workflow.py')}
    paths.add(Path(sys.executable).resolve())
    for name in ('_hashlib', '_json', '_struct'):
        filename = getattr(sys.modules.get(name), '__file__', None)
        if filename and Path(filename).is_file():
            paths.add(Path(filename).resolve())
    for directory in (Path(sys.base_prefix), Path(sys.base_prefix)/'DLLs'):
        for name in (f'python{sys.version_info.major}{sys.version_info.minor}.dll', 'python3.dll'):
            path = directory/name
            if path.is_file():
                paths.add(path.resolve())
    digest = _digest(index)
    return dict(files={str(path.resolve()): _sha(digest(path)) for path in sorted(paths)},
        runtime=dict(python=sys.version, implementation=sys.implementation.name))


def _guard_shape(value):
    """Validate historical provenance without re-executing its old tooling."""
    if (not isinstance(value, dict) or set(value) != {'files', 'runtime'}
            or not isinstance(value['files'], dict) or not value['files']
            or not isinstance(value['runtime'], dict)
            or set(value['runtime']) != {'python', 'implementation'}
            or any(not isinstance(item, str) or not item for item in value['runtime'].values())):
        raise ValueError('Reference historical import guard format differs')
    for filename, sha in value['files'].items():
        if not isinstance(filename, str) or not Path(filename).is_absolute():
            raise ValueError('Reference historical tool path differs')
        _sha(sha)


def _raw(path, limit=JSON_LIMIT):
    with Path(path).open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Reference JSON exceeds its explicit budget')
    return raw


def _pointer(value, root, category):
    if not isinstance(value, dict) or set(value) != {'path', 'sha256'}:
        raise ValueError('Reference pointer shape differs')
    expected = _sha(value['sha256'])
    if not isinstance(value['path'], str):
        raise ValueError('Reference pointer path differs')
    path = Path(value['path']).resolve()
    prefix = Path(root).resolve()/'knowledge'/category
    if (not path.is_relative_to(prefix) or path.name != 'manifest.json'
            or path.parent.name != expected):
        raise ValueError('Reference pointer escapes its immutable namespace')
    raw = _raw(path)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Reference immutable manifest SHA differs')
    return path, raw, json.loads(raw.decode('utf-8-sig'))


def _write_snapshot(workflow, root, category, value):
    if len(canonical(value)) > JSON_LIMIT:
        raise ValueError('Reference manifest exceeds its explicit budget')
    path = workflow.snapshot(root, category, value)
    return dict(path=str(path.resolve()), sha256=path.parent.name)


def _row_path(row):
    if not isinstance(row, dict) or not isinstance(row.get('path'), str) or not row['path']:
        raise ValueError('Reference archive requires an explicit path')
    return Path(row['path'])


class _Import:
    def __init__(self, index, args, rows, stop_requested):
        self.index, self.args = index, args
        self.root = Path(args.root).resolve()
        self.digest = _digest(index)
        self.workflow = index.extension('research-workflow')
        self.stop_requested = stop_requested or (lambda: False)
        self.guard = _tools(index)
        self.files, self.aliases, self.metadata = {}, {}, []
        self.hashes = {}
        self.store = self.root/'knowledge/resource-reference-v3'
        if not self.store.resolve().is_relative_to(self.root):
            raise ValueError('Reference storage escapes its library')
        self.current = self.store/'current.json'
        if not self.current.resolve().is_relative_to(self.store.resolve()):
            raise ValueError('Reference active pointer escapes its storage')
        self.current_before = _raw(self.current) if self.current.is_file() else None
        if self.current.exists() and not self.current.is_file():
            raise ValueError('Reference active pointer is not a file')
        unique = {}
        if not isinstance(rows, (list, tuple)) or not 1 <= len(rows) <= MAX_ARCHIVES:
            raise ValueError('Reference archive budget is 1..4096 rows')
        for row in rows:
            lexical = _row_path(row)
            archive = self.resolve(lexical)
            # Path keys retain Windows case-insensitive equality.
            if archive in unique:
                continue
            unique[archive] = lexical
            folder = self.resolve(self.root/'pak-extracted'/lexical.stem)
            if not folder.is_relative_to(self.root):
                raise ValueError('Reference extraction directory escapes the library')
            entries = self.resolve(self.root/'pak-extracted'/lexical.stem/'entries.json')
            if not entries.is_relative_to(folder):
                raise ValueError('Reference entries metadata escapes its directory')
            if entries.exists() and not entries.is_file():
                raise ValueError('Reference entries metadata is not a file')
            if entries.is_file():
                raw = _raw(entries, METADATA_LIMIT)
                expected = hashlib.sha256(raw).hexdigest()
                records = json.loads(raw.decode('utf-8-sig'))
                if not isinstance(records, list):
                    raise ValueError('Reference entries metadata must contain a list')
                self.files[entries] = expected
            else:
                expected, records = None, []
                self.files[entries] = None
            self.metadata.append(dict(archive=archive, folder=folder, entries=entries,
                entries_sha256=expected, records=records))
        self.metadata.sort(key=lambda row: str(row['archive']))
        base = dict(schema=3, recipe=RECIPE, root=str(self.root), import_guard=self.guard,
            archives=[dict(archive=str(row['archive']), entries=str(row['entries']),
                entries_sha256=row['entries_sha256']) for row in self.metadata],
            metadata_aliases={name: str(path) for name, path in sorted(self.aliases.items())})
        self.base_generation = fingerprint(base)
        generation = self.base_generation
        # An actual corruption failure must not re-use stale hash checkpoints
        # forever. Retain the failed attempt; a fresh generation recomputes it.
        attempt = 0
        while True:
            directory = self.store/'imports'/generation
            status = directory/'status.json'
            if not status.is_file() or json.loads(_raw(status)).get('state') != 'failed':
                break
            attempt += 1
            generation = fingerprint(dict(base_generation=self.base_generation, attempt=attempt))
        self.generation, self.directory = generation, directory
        self.status = self.directory/'status.json'

    def resolve(self, path):
        lexical = str(Path(path).absolute())
        actual = Path(path).resolve()
        if lexical in self.aliases and self.aliases[lexical] != actual:
            raise ValueError('Reference input alias changed during import')
        self.aliases[lexical] = actual
        return actual

    def stopped(self):
        if self.stop_requested():
            raise ReferenceInterrupted('Reference import interrupted; active snapshot unchanged')

    def progress(self, state, **extra):
        self.workflow.atomic(self.status, canonical(dict(schema=3, recipe=RECIPE,
            generation=self.generation, base_generation=self.base_generation, state=state, **extra)))

    def checkpoint(self, item, hashes, complete):
        value = dict(schema=3, recipe=RECIPE, generation=self.generation,
            archive=str(item['archive']), entries_sha256=item['entries_sha256'],
            state='hash_checkpoint_only', complete=complete, hashes=hashes)
        pointer = _write_snapshot(self.workflow, self.root, CHECKPOINT_CATEGORY, value)
        path = self.directory/'archives'/(fingerprint(str(item['archive']))+'.json')
        self.workflow.atomic(path, canonical(pointer))
        return pointer

    def archive(self, item):
        checkpoint_path = self.directory/'archives'/(fingerprint(str(item['archive']))+'.json')
        reused = {}
        if checkpoint_path.is_file():
            _, _, value = _pointer(json.loads(_raw(checkpoint_path)), self.root, CHECKPOINT_CATEGORY)
            if (value.get('schema') != 3 or value.get('recipe') != RECIPE
                    or value.get('generation') != self.generation
                    or value.get('archive') != str(item['archive'])
                    or value.get('entries_sha256') != item['entries_sha256']
                    or value.get('state') != 'hash_checkpoint_only'
                    or not isinstance(value.get('hashes'), dict)):
                raise ValueError('Reference hash checkpoint identity differs')
            reused = {str(Path(path).resolve()): _sha(sha) for path, sha in value['hashes'].items()}
        blobs, hashes, new_hashes = [], {}, 0
        try:
            for row in item['records']:
                self.stopped()
                if not isinstance(row, dict):
                    raise ValueError('Reference entry must be an object')
                if not row.get('saved'):
                    continue
                if not isinstance(row['saved'], str):
                    raise ValueError('Reference saved blob path differs')
                path = self.resolve(row['saved'])
                if not path.is_relative_to(item['folder']):
                    raise ValueError('Reference historical blob escapes its directory')
                if not path.is_file():
                    raise ValueError('Reference historical blob is missing')
                if type(row.get('entry')) is not int or row['entry'] < 0:
                    raise ValueError('Reference previous entry must be a nonnegative integer')
                paths = row.get('paths', [])
                if not isinstance(paths, list) or any(not isinstance(value, str) for value in paths):
                    raise ValueError('Reference observed paths must be strings')
                text = str(path)
                if path not in self.hashes:
                    self.hashes[path] = reused.get(text)
                    if self.hashes[path] is None:
                        self.hashes[path] = _sha(self.digest(path))
                        new_hashes += 1
                expected = self.hashes[path]
                self.files[path] = expected
                hashes[text] = expected
                blobs.append(dict(previous_entry=row['entry'], file=text, sha256=expected,
                    observed_paths=copy.deepcopy(paths)))
                if len(blobs) > MAX_BLOBS:
                    raise ValueError('Reference blob budget exceeded')
                if new_hashes >= CHECKPOINT_INTERVAL:
                    self.checkpoint(item, hashes, False)
                    new_hashes = 0
            pointer = self.checkpoint(item, hashes, True)
        except ReferenceInterrupted:
            self.checkpoint(item, hashes, False)
            raise
        projection = dict(schema=3, recipe=RECIPE, archive=str(item['archive']),
            state='available' if item['entries_sha256'] is not None else 'missing',
            entries=dict(path=str(item['entries']), sha256=item['entries_sha256'])
                if item['entries_sha256'] is not None else None,
            blobs=blobs, validation_scope='legacy_saved_blob_hash_reference', client_version=None,
            resource_identity_proven=False, compatibility='not_established')
        return dict(projection=projection, checkpoint=pointer)

    def barrier(self):
        def aliases():
            if any(Path(name).resolve() != path for name, path in self.aliases.items()):
                raise ValueError('Reference input alias changed before final barrier')
        aliases()
        for path, expected in self.files.items():
            if expected is None:
                if path.exists():
                    raise ValueError('Reference missing metadata appeared during import')
            elif not path.is_file() or self.digest(path) != expected:
                raise ValueError('Reference input SHA changed before final barrier: ' + str(path))
        if _tools(self.index) != self.guard:
            raise ValueError('Reference import tool or runtime guard changed')
        aliases()
        if (_raw(self.current) if self.current.is_file() else None) != self.current_before:
            raise ValueError('Reference active pointer changed during import')

    def run(self):
        self.progress('running')
        try:
            archives = []
            for item in self.metadata:
                self.stopped()
                archives.append(self.archive(item))
            self.stopped()
            closure_sha = fingerprint(dict(files={str(path): sha for path, sha in self.files.items()},
                aliases={name: str(path) for name, path in self.aliases.items()}, import_guard=self.guard))
            value = dict(schema=3, recipe=RECIPE, generation=self.generation,
                import_guard=self.guard, archives=archives,
                validation_scope='legacy_saved_blob_hash_reference', original_client_version=None,
                resource_identity_proven=False, compatibility='not_established',
                input_closure_sha256=closure_sha,
                import_verification=dict(initial_inputs_hashed=True, activation_requires_fresh_barrier=True,
                    files=len(self.files), missing_metadata=sum(sha is None for sha in self.files.values())))
            pointer = _write_snapshot(self.workflow, self.root, CATEGORY, value)
            self.stopped()
            self.barrier()
            self.stopped()
            activation = _write_snapshot(self.workflow, self.root, ACTIVATION_CATEGORY, dict(
                schema=3, recipe=RECIPE, snapshot=pointer, generation=self.generation,
                final_barrier_passed=True, input_closure_sha256=closure_sha,
                import_guard=self.guard, validation_scope='legacy_reference_import_activation',
                files_verified=len(self.files), aliases_verified=len(self.aliases),
                resource_identity_proven=False, compatibility='not_established'))
            self.stopped()
            # No pointer is assigned until every archive and all initial inputs
            # pass their fresh SHA/alias barrier. The immutable data was not a
            # completed admission while it existed only as hash checkpoints.
            if (_raw(self.current) if self.current.is_file() else None) != self.current_before:
                raise ValueError('Reference active pointer changed before atomic activation')
            if (self.digest(pointer['path']) != pointer['sha256']
                    or self.digest(activation['path']) != activation['sha256']):
                raise ValueError('Reference snapshot or activation changed before atomic activation')
            self.progress('validated', snapshot=pointer, activation=activation)
            self.workflow.atomic(self.current, canonical(dict(schema=3, snapshot=pointer, activation=activation)))
            return pointer
        except ReferenceInterrupted as error:
            self.progress('interrupted', reason=str(error))
            raise
        except BaseException as error:
            self.progress('failed', reason=str(error))
            raise


def import_legacy(index, args, archive_rows, *, stop_requested=None):
    """Explicit import; callers decide when to replace an active baseline."""
    return _Import(index, args, archive_rows, stop_requested).run()


class Snapshot:
    def __init__(self, index, args, pointer):
        self.index, self.root = index, Path(args.root).resolve()
        self.digest = _digest(index)
        self.pointer = copy.deepcopy(pointer)
        self.path, self.raw, value = _pointer(pointer, self.root, CATEGORY)
        self.path_alias = str(Path(pointer['path']).absolute())
        self.guard = _tools(index)
        if (value.get('schema') != 3 or value.get('recipe') != RECIPE
                or value.get('validation_scope') != 'legacy_saved_blob_hash_reference'
                or value.get('original_client_version') is not None
                or value.get('resource_identity_proven') is not False
                or value.get('compatibility') != 'not_established'
                or value.get('import_verification', {}).get('initial_inputs_hashed') is not True
                or value.get('import_verification', {}).get('activation_requires_fresh_barrier') is not True
                or not isinstance(value.get('archives'), list)
                or not isinstance(value.get('import_guard'), dict)):
            raise ValueError('Reference snapshot schema or import admission differs')
        _guard_shape(value['import_guard'])
        if (not 1 <= len(value['archives']) <= MAX_ARCHIVES
                or type(value['import_verification'].get('files')) is not int
                or value['import_verification']['files'] < 1):
            raise ValueError('Reference import file/archive counts differ')
        _sha(value.get('input_closure_sha256'))
        _sha(value.get('generation'))
        self.current = self.root/'knowledge/resource-reference-v3/current.json'
        if not self.current.resolve().is_relative_to(self.root/'knowledge/resource-reference-v3'):
            raise ValueError('Reference active pointer escapes its storage')
        self.current_raw = _raw(self.current) if self.current.is_file() else None
        if self.current_raw is None:
            raise ValueError('Reference snapshot has no completed activation')
        active = json.loads(self.current_raw)
        if (not isinstance(active, dict) or set(active) != {'schema', 'snapshot', 'activation'}
                or active['schema'] != 3 or active['snapshot'] != pointer):
            raise ValueError('Reference snapshot is not the explicit active baseline')
        self.activation = copy.deepcopy(active['activation'])
        self.activation_path, _, admitted = _pointer(self.activation, self.root, ACTIVATION_CATEGORY)
        if (admitted.get('schema') != 3 or admitted.get('recipe') != RECIPE
                or admitted.get('snapshot') != pointer or admitted.get('generation') != value['generation']
                or admitted.get('final_barrier_passed') is not True
                or admitted.get('input_closure_sha256') != value['input_closure_sha256']
                or admitted.get('import_guard') != value['import_guard']
                or admitted.get('validation_scope') != 'legacy_reference_import_activation'
                or admitted.get('files_verified') != value['import_verification']['files']
                or type(admitted.get('aliases_verified')) is not int or admitted['aliases_verified'] < 1
                or admitted.get('resource_identity_proven') is not False
                or admitted.get('compatibility') != 'not_established'):
            raise ValueError('Reference activation lacks its exact completed import barrier')
        self.aliases = {self.path_alias: self.path,
            str(self.current.absolute()): self.current.resolve(),
            str(Path(self.activation['path']).absolute()): self.activation_path}
        self.archives = {}
        for item in value['archives']:
            row = item.get('projection') if isinstance(item, dict) else None
            if (not isinstance(row, dict) or row.get('schema') != 3 or row.get('recipe') != RECIPE
                    or not isinstance(row.get('archive'), str) or row.get('state') not in ('available', 'missing')
                    or not isinstance(row.get('blobs'), list)):
                raise ValueError('Reference archive projection differs')
            path = Path(row['archive'])
            if not path.is_absolute() or path in self.archives:
                raise ValueError('Reference archive path is ambiguous')
            if (row.get('validation_scope') != 'legacy_saved_blob_hash_reference'
                    or row.get('client_version') is not None or row.get('resource_identity_proven') is not False
                    or row.get('compatibility') != 'not_established'):
                raise ValueError('Reference projection claims unsupported resource semantics')
            if row['state'] == 'missing' and (row.get('entries') is not None or row['blobs']):
                raise ValueError('Missing reference projection invents blob data')
            if row['state'] == 'available':
                entries = row.get('entries')
                if not isinstance(entries, dict) or set(entries) != {'path', 'sha256'}:
                    raise ValueError('Available reference lacks exact entries metadata')
                _sha(entries['sha256'])
                if (not isinstance(entries['path'], str) or not Path(entries['path']).is_absolute()
                        or not Path(entries['path']).is_relative_to(self.root/'pak-extracted')):
                    raise ValueError('Reference metadata path differs')
            for blob in row['blobs']:
                if (not isinstance(blob, dict) or set(blob) != {'previous_entry', 'file', 'sha256', 'observed_paths'}
                        or type(blob['previous_entry']) is not int or blob['previous_entry'] < 0
                        or not isinstance(blob['file'], str) or not Path(blob['file']).is_absolute()
                        or not Path(blob['file']).is_relative_to(self.root/'pak-extracted')
                        or not isinstance(blob['observed_paths'], list)
                        or any(not isinstance(value, str) for value in blob['observed_paths'])):
                    raise ValueError('Reference blob projection differs')
                _sha(blob['sha256'])
            self.archives[path] = copy.deepcopy(row)
        self.finished = False

    def select(self, row):
        if self.finished:
            raise ValueError('Reference snapshot consumer is closed')
        lexical = str(_row_path(row).absolute())
        archive = _row_path(row).resolve()
        if lexical in self.aliases and self.aliases[lexical] != archive:
            raise ValueError('Reference selected archive path alias changed')
        self.aliases[lexical] = archive
        projection = self.archives.get(archive)
        if projection is None:
            projection = dict(schema=3, recipe=RECIPE, archive=str(archive), state='not_imported',
                entries=None, blobs=[], validation_scope='legacy_saved_blob_hash_reference',
                client_version=None, resource_identity_proven=False, compatibility='not_established')
        result = copy.deepcopy(projection)
        result['projection_sha256'] = fingerprint(result)
        return result

    def finish_barrier(self):
        if self.finished:
            raise ValueError('Reference snapshot consumer is closed')
        def aliases():
            if any(Path(name).resolve() != path for name, path in self.aliases.items()):
                raise ValueError('Reference consumer path alias changed')
        aliases()
        if (self.digest(self.path) != self.pointer['sha256']
                or self.digest(self.activation_path) != self.activation['sha256']
                or (_raw(self.current) if self.current.is_file() else None) != self.current_raw
                or _tools(self.index) != self.guard):
            raise ValueError('Reference snapshot, active pointer or consumer guard changed')
        aliases()
        self.finished = True
        return dict(schema=3, recipe=RECIPE, state='validated', snapshot=copy.deepcopy(self.pointer),
            consumer_guard=copy.deepcopy(self.guard), legacy_files_rehashed=0,
            validation_scope='immutable_legacy_reference_consumption', compatibility='not_established')


def open_snapshot(index, args, pointer):
    return Snapshot(index, args, pointer)


def open_active(index, args):
    """Open the explicit active baseline, or None before its first import.

    The returned consumer remains open so the pipeline can perform its final
    barrier together with the other consumed inputs, without a second open.
    """
    path = Path(args.root).resolve()/'knowledge/resource-reference-v3/current.json'
    if not path.exists():
        return None
    if not path.is_file():
        raise ValueError('Reference active pointer is not a file')
    value = json.loads(_raw(path))
    if (not isinstance(value, dict) or set(value) != {'schema', 'snapshot', 'activation'}
            or value['schema'] != 3):
        raise ValueError('Reference active pointer schema differs')
    return open_snapshot(index, args, value['snapshot'])


def active_pointer(index, args):
    """Validate the active snapshot and return its immutable pointer."""
    snapshot = open_active(index, args)
    if snapshot is None:
        return None
    snapshot.finish_barrier()
    return copy.deepcopy(snapshot.pointer)
