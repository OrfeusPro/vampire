"""Один снимок SHA ресурсов и назначение кэша после свежего общего барьера."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import time
import uuid
from functools import wraps

RECIPE = 'resource-owner-sha-v4'
SHA = re.compile('[0-9a-f]{64}')


def locked(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self.lock:
            return method(self, *args, **kwargs)
    return call


def original(index, args):
    store = getattr(args, 'source_store', None)
    return getattr(store, 'index', index)


def enabled(index, args):
    path = Path(args.knowledge)/'resource-owner-engine.json'
    if not path.is_file():
        return False
    if index.read_json(path) != dict(schema=4, recipe=RECIPE):
        raise ValueError('Неизвестный resource owner recipe')
    return True


def begin(index, args):
    previous = getattr(args, 'resource_owner', None)
    if previous is not None and not previous.closed:
        raise ValueError('Resource owner уже открыт')
    owner = Owner(index, args)
    args.resource_owner = owner
    try:
        owner.digest(Path(__file__))
        selector = Path(args.knowledge)/'resource-owner-engine.json'
        with selector.open('rb') as stream:
            raw = stream.read(4097)
        if len(raw) > 4096 or json.loads(raw) != dict(schema=4, recipe=RECIPE):
            owner.fail('Resource owner selector изменился')
        owner.remember(selector, raw)
        return owner
    except BaseException:
        if not owner.closed:owner.abort()
        raise


class Owner:
    recipe = RECIPE

    def __init__(self, index, args):
        self.index, self.args = index, args
        self.lock = threading.RLock()
        self.origin = original(index, args)
        self.raw_digest = self.origin.digest
        self.store = getattr(args, 'source_store', None)
        if self.store is not None and getattr(self.raw_digest, '__self__', None) is self.store:
            raise ValueError('Resource owner требует исходный digest')
        self.root, self.knowledge = Path(args.root).resolve(), Path(args.knowledge).resolve()
        self.root_argument, self.knowledge_argument = Path(args.root).absolute(), Path(args.knowledge).absolute()
        self.state = 'open'
        self.epoch = uuid.uuid4().hex
        self.files, self.aliases, self.optional, self.pending = {}, {}, {}, {}
        self.aliases[str(self.root_argument)] = self.root
        self.aliases[str(self.knowledge_argument)] = self.knowledge
        self.final_checks = []
        self.metrics = dict(digest_reads=0, digest_hits=0, remembered_reads=0,
            barrier_reads=0, barrier_bytes=0, barrier_seconds=0,
            pending_caches=0, assigned_caches=0)

    @property
    def closed(self):
        return self.state != 'open'

    @locked
    def fail(self, reason):
        self.state = 'failed'
        raise ValueError(reason)

    @locked
    def identity(self, index, args):
        if (args is not self.args or original(index, args) is not self.origin
                or self.origin.digest != self.raw_digest
                or getattr(args, 'source_store', None) is not self.store
                or getattr(args, 'resource_owner', None) is not self
                or Path(args.root).absolute() != self.root_argument
                or Path(args.knowledge).absolute() != self.knowledge_argument):
            self.fail('Resource owner identity изменилась')

    @locked
    def check(self, index, args):
        if self.closed:
            raise ValueError('Resource owner закрыт')
        self.identity(index, args)

    @locked
    def resolve(self, filename):
        self.check(self.index, self.args)
        lexical = str(Path(filename).absolute())
        if lexical in self.aliases:
            return self.aliases[lexical]
        path = Path(filename).resolve()
        self.aliases[lexical] = path
        return path

    @locked
    def bind_aliases(self, aliases):
        self.check(self.index, self.args)
        for lexical, expected in aliases.items():
            if self.resolve(lexical) != Path(expected):
                self.fail('Resource owner alias отличается от проверенного')

    @locked
    def remember(self, filename, raw):
        if not isinstance(raw, bytes):
            self.fail('Resource owner требует прочитанные bytes')
        path = self.resolve(filename)
        sha = hashlib.sha256(raw).hexdigest()
        if path in self.files and self.files[path] != sha:
            self.fail('Resource owner SHA конфликтует: '+str(path))
        self.files[path] = sha
        self.metrics['remembered_reads'] += 1
        return sha

    @locked
    def digest(self, filename):
        path = self.resolve(filename)
        if path in self.files:
            self.metrics['digest_hits'] += 1
            return self.files[path]
        sha = self.raw_digest(path)
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            self.fail('Resource owner требует полный SHA')
        self.files[path] = sha
        self.metrics['digest_reads'] += 1
        return sha

    @locked
    def expect(self, filename, expected):
        if not isinstance(expected, str) or not SHA.fullmatch(expected):
            self.fail('Resource owner expected SHA неверен')
        actual = self.digest(filename)
        if actual != expected:
            self.fail('Resource owner SHA отличается: '+str(filename))
        return actual

    @locked
    def watch(self, filename, exists):
        path = self.resolve(filename)
        if path in self.optional and self.optional[path] != exists:
            self.fail('Resource owner optional input изменился')
        self.optional[path] = exists

    def cache_path(self, filename):
        path = self.resolve(filename)
        allowed = (self.root/'knowledge/resource-csv-v3-cache',
            self.root/'knowledge/resource-comparison-cache-v3')
        if not any(path.is_relative_to(folder) for folder in allowed):
            self.fail('Resource owner cache вне разрешённого каталога')
        return path

    @locked
    def cached(self, filename):
        path = self.cache_path(filename)
        if path in self.pending:
            return copy.deepcopy(self.pending[path])
        exists = path.is_file()
        self.watch(path, exists)
        if not exists:
            return None
        with path.open('rb') as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            self.fail('Resource owner cache превышает бюджет')
        self.remember(path, raw)
        return json.loads(raw)

    @locked
    def defer(self, filename, pointer):
        path = self.cache_path(filename)
        if (not isinstance(pointer, dict) or set(pointer) != {'path', 'sha256'}
                or not isinstance(pointer['path'], str) or not Path(pointer['path']).is_absolute()):
            self.fail('Resource owner требует точный cache pointer')
        target = self.resolve(pointer['path'])
        if (not target.is_relative_to(self.root/'knowledge') or target.name != 'manifest.json'
                or target.parent.name != pointer['sha256']):
            self.fail('Resource owner cache target вне content-addressed каталога')
        self.expect(pointer['path'], pointer['sha256'])
        current = self.cached(path)
        if current is not None and current != pointer:
            self.fail('Resource owner cache key имеет другой результат')
        if path in self.pending and self.pending[path] != pointer:
            self.fail('Resource owner pending cache конфликтует')
        if current is None:
            self.pending[path] = copy.deepcopy(pointer)
            self.metrics['pending_caches'] = len(self.pending)

    def aliases_match(self):
        for lexical, expected in self.aliases.items():
            if Path(lexical).resolve() != expected:
                self.fail('Resource owner alias изменился перед публикацией')

    @locked
    def final_check(self, callback):
        self.check(self.index, self.args)
        self.final_checks.append(callback)

    def assign(self, path, pointer, workflow):
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = workflow.canonical(pointer)
        handle, temporary = tempfile.mkstemp(prefix='.resource-owner-', dir=path.parent)
        try:
            with os.fdopen(handle, 'wb') as stream:
                stream.write(raw)
            try:
                os.link(temporary, path)
            except FileExistsError:
                if path.read_bytes() != raw:
                    self.fail('Resource owner cache изменился при назначении')
        finally:
            Path(temporary).unlink(missing_ok=True)

    @locked
    def finish(self):
        self.check(self.index, self.args)
        self.state = 'validating'
        started = time.perf_counter()
        try:
            self.identity(self.index, self.args)
            self.aliases_match()
            for check in self.final_checks:
                check()
            for path, expected in self.files.items():
                if self.raw_digest(path) != expected:
                    self.fail('Resource owner input изменился перед публикацией: '+str(path))
                self.metrics['barrier_reads'] += 1
                self.metrics['barrier_bytes'] += path.stat().st_size
            for path, exists in self.optional.items():
                if path.is_file() != exists:
                    self.fail('Resource owner optional input появился или исчез')
            self.identity(self.index, self.args)
            self.aliases_match()
            for check in self.final_checks:
                check()
            self.metrics['barrier_seconds'] = round(time.perf_counter()-started, 6)
            workflow = self.index.extension('research-workflow')
            receipt = workflow.snapshot(self.root, 'resource-owner-barriers-v4', dict(
                schema=4, recipe=RECIPE, epoch=self.epoch, barrier_completed=True,
                cache_assignment_pending=True, inputs={str(p):sha for p,sha in self.files.items()},
                pending_caches={str(p):v for p,v in self.pending.items()},
                metrics=copy.deepcopy(self.metrics), resource_identity_proven=False))
            for path, pointer in self.pending.items():
                self.assign(path, pointer, workflow)
                self.metrics['assigned_caches'] += 1
            self.state = 'completed'
            return dict(recipe=RECIPE, state='completed', barrier_completed=True,
                report=str(receipt), sha256=self.raw_digest(receipt),
                metrics=copy.deepcopy(self.metrics), resource_identity_proven=False)
        except BaseException:
            self.state = 'failed'
            raise

    @locked
    def abort(self):
        self.state = 'aborted'
