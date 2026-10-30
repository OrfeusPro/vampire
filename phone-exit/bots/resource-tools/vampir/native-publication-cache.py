"""Reuse a fully validated publication only while its complete inputs are unchanged.

Adapters remain frozen. A new cache entry is earned by their normal publish();
an index entry or a cached native result alone never creates this receipt.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import time

HERE = Path(__file__).resolve().parent
SCHEMA = 1
CATEGORY = 'native-publication-validations'
SHA = re.compile('[0-9a-f]{64}')
INDEXES = {
    'utf8': 'generated-native',
    'string-writer': 'generated-string-writers',
    'archive-wire': 'generated-archive-wire',
    'version-result': 'generated-version-results',
    'version-prepare': 'generated-version-prepare',
    'login-prepare': 'generated-login-prepare',
    'login-prepare-sdk': 'generated-login-sdk',
    **{name: 'generated-version-helpers/' + name for name in (
        'version-nm-device', 'version-cpu', 'version-windows', 'version-combiner', 'version-platform',
        'version-prepare-nm', 'version-prepare-system', 'version-prepare-combiner', 'version-prepare-platform')},
    **{name: 'generated-login-metadata/' + name for name in ('login-metadata', 'login-prepare-metadata')},
    **{name: 'generated-login-input/' + name for name in ('login-nested', 'login-strings-buffer')},
    **{name: 'generated-login-handlers/' + name for name in ('login-continuation', 'login-handler-early')},
}
MODULES = {
    'string-writer': 'update-native-string-writer', 'archive-wire': 'update-native-archive-wire',
    'version-result': 'update-native-version-result', 'version-prepare': 'update-native-version-prepare',
    'login-prepare': 'update-native-login-prepare', 'login-prepare-sdk': 'update-native-login-sdk',
    **{name: 'update-native-version-helpers' for name in INDEXES if name.startswith('version-') and name not in ('version-result', 'version-prepare')},
    **{name: 'update-native-login-metadata' for name in ('login-metadata', 'login-prepare-metadata')},
    **{name: 'update-native-login-input' for name in ('login-nested', 'login-strings-buffer')},
    **{name: 'update-native-login-handler' for name in ('login-continuation', 'login-handler-early')},
}
MULTI = {'update-native-version-helpers', 'update-native-login-metadata', 'update-native-login-input', 'update-native-login-handler'}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def fingerprint(value): return hashlib.sha256(canonical(value)).hexdigest()


def begin(index, args, sha): return Session(index, args, sha)


class Session:
    """One frozen driver invocation, with a mandatory final source/file barrier."""
    def __init__(self, index, args, sha):
        if not isinstance(sha, str) or not SHA.fullmatch(sha): raise ValueError('Publication cache needs full source SHA')
        if not hasattr(args, 'source_store'): raise ValueError('Publication cache requires a frozen source store')
        self.index, self.args, self.sha = index, args, sha
        self.root, self.knowledge = Path(args.root).resolve(), Path(args.knowledge).resolve()
        self.store = args.source_store
        self.files, self.documents, self.sources, self.pending, self.observed = {}, {}, {}, {}, []
        self.finished = False
        self.started = time.perf_counter()
        self.metrics = dict(reused=0, validated=0, receipts_written=0)
        self.common = index.extension('update-native-contexts')
        self.workflow = index.extension('research-workflow')
        self.registry_api = index.extension('native-release-registry')
        self.registry_path = self.knowledge / 'native-release-registry.json'
        self.registry_hash = self.actual(self.registry_path)
        self.registry = self.registry_api.read(self.knowledge)
        self.guard = {str(HERE / name): self.actual(HERE / name)
            for name in ('native-publication-cache.py', 'update-native-drivers.py')}
        self.runtime = index.extension('update-native-harness').runtime_inputs()

    def actual(self, path):
        p = Path(path).resolve(); value = self.index.digest(p)
        previous = self.files.get(str(p))
        if previous is not None and previous != value: raise ValueError('Publication input changed during update: ' + str(p))
        self.files[str(p)] = value
        return value

    def _pointer(self, item):
        if not isinstance(item, dict) or set(item) != {'path', 'sha256'} or not isinstance(item['path'], str) or not isinstance(item['sha256'], str) or not SHA.fullmatch(item['sha256']):
            raise ValueError('Publication lineage pointer differs')
        return Path(item['path']).resolve(), item['sha256']

    def _source(self, sha, path=None):
        if not isinstance(sha, str) or not SHA.fullmatch(sha): raise ValueError('Publication lineage source SHA differs')
        expected = self.root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
        if path is not None and Path(path).resolve() != expected:
            raise ValueError('Publication lineage source path differs')
        self.store.source(sha)
        self.sources[sha] = str(expected)
        return str(expected)

    def _lineage(self, pointers, artifacts):
        """Read bounded knowledge JSON; large Ghidra exports are hash-only inputs."""
        files, contexts, sources, seen = {}, {}, {}, set()
        export_root = self.root / 'ghidra/request-exports'
        allowed = (self.knowledge / 'native-contexts', self.root / 'knowledge', export_root)

        def pin(path, expected, parse=True):
            p = Path(path).resolve(); text = str(p)
            if not any(p.is_relative_to(folder) for folder in allowed):
                raise ValueError('Publication lineage outside reviewed knowledge')
            if not isinstance(expected, str) or not SHA.fullmatch(expected): raise ValueError('Publication expected artifact SHA differs')
            if text in files and files[text] != expected: raise ValueError('Conflicting publication lineage hashes')
            if text in self.files and self.files[text] != expected: raise ValueError('Conflicting publication input hashes')
            actual = self.actual(p)
            if actual != expected: raise ValueError('Publication lineage artifact changed: ' + text)
            files[text] = actual
            if text in seen: return
            seen.add(text)
            if len(seen) > 1024: raise ValueError('Publication lineage file budget exceeded')
            if not parse or p.is_relative_to(export_root): return
            if p not in self.documents:
                raw = p.read_bytes()
                if hashlib.sha256(raw).hexdigest() != expected: raise ValueError('Publication lineage changed while reading')
                self.documents[p] = json.loads(raw)
            value = self.documents[p]
            if p.is_relative_to(self.root / 'knowledge/generated-native-contexts'):
                family = value.get('family')
                if family not in INDEXES: raise ValueError('Unregistered publication lineage family')
                identity = (family, value.get('source_sha256')); pointer = dict(path=text, sha256=actual)
                if identity in contexts and contexts[identity] != pointer:
                    raise ValueError('Conflicting publication source/family contexts')
                contexts[identity] = pointer
            walk(value)

        def walk(value, inherited=None):
            if isinstance(value, dict):
                sha = value.get('source_sha256', inherited)
                if 'source_sha256' in value:
                    sources[sha] = self._source(sha, value.get('source'))
                elif 'source' in value and isinstance(value['source'], str) and sha is not None:
                    sources[sha] = self._source(sha, value['source'])
                if 'path' in value and 'sha256' in value:
                    p, expected = self._pointer(value); pin(p, expected)
                if isinstance(value.get('exports'), dict):
                    if value['exports'] and (not isinstance(sha, str) or not SHA.fullmatch(sha)):
                        raise ValueError('Publication exports have no explicit source')
                    for run, expected in value['exports'].items():
                        if not isinstance(run, str) or Path(run).name != run or not run.startswith('run-'):
                            raise ValueError('Publication export name differs')
                        pin(export_root / sha / run / 'details.json', expected, parse=False)
                # Proof tools are inputs even when a legacy declaration only
                # carried its immediate proof/context, rather than full lineage.
                if isinstance(value.get('tools'), dict):
                    for path, expected in value['tools'].items():
                        # The original UTF-8 proof format records bare tool
                        # filenames; later families record absolute paths.
                        p = Path(path)
                        if not p.is_absolute():
                            if p.name != path: raise ValueError('Publication proof relative tool path differs')
                            p = HERE / p
                        if self.actual(p) != expected: raise ValueError('Publication proof tool changed')
                        files[str(p.resolve())] = expected
                for name, child in value.items():
                    if name not in ('exports', 'tools'): walk(child, sha)
            elif isinstance(value, list):
                for child in value: walk(child, inherited)

        for pointer in pointers:
            p, expected = self._pointer(pointer); pin(p, expected)
        for path, expected in artifacts.items(): pin(path, expected)
        return files, contexts, sources

    def _tool(self, family):
        module = MODULES.get(family)
        if module is None: raise ValueError('Unregistered publication family')
        tool = self.index.extension(module)
        return tool.select(family) if module in MULTI else tool

    def _row(self, family, sha, tool=None):
        if family not in INDEXES: raise ValueError('Unregistered publication index')
        path = self.root / 'knowledge' / INDEXES[family] / 'index.json'
        if not path.is_file(): return None
        raw = path.read_bytes(); value = json.loads(raw)
        if (value.get('schema') != 1 or not isinstance(value.get('contexts'), list) or len(value['contexts']) > 4096):
            raise ValueError('Publication index structure differs')
        if family == 'utf8':
            # The frozen UTF-8 importer lacks value=; ensure it read the same
            # bytes. It performs its own exact report/context proof admission.
            found = self.registry_api.generated_contexts(self.root, self.registry)
        else:
            tool = tool or self._tool(family)
            found = tool.published_contexts(self.root, self.registry, value=value)
        if path.read_bytes() != raw: raise ValueError('Publication index changed while checking')
        selected = [str(Path(p).resolve()) for p, c, _ in found if c['source_sha256'] == sha]
        if len(selected) > 1: raise ValueError('Ambiguous publication source')
        rows = [row for row in value['contexts'] if str(self._pointer(row['context'])[0]) in selected]
        if len(rows) != len(selected): raise ValueError('Publication selection differs')
        for row in rows:
            for name in ('context', 'check'):
                p, expected = self._pointer(row[name])
                if self.actual(p) != expected: raise ValueError('Publication selected receipt changed')
        return copy.deepcopy(rows[0]) if rows else None

    def _snapshot(self, spec, tool, declaration, outcome):
        context = self.common.checked(self.root, declaration['context'], 'generated-native-contexts')
        check = dict(path=outcome['report'], sha256=outcome['sha256'])
        report = self.common.checked(self.root, check, 'native-adapter-checks')
        if (spec.get('family') not in INDEXES or declaration.get('id') != spec['id'] or outcome.get('id') != spec['id']
                or declaration.get('adapter') != spec['adapter'] or declaration.get('family', spec['family']) != spec['family']
                or outcome.get('state') != 'passed' or context.get('family') != spec['family'] or context.get('source_sha256') != self.sha
                or declaration.get('scope') != report.get('scope') or outcome.get('scope') != report.get('scope')
                or report.get('method') != 'bounded_native' or report.get('source_sha256') != self.sha
                or report.get('context_sha256') != declaration['context']['sha256']
                or report.get('proof') != context.get('transfer_proof') or declaration.get('proof') != context.get('transfer_proof')
                or any(report.get(k) is not False for k in ('network_used', 'profile_activated', 'runtime_activated'))
                or any(outcome.get(k) is not False for k in ('profile_activated', 'runtime_activated'))):
            raise ValueError('Publication declaration/result provenance differs')
        tools = tool.tools()
        if declaration.get('dependencies') != tools: raise ValueError('Publication tool dependencies differ')
        for path, expected in tools.items():
            if self.actual(path) != expected: raise ValueError('Publication tool file changed')
        if report.get('runtime') != self.runtime: raise ValueError('Publication native runtime differs')
        self._source(self.sha, context.get('source'))
        artifacts = declaration.get('artifacts')
        if not isinstance(artifacts, dict): raise ValueError('Publication artifacts are not explicit')
        files, contexts, sources = self._lineage([declaration['context'], check], artifacts)
        sources[self.sha] = self.sources[self.sha]
        # Mutable indexes are inspected every time, but only relevant rows enter
        # the cache key. A valid unrelated release does not invalidate this role.
        selections = {}; eligible = True
        for (family, sha), pointer in sorted(contexts.items()):
            row = self._row(family, sha, tool if family == spec['family'] else None)
            selections[family + '@' + sha] = row
            if row is None or row['context'] != pointer: eligible = False
        row = selections.get(spec['family'] + '@' + self.sha)
        if row is None or row['context'] != declaration['context'] or row['check'] != check: eligible = False
        return copy.deepcopy(dict(schema=SCHEMA, spec=spec, source_sha256=self.sha, declaration=declaration, outcome=outcome,
            files=files, sources=sources, tools=tools, guard=self.guard, runtime=self.runtime,
            registry_sha256=self.registry_hash, publications=selections)), eligible

    def _cached(self, snapshot):
        key = fingerprint(snapshot); path = self.root / 'knowledge/native-publication-cache' / (key + '.json')
        if not path.is_file(): return False
        raw = path.read_bytes(); pointer = json.loads(raw)
        if self.actual(path) != hashlib.sha256(raw).hexdigest(): raise ValueError('Publication cache pointer changed while reading')
        value = self.common.checked(self.root, pointer, CATEGORY)
        if self.actual(pointer['path']) != pointer['sha256']: raise ValueError('Publication cache receipt changed')
        if (set(value) != {'schema', 'key', 'inputs', 'validation_method', 'runtime_activated'}
                or value['schema'] != SCHEMA or value['key'] != key or value['inputs'] != snapshot
                or value['validation_method'] != 'full_adapter_publish' or value['runtime_activated'] is not False):
            raise ValueError('Publication validation receipt differs')
        return True

    def publish(self, spec, tool, declaration, outcome):
        if self.finished: raise ValueError('Publication cache session already finished')
        before, eligible = self._snapshot(spec, tool, declaration, outcome)
        if eligible and self._cached(before):
            self.metrics['reused'] += 1; self.observed.append((copy.deepcopy(spec), tool, copy.deepcopy(declaration), copy.deepcopy(outcome), before))
            return 'reused'
        tool.publish(self.index, self.args, self.sha, declaration, outcome)
        after, eligible = self._snapshot(spec, tool, declaration, outcome)
        # A publication may create/repair its membership; it cannot change any
        # actual evidence, source, tool, declaration or result while doing so.
        if {k: v for k, v in before.items() if k != 'publications'} != {k: v for k, v in after.items() if k != 'publications'}:
            raise ValueError('Publication inputs changed during validation')
        if not eligible: raise ValueError('Validated publication is not the exact current context/check')
        self.metrics['validated'] += 1
        key = fingerprint(after); self.pending[key] = after
        self.observed.append((copy.deepcopy(spec), tool, copy.deepcopy(declaration), copy.deepcopy(outcome), after))
        return 'validated'

    def finish(self):
        if self.finished: raise ValueError('Publication cache session already finished')
        # Re-read mutable selections/reports and compare dependencies before any
        # cache receipt is earned. No adapter transfer or native replay occurs.
        for spec, tool, declaration, outcome, expected in self.observed:
            actual, eligible = self._snapshot(spec, tool, declaration, outcome)
            if not eligible or actual != expected: raise ValueError('Publication changed before final barrier')
        if self.index.extension('update-native-harness').runtime_inputs() != self.runtime:
            raise ValueError('Publication runtime changed during update')
        if any(self.index.digest(path) != expected for path, expected in self.files.items()):
            raise ValueError('Publication evidence/tools changed before final barrier')
        # One full source read barrier per driver invocation, shared by all
        # families. Actual EXE bytes, including historical sources, stay pinned.
        source_metrics = self.store.validate()
        for key, snapshot in self.pending.items():
            value = dict(schema=SCHEMA, key=key, inputs=snapshot,
                validation_method='full_adapter_publish', runtime_activated=False)
            pointer = self.common.receipt(self.root, CATEGORY, value)
            self.workflow.atomic(self.root / 'knowledge/native-publication-cache' / (key + '.json'), self.workflow.canonical(pointer))
            self.metrics['receipts_written'] += 1
        self.finished = True
        return dict(self.metrics, seconds=round(time.perf_counter() - self.started, 6),
            source_store=source_metrics, runtime_activated=False)
