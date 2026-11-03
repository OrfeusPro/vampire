"""Reuse a fully validated publication only while its complete inputs are unchanged.

Versioned declarative orchestration. A new receipt is earned by normal frozen publish();
an index entry or a cached native result alone never creates this receipt.
"""
import copy
import hashlib
import json
import importlib.metadata
from pathlib import Path
import re
import sys
import time

HERE = Path(__file__).resolve().parent
SCHEMA = 2
CATEGORY = 'native-publication-validations-v2'
SHA = re.compile('[0-9a-f]{64}')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def fingerprint(value): return hashlib.sha256(canonical(value)).hexdigest()


def begin(index, args, sha): return Session(index, args, sha)


def runtime_files():
    """Actual Python and bounded Capstone/Unicorn implementation bytes."""
    paths = {Path(sys.executable).resolve()}
    for directory in (Path(sys.base_prefix), Path(sys.base_prefix) / 'DLLs'):
        for name in (f'python{sys.version_info.major}{sys.version_info.minor}.dll', 'python3.dll'):
            if (directory / name).is_file():
                paths.add((directory / name).resolve())
    folder = HERE.parents[2] / '.tools/vampir-analysis'
    for distribution in importlib.metadata.distributions(path=[str(folder)]):
        if distribution.metadata['Name'].lower() not in ('capstone', 'unicorn'):
            continue
        for entry in distribution.files or ():
            path = Path(distribution.locate_file(entry)).resolve()
            if path.is_relative_to(folder.resolve()) and (path.suffix in ('.py', '.dll', '.pyd', '.so') or path.name == 'RECORD'):
                paths.add(path)
    return sorted(paths)


class Session:
    """One frozen driver invocation, with a mandatory final source/file barrier."""
    def __init__(self, index, args, sha):
        if not isinstance(sha, str) or not SHA.fullmatch(sha): raise ValueError('Publication cache needs full source SHA')
        if not hasattr(args, 'source_store'): raise ValueError('Publication cache requires a frozen source store')
        self.index, self.args, self.sha = index, args, sha
        self.root, self.knowledge = Path(args.root).resolve(), Path(args.knowledge).resolve()
        self.store = args.source_store
        self.files, self.documents, self.sources, self.pending, self.observed = {}, {}, {}, {}, []
        self.mutable_files, self.mutable_documents, self.used_descriptors, self.validator_tools = {}, {}, {}, {}
        self.migration_inputs = {}
        self.finished = False
        self.started = time.perf_counter()
        self.metrics = dict(reused=0, validated=0, receipts_written=0)
        self.common = index.extension('update-native-contexts')
        self.workflow = index.extension('research-workflow')
        self.registry_api = index.extension('native-release-registry')
        self.registry_path = self.knowledge / 'native-release-registry.json'
        self.registry_hash = self.mutable(self.registry_path)
        self.registry = self.registry_api.read(self.knowledge)
        self.driver = index.extension('update-native-drivers-v2')
        self.descriptor_inventory = self.driver.registry(index, self.knowledge)
        self.descriptors = {row['family']: row for row in self.descriptor_inventory}
        self.guard = {str(HERE / name): self.actual(HERE / name)
            for name in ('native-publication-v2.py', 'update-native-drivers-v2.py',
                'knowledge-index.py', 'research-workflow.py', 'native-release-registry.py',
                'update-native-contexts.py', 'update-native-harness.py', 'update-bindings.py')}
        self.python_runtime = sys.version
        self.binary_runtime = {str(path):self.actual(path) for path in runtime_files()}
        self.runtime = index.extension('update-native-harness').runtime_inputs()

    def mutable(self, path, *, owned_write=False):
        p = Path(path).resolve()
        value = self.index.digest(p) if p.is_file() else None
        if not owned_write and str(p) in self.mutable_files and self.mutable_files[str(p)] != value:
            raise ValueError('Publication mutable input changed during update: ' + str(p))
        self.mutable_files[str(p)] = value
        return value

    def _descriptor(self, family):
        if family not in self.descriptors:
            raise ValueError('Unregistered publication v2 family')
        row = self.descriptors[family]
        self.used_descriptors[family] = copy.deepcopy(row)
        return row

    def _tools(self, family, model):
        descriptor = self._descriptor(family)
        if descriptor['factory_kind'] == 'utf8-module':
            tools = {str(HERE / name): self.index.digest(HERE / name) for name in model.TOOLS}
        else:
            tools = model.tools()
        if not isinstance(tools, dict) or not tools:
            raise ValueError('Publication validator tools are not explicit')
        for path, expected in tools.items():
            if self.actual(path) != expected:
                raise ValueError('Publication validator tool changed')
        self.validator_tools[family] = copy.deepcopy(tools)
        return tools

    def _registry_projection(self, sources, contexts):
        releases = [row for row in self.registry['releases'] if row['source_sha256'] in sources]
        ids = {row['id'] for row in releases}
        families = {family for family, _ in contexts}
        aliases = {release: {key: value for key, value in items.items()
            if key in families or value in families}
            for release, items in self.registry.get('family_aliases', {}).items() if release in ids}
        return dict(schema=self.registry['schema'], releases=sorted(releases, key=lambda row: row['order']),
            family_aliases={key: value for key, value in aliases.items() if value},
            suite_adapters=[row for row in self.registry.get('suite_adapters', []) if row['family'] in families],
            projections=[row for row in self.registry.get('projections', [])
                if row['release'] in ids and 'contract:' + row['contract'] in families])

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

    def _lineage(self, pointers, artifacts, *, historical_migration=False):
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
                self._descriptor(family)
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
                # An inherited source hash also covers semantic event metadata
                # such as source="packet". Only path-like inherited values are
                # EXE references; an explicit source_sha256 always stays strict.
                elif ('source' in value and isinstance(value['source'], str) and sha is not None
                        and (Path(value['source']).is_absolute() or any(char in value['source'] for char in '/\\:')
                             or value['source'].lower().endswith('.exe'))):
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
                if not historical_migration and isinstance(value.get('tools'), dict):
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
        return self.driver.tool(self.index, self._descriptor(family))

    def _row(self, family, sha, tool=None):
        descriptor = self._descriptor(family)
        self._tools(family, tool or self._tool(family))
        path = self.root / 'knowledge' / descriptor['index_relative_path'] / 'index.json'
        self.mutable(path)
        if not path.is_file(): return None
        raw = path.read_bytes(); value = json.loads(raw)
        if (value.get('schema') != 1 or not isinstance(value.get('contexts'), list) or len(value['contexts']) > 4096):
            raise ValueError('Publication index structure differs')
        self.mutable_documents[str(path.resolve())] = copy.deepcopy(value)
        selected_rows = []
        for row in value['contexts']:
            if set(row) != {'context', 'check', 'order'} or type(row['order']) is not int or row['order'] < 0:
                raise ValueError('Publication index declaration differs')
            p, expected = self._pointer(row['context'])
            metadata = self.common.checked(self.root, row['context'], 'generated-native-contexts')
            # Metadata needed to select a row is an invocation input, not a
            # persistent dependency on the report of every historical release.
            if self.actual(p) != expected or metadata.get('family') != family or not isinstance(metadata.get('source_sha256'), str) or not SHA.fullmatch(metadata['source_sha256']):
                raise ValueError('Publication index context metadata differs')
            if metadata['source_sha256'] == sha:
                selected_rows.append(row)
        if len(selected_rows) > 1:
            raise ValueError('Ambiguous publication source')
        if descriptor['factory_kind'] == 'utf8-module':
            self._tools(family, tool or self._tool(family))
            # The legacy importer lacks value=. This exact selected-row
            # contract mirrors its bounded UTF-8 admission without reading all
            # other release reports or monkeypatching the frozen importer.
            found = []
            for row in selected_rows:
                context = self.common.checked(self.root, row['context'], 'generated-native-contexts')
                report = self.common.checked(self.root, row['check'], 'native-adapter-checks')
                if (report.get('source_sha256') != sha or report.get('scope') != 'bounded_native_utf8'
                        or report.get('method') != 'bounded_native' or report.get('proof') != context.get('native_admission')
                        or any(report.get(key) is not False for key in ('runtime_activated', 'network_used', 'profile_activated'))
                        or len(report.get('cases', [])) != 142 or len(report.get('scalar_cases', [])) != 80
                        or not all(item.get('guards') is True for item in report['cases'] + report['scalar_cases'])):
                    raise ValueError('Selected UTF-8 publication lacks reviewed semantic proof')
                found.append((Path(row['context']['path']), context, row['order']))
        else:
            tool = tool or self._tool(family)
            self._tools(family, tool)
            found = tool.published_contexts(self.root, self.registry, value=dict(schema=1, contexts=selected_rows))
        if path.read_bytes() != raw or self.mutable(path) != hashlib.sha256(raw).hexdigest():
            raise ValueError('Publication index changed while checking')
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
        descriptor = self._descriptor(spec.get('family'))
        if spec != self.driver.spec(descriptor):
            raise ValueError('Publication v2 selected descriptor differs')
        context = self.common.checked(self.root, declaration['context'], 'generated-native-contexts')
        check = dict(path=outcome['report'], sha256=outcome['sha256'])
        report = self.common.checked(self.root, check, 'native-adapter-checks')
        proof = context.get('native_admission') if descriptor['factory_kind'] == 'utf8-module' else context.get('transfer_proof')
        if (declaration.get('id') != spec['id'] or outcome.get('id') != spec['id']
                or declaration.get('adapter') != spec['adapter'] or declaration.get('family', spec['family']) != spec['family']
                or outcome.get('state') != 'passed' or context.get('family') != spec['family'] or context.get('source_sha256') != self.sha
                or declaration.get('scope') != report.get('scope') or outcome.get('scope') != report.get('scope')
                or report.get('method') != 'bounded_native' or report.get('source_sha256') != self.sha
                or report.get('context_sha256') != declaration['context']['sha256']
                or report.get('proof') != proof or declaration.get('proof') != proof
                or any(report.get(k) is not False for k in ('network_used', 'profile_activated', 'runtime_activated'))
                or any(outcome.get(k) is not False for k in ('profile_activated', 'runtime_activated'))):
            raise ValueError('Publication declaration/result provenance differs')
        tools = self._tools(spec['family'], tool)
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
            python_runtime=self.python_runtime, binary_runtime=self.binary_runtime, publications=selections,
            registry_projection=self._registry_projection(sources, contexts),
            descriptors={family:self.used_descriptors[family] for family, _ in sorted(contexts)},
            validator_tools={family:self.validator_tools[family] for family, _ in sorted(contexts)
                if family in self.validator_tools})), eligible

    def _cached(self, snapshot):
        key = fingerprint(snapshot); path = self.root / 'knowledge/native-publication-cache-v2' / (key + '.json')
        if not path.is_file(): return False
        raw = path.read_bytes(); pointer = json.loads(raw)
        if self.actual(path) != hashlib.sha256(raw).hexdigest(): raise ValueError('Publication cache pointer changed while reading')
        value = self.common.checked(self.root, pointer, CATEGORY)
        if self.actual(pointer['path']) != pointer['sha256']: raise ValueError('Publication cache receipt changed')
        if (set(value) != {'schema', 'key', 'inputs', 'validation_method', 'runtime_activated', 'migration_provenance'}
                or value['schema'] != SCHEMA or value['key'] != key or value['inputs'] != snapshot
                or value['validation_method'] != 'full_adapter_publish' or value['runtime_activated'] is not False):
            raise ValueError('Publication validation receipt differs')
        provenance = value['migration_provenance']
        if not isinstance(provenance, dict) or provenance.get('method') != 'full_frozen_adapter_publish' or provenance.get('final_barriers_passed') is not True:
            raise ValueError('Publication v2 migration provenance differs')
        return True

    def publish(self, spec, tool, declaration, outcome):
        if self.finished: raise ValueError('Publication cache session already finished')
        before, eligible = self._snapshot(spec, tool, declaration, outcome)
        if eligible and self._cached(before):
            self.metrics['reused'] += 1; self.observed.append((copy.deepcopy(spec), tool, copy.deepcopy(declaration), copy.deepcopy(outcome), before))
            return 'reused'
        owned_index = self.root / 'knowledge' / self._descriptor(spec['family'])['index_relative_path'] / 'index.json'
        old_document = self.mutable_documents.get(str(owned_index.resolve()))
        migration_files, migration_sources = {}, {}
        def pin_legacy_document(document):
            for row in (document or {}).get('contexts', []):
                files, _, sources = self._lineage([row['context'], row['check']], {}, historical_migration=True)
                migration_files.update(files); migration_sources.update(sources)
        # Frozen publish() also reads retained historical rows. Record that
        # one-time consumed closure for final barriers and historical migration
        # provenance, without putting it in future selected-family cache keys.
        pin_legacy_document(old_document)
        tool.publish(self.index, self.args, self.sha, declaration, outcome)
        new_document = json.loads(owned_index.read_bytes())
        pin_legacy_document(new_document)
        def unrelated(document):
            if document is None:
                return []
            if set(document) != {'schema', 'contexts'} or document['schema'] != 1 or not isinstance(document['contexts'], list):
                raise ValueError('Owned publication index schema differs')
            return sorted(canonical(row) for row in document['contexts']
                if self.common.checked(self.root, row['context'], 'generated-native-contexts')['source_sha256'] != self.sha)
        if unrelated(old_document) != unrelated(new_document):
            raise ValueError('Publication changed an unrelated index row')
        self.mutable(owned_index, owned_write=True)
        after, eligible = self._snapshot(spec, tool, declaration, outcome)
        # A publication may create/repair its membership; it cannot change any
        # actual evidence, source, tool, declaration or result while doing so.
        if {k: v for k, v in before.items() if k != 'publications'} != {k: v for k, v in after.items() if k != 'publications'}:
            raise ValueError('Publication inputs changed during validation')
        if not eligible: raise ValueError('Validated publication is not the exact current context/check')
        self.metrics['validated'] += 1
        key = fingerprint(after); self.pending[key] = after
        self.migration_inputs[key] = dict(method='full_frozen_adapter_publish',
            files=migration_files, sources=migration_sources, final_barriers_passed=True)
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
        if self.driver.registry(self.index, self.knowledge) != self.descriptor_inventory:
            raise ValueError('Publication descriptor registry changed before final barrier')
        if any((self.index.digest(path) if Path(path).is_file() else None) != expected
                for path, expected in self.mutable_files.items()):
            raise ValueError('Publication mutable registry/index changed before final barrier')
        if any(self.index.digest(path) != expected for path, expected in self.files.items()):
            raise ValueError('Publication evidence/tools changed before final barrier')
        # One full source read barrier per driver invocation, shared by all
        # families. Actual EXE bytes, including historical sources, stay pinned.
        source_metrics = self.store.validate()
        for key, snapshot in self.pending.items():
            value = dict(schema=SCHEMA, key=key, inputs=snapshot,
                validation_method='full_adapter_publish', runtime_activated=False,
                migration_provenance=self.migration_inputs[key])
            pointer = self.common.receipt(self.root, CATEGORY, value)
            self.workflow.atomic(self.root / 'knowledge/native-publication-cache-v2' / (key + '.json'), self.workflow.canonical(pointer))
            self.metrics['receipts_written'] += 1
        self.finished = True
        return dict(self.metrics, seconds=round(time.perf_counter() - self.started, 6),
            source_store=source_metrics, runtime_activated=False)
