"""Publication reuse must preserve all proof, source and report admission guards."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_vampir_update_contracts import load

CACHE = load('native-publication-cache')
COMMON = load('update-native-contexts')
WORKFLOW = load('research-workflow')


def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Fixture:
    def __init__(self, directory):
        self.root = Path(directory).resolve();self.knowledge = self.root / 'definitions'
        self.knowledge.mkdir();self.runtime = {'capstone': {'version': 'fixture'}, 'unicorn': {'version': 'fixture'}}
        self.spec = dict(id='native-auto-version-result', family='version-result', adapter='version-result-v1')
        self.scope = 'bounded_native_version_result_input'
        self.sha = self.source(b'bounded target fixture');self.old_sha = self.source(b'bounded baseline fixture')
        self.tool_file = self.root / 'fixture-tool.py';self.tool_file.write_bytes(b'fixture tool v1')
        self.tools = {str(self.tool_file): digest(self.tool_file)}
        self.registry_path = self.knowledge / 'native-release-registry.json'
        self.registry_path.write_text(json.dumps(dict(schema=1, releases=[dict(source_sha256=self.sha, order=1)])))
        self.baseline = self.knowledge / 'native-contexts/base.json';self.baseline.parent.mkdir()
        self.baseline.write_text(json.dumps(dict(source_sha256=self.old_sha, source=self.source_path(self.old_sha), fields='reviewed')))
        self.export = self.root / 'ghidra/request-exports' / self.sha / 'run-fixture/details.json'
        self.export.parent.mkdir(parents=True);self.export.write_bytes(b'large export bytes: deliberately not JSON')
        self.proof_value = dict(schema=1, baseline=dict(path=str(self.baseline), sha256=digest(self.baseline)),
            source_sha256=self.sha, tools=self.tools, runtime_activated=False)
        proof = COMMON.receipt(self.root, 'fixture-native-proofs', self.proof_value)
        self.context_value = dict(schema=1, family='version-result', source_sha256=self.sha, source=self.source_path(self.sha),
            transfer_proof=proof, exports={'run-fixture': digest(self.export)}, layout=dict(packet_bytes=40))
        self.context = COMMON.receipt(self.root, 'generated-native-contexts', self.context_value)
        self.report_value = dict(schema=1, source_sha256=self.sha, scope=self.scope, method='bounded_native',
            proof=proof, context_sha256=self.context['sha256'], runtime=copy.deepcopy(self.runtime),
            network_used=False, profile_activated=False, runtime_activated=False, cases=[dict(observed='native-fixture', guards=True)])
        self.report = COMMON.receipt(self.root, 'native-adapter-checks', self.report_value)
        self.declaration = dict(id=self.spec['id'], adapter=self.spec['adapter'], scope=self.scope, proof=proof,
            context=self.context, dependencies=copy.deepcopy(self.tools), artifacts={str(self.baseline): digest(self.baseline),
                proof['path']: proof['sha256'], self.context['path']: self.context['sha256'], str(self.export): digest(self.export)})
        self.outcome = dict(id=self.spec['id'], state='passed', scope=self.scope, report=self.report['path'],
            sha256=self.report['sha256'], runtime_activated=False, profile_activated=False)
        self.path = self.root / 'knowledge/generated-version-results/index.json'
        self.publish_count = self.validate_count = 0;self.after_publish = None
        self.tool = SimpleNamespace(tools=lambda:copy.deepcopy(self.tools), published_contexts=self.published_contexts, publish=self.publish)
        self.registry = SimpleNamespace(read=lambda path:json.loads(self.registry_path.read_text()))
        self.index = SimpleNamespace(digest=digest, extension=self.extension)
        self.new_args()

    def new_args(self):
        self.store = load('update-bindings').SourceStore(self.index, self.root)
        original = self.store.validate;self.store.validate = Mock(side_effect=original)
        self.args = SimpleNamespace(root=self.root, knowledge=self.knowledge, source_store=self.store)

    def source_path(self, sha): return str(self.root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe')

    def source(self, raw):
        sha = hashlib.sha256(raw).hexdigest();path = Path(self.source_path(sha))
        path.parent.mkdir(parents=True);path.write_bytes(raw);return sha

    def extension(self, name):
        return {'update-native-contexts': COMMON, 'research-workflow': WORKFLOW, 'native-release-registry': self.registry,
            'update-native-harness': SimpleNamespace(runtime_inputs=lambda:copy.deepcopy(self.runtime)),
            'update-native-version-result': self.tool}[name]

    def row(self): return dict(context=self.context, check=self.report, order=1)

    def write_index(self, rows=None):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(dict(schema=1, contexts=rows if rows is not None else [self.row()])))

    def published_contexts(self, root, registry, *, value):
        seen = set();result = []
        if value.get('schema') != 1 or not isinstance(value.get('contexts'), list): raise ValueError('Fixture bad index')
        for row in value['contexts']:
            if set(row) != {'context', 'check', 'order'} or type(row['order']) is not int or row['order'] < 0:
                raise ValueError('Fixture bad index declaration')
            context = COMMON.checked(root, row['context'], 'generated-native-contexts')
            report = COMMON.checked(root, row['check'], 'native-adapter-checks');sha = context['source_sha256']
            if sha in seen or context['family'] != 'version-result' or context['layout'] != dict(packet_bytes=40):
                raise ValueError('Fixture duplicate/family/layout')
            if (report.get('source_sha256') != sha or report.get('context_sha256') != row['context']['sha256']
                    or report.get('proof') != context['transfer_proof'] or report.get('method') != 'bounded_native'
                    or report.get('scope') != self.scope or report.get('cases') != [dict(observed='native-fixture', guards=True)]
                    or any(report.get(k) is not False for k in ('network_used', 'runtime_activated', 'profile_activated'))):
                raise ValueError('Fixture bad semantic report')
            seen.add(sha);result.append((Path(row['context']['path']), context, row['order']))
        return result

    def publish(self, index, args, sha, declaration, outcome):
        self.publish_count += 1;self.validate_count += 1
        context = COMMON.checked(self.root, declaration['context'], 'generated-native-contexts')
        COMMON.checked(self.root, context['transfer_proof'], 'fixture-native-proofs')
        rows = json.loads(self.path.read_text())['contexts'] if self.path.is_file() else []
        rows = [row for row in rows if COMMON.checked(self.root, row['context'], 'generated-native-contexts')['source_sha256'] != sha]
        rows.append(dict(context=declaration['context'], check=dict(path=outcome['report'], sha256=outcome['sha256']), order=1))
        self.published_contexts(self.root, {}, value=dict(schema=1, contexts=rows));self.write_index(rows)
        if self.after_publish: self.after_publish()

    def session(self): return CACHE.begin(self.index, self.args, self.sha)

    def call(self, session): return session.publish(self.spec, self.tool, self.declaration, self.outcome)

    def populate(self):
        session = self.session();self.call(session);return session.finish()


class PublicationReuseTests(unittest.TestCase):
    def test_cold_publication_earns_receipt_only_after_final_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(directory);session = f.session()
            self.assertEqual(f.call(session), 'validated');self.assertEqual(f.publish_count, 1)
            self.assertFalse(list((f.root / 'knowledge').glob('native-publication-cache/*.json')))
            metrics = session.finish()
            self.assertEqual((metrics['validated'], metrics['reused'], metrics['receipts_written']), (1, 0, 1))
            f.store.validate.assert_called_once()
            self.assertEqual(set(f.store._sources), {f.sha, f.old_sha})

    def test_warm_exact_publication_skips_heavy_publish_without_skipping_source_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(directory);f.populate();f.new_args();session = f.session()
            self.assertEqual(f.call(session), 'reused');metrics = session.finish()
            self.assertEqual(f.publish_count, 1);self.assertEqual(f.validate_count, 1)
            self.assertEqual((metrics['reused'], metrics['validated'], metrics['receipts_written']), (1, 0, 0))
            f.store.validate.assert_called_once()

    def test_existing_index_and_cached_report_alone_do_not_authorize_fast_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(directory);f.write_index();session = f.session()
            self.assertEqual(f.call(session), 'validated');session.finish();self.assertEqual(f.publish_count, 1)

    def test_missing_or_empty_index_is_repaired_by_full_publish_without_native_replay(self):
        for missing in (True, False):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                f = Fixture(directory);f.populate()
                if missing: f.path.unlink()
                else: f.write_index([])
                f.new_args();session = f.session()
                self.assertEqual(f.call(session), 'validated');session.finish();self.assertEqual(f.publish_count, 2)

    def test_bad_index_schema_duplicate_or_rank_blocks_without_rewrite(self):
        for change in ('schema', 'duplicate', 'rank'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                f = Fixture(directory);f.populate();value = json.loads(f.path.read_text())
                if change == 'schema': value['schema'] = 2
                if change == 'duplicate': value['contexts'] *= 2
                if change == 'rank': value['contexts'][0]['order'] = True
                f.path.write_text(json.dumps(value));before = f.path.read_bytes();f.new_args()
                with self.assertRaises(ValueError): f.call(f.session())
                self.assertEqual(f.path.read_bytes(), before);self.assertEqual(f.publish_count, 1)

    def test_report_hash_and_actual_transitive_files_are_checked_before_reuse(self):
        for artifact in ('report', 'proof', 'baseline', 'export'):
            with self.subTest(artifact=artifact), tempfile.TemporaryDirectory() as directory:
                f = Fixture(directory);f.populate();paths = dict(report=Path(f.report['path']),
                    proof=Path(f.context_value['transfer_proof']['path']), baseline=f.baseline, export=f.export)
                paths[artifact].write_bytes(b'corrupted');f.new_args()
                with self.assertRaises(ValueError): f.call(f.session())
                self.assertEqual(f.publish_count, 1)

    def test_bad_report_method_projection_or_activation_is_not_accepted_via_new_pointer(self):
        for change in (dict(method='static'), dict(cases=[]), dict(network_used=True), dict(profile_activated=0),
                dict(context_sha256='f' * 64), dict(proof={}), dict(scope='all_entry')):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                f = Fixture(directory);f.populate()
                bad = COMMON.receipt(f.root, 'native-adapter-checks', dict(f.report_value, **change))
                f.report = bad;f.outcome.update(report=bad['path'], sha256=bad['sha256']);f.write_index();f.new_args()
                with self.assertRaises(ValueError): f.call(f.session())
                self.assertEqual(f.publish_count, 1)

    def test_full_exe_bytes_are_checked_even_when_sha_directory_and_index_are_unchanged(self):
        for source in ('target', 'baseline'):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                f = Fixture(directory);f.populate();Path(f.source_path(f.sha if source == 'target' else f.old_sha)).write_bytes(b'changed')
                f.new_args()
                with self.assertRaisesRegex(ValueError, 'source SHA'): f.call(f.session())

    def test_source_or_evidence_change_after_fast_reuse_aborts_before_new_receipts(self):
        for artifact in ('source', 'export', 'tool', 'index'):
            with self.subTest(artifact=artifact), tempfile.TemporaryDirectory() as directory:
                f = Fixture(directory);f.populate();f.new_args();session = f.session();self.assertEqual(f.call(session), 'reused')
                if artifact == 'source': Path(f.source_path(f.sha)).write_bytes(b'changed')
                if artifact == 'export': f.export.write_bytes(b'changed')
                if artifact == 'tool': f.tool_file.write_bytes(b'changed')
                if artifact == 'index': f.write_index([])
                with self.assertRaises(ValueError): session.finish()
                self.assertFalse(session.finished);self.assertEqual(session.metrics['receipts_written'], 0)

    def test_publish_mutation_or_exception_never_creates_validation_receipt(self):
        for mutate in ('export', 'raises'):
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as directory:
                f = Fixture(directory)
                def change():
                    if mutate == 'export': f.export.write_bytes(b'changed')
                    else: raise ValueError('Interrupted publish')
                f.after_publish = change;session = f.session()
                with self.assertRaises(ValueError): f.call(session)
                self.assertEqual(session.pending, {})
                self.assertFalse(list((f.root / 'knowledge').glob('native-publication-cache/*.json')))

    def test_runtime_or_tool_change_invalidates_reuse_and_registry_change_is_keyed(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(directory);f.populate();f.runtime['unicorn']['version'] = 'changed';f.new_args()
            with self.assertRaisesRegex(ValueError, 'runtime'): f.call(f.session())
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(directory);f.populate();f.tool_file.write_bytes(b'changed');f.new_args()
            with self.assertRaisesRegex(ValueError, 'tool'): f.call(f.session())
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(directory);f.populate();value = json.loads(f.registry_path.read_text());value['note'] = 'changed'
            f.registry_path.write_text(json.dumps(value));f.new_args();session = f.session()
            self.assertEqual(f.call(session), 'validated');session.finish();self.assertEqual(f.publish_count, 2)

    def test_unrelated_valid_index_row_does_not_invalidate_selected_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(directory);f.populate();other_sha = f.source(b'other valid release')
            c = dict(f.context_value, source_sha256=other_sha, source=f.source_path(other_sha))
            cp = COMMON.receipt(f.root, 'generated-native-contexts', c)
            rp = COMMON.receipt(f.root, 'native-adapter-checks', dict(f.report_value, source_sha256=other_sha, context_sha256=cp['sha256']))
            f.write_index([f.row(), dict(context=cp, check=rp, order=2)]);f.new_args();session = f.session()
            self.assertEqual(f.call(session), 'reused');session.finish();self.assertEqual(f.publish_count, 1)

    def test_different_valid_selected_row_requires_full_publish_then_repairs_exact_membership(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(directory);f.populate()
            other = COMMON.receipt(f.root, 'generated-native-contexts', dict(f.context_value, note='another valid context'))
            report = COMMON.receipt(f.root, 'native-adapter-checks', dict(f.report_value, context_sha256=other['sha256']))
            f.write_index([dict(context=other, check=report, order=1)]);f.new_args();session = f.session()
            self.assertEqual(f.call(session), 'validated');session.finish();self.assertEqual(f.publish_count, 2)
            self.assertEqual(json.loads(f.path.read_text())['contexts'][0], f.row())

    def test_lineage_rejects_outside_paths_conflicting_hashes_and_source_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(directory);session = f.session()
            with self.assertRaisesRegex(ValueError, 'outside reviewed'):
                session._lineage([], {str(f.tool_file): digest(f.tool_file)})
            with self.assertRaisesRegex(ValueError, 'Conflicting'):
                session._lineage([f.context], {f.context['path']: 'f' * 64})
            bad = COMMON.receipt(f.root, 'fixture-native-proofs', dict(source_sha256=f.sha, source=f.source_path(f.old_sha)))
            with self.assertRaisesRegex(ValueError, 'source path'): session._lineage([bad], {})

    def test_large_exports_are_hashed_without_json_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(directory);f.populate()
            self.assertEqual(f.publish_count, 1)

    def test_semantic_event_sources_are_pinned_metadata_not_executable_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(directory);session = f.session()
            report = COMMON.receipt(f.root, 'native-adapter-checks', dict(source_sha256=f.sha,
                cases=[dict(events=[dict(action='apply', source=label) for label in ('packet', 'empty_temporary')])],
                input=dict(source=f.source_path(f.sha))))
            files, _, sources = session._lineage([report], {})
            self.assertEqual(files[report['path']], report['sha256'])
            self.assertEqual(sources, {f.sha: f.source_path(f.sha)})
            # A source owned by an explicit SHA is always a client path.
            bad = COMMON.receipt(f.root, 'fixture-native-proofs', dict(source_sha256=f.sha, source='packet'))
            with self.assertRaisesRegex(ValueError, 'source path'): session._lineage([bad], {})

    def test_inherited_source_paths_still_reject_substitutions_and_relative_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(directory);session = f.session()
            for source in (f.source_path(f.old_sha), 'other.exe', 'relative/client', 'relative\\client', 'C:client', 'https:client'):
                with self.subTest(source=source):
                    bad = COMMON.receipt(f.root, 'fixture-native-proofs', dict(source_sha256=f.sha, input=dict(source=source)))
                    with self.assertRaisesRegex(ValueError, 'source path'): session._lineage([bad], {})

    def test_corrupted_validation_cache_is_a_blocker_and_not_silently_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(directory);f.populate();path = next((f.root / 'knowledge/native-publication-cache').glob('*.json'))
            pointer = json.loads(path.read_text());Path(pointer['path']).write_text('{}');f.new_args()
            with self.assertRaises(ValueError): f.call(f.session())
            self.assertEqual(f.publish_count, 1)

    def test_validation_receipt_and_lookup_remain_pinned_until_final_barrier(self):
        for which in ('receipt', 'lookup'):
            with self.subTest(which=which), tempfile.TemporaryDirectory() as directory:
                f = Fixture(directory);f.populate();f.new_args();session = f.session()
                self.assertEqual(f.call(session), 'reused')
                lookup = next((f.root / 'knowledge/native-publication-cache').glob('*.json'))
                receipt = Path(json.loads(lookup.read_text())['path'])
                (receipt if which == 'receipt' else lookup).write_text('{}')
                with self.assertRaisesRegex(ValueError, 'final barrier'): session.finish()
                self.assertEqual(session.metrics['receipts_written'], 0)

    def test_legacy_bare_tool_names_are_resolved_only_inside_tool_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(directory);session = f.session();path = CACHE.HERE / 'build-native-entry-code.py'
            old = COMMON.receipt(f.root, 'fixture-native-proofs', dict(tools={path.name: digest(path)}))
            files, _, _ = session._lineage([old], {})
            self.assertEqual(files[str(path.resolve())], digest(path))
            bad = COMMON.receipt(f.root, 'fixture-native-proofs', dict(tools={'../build-native-entry-code.py': digest(path)}))
            with self.assertRaisesRegex(ValueError, 'relative tool'): session._lineage([bad], {})

    def test_driver_indexes_are_closed_and_match_all_registered_families(self):
        driver = load('update-native-drivers')
        self.assertEqual(set(CACHE.INDEXES) - {'utf8'}, {row['family'] for row in driver.SPECS})
        self.assertEqual(CACHE.INDEXES['login-handler-early'], 'generated-login-handlers/login-handler-early')
        with tempfile.TemporaryDirectory() as directory:
            f = Fixture(directory);session = f.session()
            with self.assertRaises(ValueError): session._row('../custom', f.sha)
            with self.assertRaises(ValueError): CACHE.begin(f.index, SimpleNamespace(root=f.root, knowledge=f.knowledge), f.sha)


if __name__ == '__main__': unittest.main()
