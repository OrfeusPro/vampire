"""Discovery hints can avoid work, but cannot grant resource admission."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_vampir_update_run as fixtures


class ResourceReadinessV2Tests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.UpdateRunTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        for name in ('root', 'args', 'api', 'engine', 'workflow'):
            setattr(self, name, getattr(self.fixture, name))
        self.module = self.fixture.index.extension('resource-readiness-v2')
        self.row = dict(path=str(self.root/'example.pak'),
            current=dict(sha256='a'*64, size=10, pak_version=11),
            baseline=dict(sha256='b'*64, size=10, pak_version=11))
        self.contracts = dict(contracts=[dict(resources=[dict(archive='*.pak', path='*')])])
        self.report = dict(exe=dict(sha256='c'*64), files=[self.row])

    def save(self, *, state='passed', inputs=None, outputs=None):
        inputs = inputs or self.engine.resource_stage_inputs(self.api, self.args, self.row, {})
        name = 'resource-'+self.engine.hashlib.sha256(self.row['path'].encode()).hexdigest()[:16]
        key = self.engine.fingerprint(self.workflow, dict(stage=name, inputs=inputs))
        if outputs is None:
            output = self.root/'output.json'; output.write_text('{}', 'utf-8')
            outputs = {str(output): self.api.digest(output)}
        entry = dict(key=key, inputs=inputs, state='completed', result=dict(state=state), outputs=outputs)
        target = self.workflow.snapshot(self.root, 'update-stages', entry)
        path = self.root/'knowledge/update-stage-cache'/(key+'.json')
        self.workflow.atomic(path, self.workflow.canonical(dict(report=str(target))))
        return target, entry

    def work(self, changed=()):
        self.args.resource_candidates = self.module.Candidates(self.api, self.args)
        return self.engine.resource_work(self.api, self.args, self.report, self.contracts, changed, {})

    def test_no_hint_never_reads_historical_material_to_discover_a_miss(self):
        with patch.object(self.engine, 'resource_stage_inputs', side_effect=AssertionError('No candidate')):
            self.assertEqual(self.work(), [self.row])
        self.assertEqual(self.args.resource_candidates.metrics['material_scans_avoided'], 1)

    def test_failed_stage_is_pending_without_rehashing_its_old_inputs(self):
        self.save(state='requires_review')
        with patch.object(self.engine, 'resource_stage_inputs', side_effect=AssertionError('Not ready')):
            self.assertEqual(self.work(), [self.row])

    def test_selected_changed_archive_skips_redundant_readiness_lookup(self):
        with patch.object(self.engine, 'resource_stage_inputs', side_effect=AssertionError('Already pending')):
            self.assertEqual(self.work([self.row]), [self.row])
        self.assertEqual(self.args.resource_candidates.metrics['discovery_reads'], 0)

    def test_passed_hint_still_runs_full_material_key_and_output_checks(self):
        self.save()
        with patch.object(self.engine, 'resource_stage_inputs', wraps=self.engine.resource_stage_inputs) as build:
            self.assertEqual(self.work(), [])
        self.assertEqual(build.call_count, 1)
        (self.root/'output.json').write_text('[]', 'utf-8')
        with self.assertRaisesRegex(ValueError, 'output changed'):
            self.work()

    def test_forged_hint_cannot_grant_ready_without_matching_actual_cache_key(self):
        inputs = self.engine.resource_stage_inputs(self.api, self.args, self.row, {})
        inputs['historical']['forged'] = 'e'*64
        self.save(inputs=inputs)
        self.assertEqual(self.work(), [self.row])

    def test_changed_selected_blob_invalidates_passed_candidate(self):
        entries = self.root/'pak-extracted/example/entries.json'; entries.parent.mkdir(parents=True)
        blob = entries.parent/'blob.bin'; blob.write_bytes(b'one')
        entries.write_text(json.dumps([dict(saved=str(blob))]), 'utf-8')
        self.save(); blob.write_bytes(b'two')
        self.assertEqual(self.work(), [self.row])

    def test_changed_material_tools_or_source_is_negative_before_expensive_scan(self):
        original = self.engine.resource_stage_inputs(self.api, self.args, self.row, {})
        variants = [dict(original, current=dict(original['current'], sha256='d'*64)),
            dict(original, baseline=dict(original['baseline'], sha256='d'*64)),
            dict(original, tools=dict(recipe='changed')),
            dict(original, config_source_sha256='d'*64),
            dict(original, incomplete_material_audit_sha256='d'*64)]
        for value in variants:
            with self.subTest(value=list(value)):
                self.save(inputs=value)
        with patch.object(self.engine, 'resource_stage_inputs', side_effect=AssertionError('No matching hint')):
            self.assertEqual(self.work(), [self.row])

    def test_invalid_or_escaping_discovery_pointer_only_leaves_pending(self):
        directory = self.root/'knowledge/update-stage-cache'; directory.mkdir(parents=True)
        (directory/'invalid.json').write_text('not json', 'utf-8')
        outside = self.root/'untrusted.json'; outside.write_text('{}', 'utf-8')
        (directory/'outside.json').write_text(json.dumps(dict(report=str(outside))), 'utf-8')
        (directory/'other-recipe.json').write_text(json.dumps(dict(report=dict(path=str(outside)))), 'utf-8')
        self.assertEqual(self.work(), [self.row])
        self.assertEqual(self.args.resource_candidates.metrics['invalid_hints'], 1)

    def test_next_invocation_discovers_new_completed_stage(self):
        self.assertEqual(self.work(), [self.row])
        self.save()
        self.assertEqual(self.work(), [])

    def test_discovery_is_once_per_invocation_and_never_calls_native(self):
        self.save(state='requires_review')
        candidates = self.module.Candidates(self.api, self.args)
        self.assertFalse(candidates.possible(self.row, {}))
        reads = candidates.metrics['discovery_reads']
        self.assertFalse(candidates.possible(copy.deepcopy(self.row), {}))
        self.assertEqual(candidates.metrics['discovery_reads'], reads)

    def test_new_failed_resource_stage_is_not_cached_if_input_barrier_fails(self):
        scope = SimpleNamespace(validate=lambda row: (_ for _ in ()).throw(ValueError('changed input')))
        self.args.resource_scope = scope
        record = dict(stages={}, state='running')
        journal = self.engine.Journal(self.api, self.workflow, self.args, record, self.root/'journal.json')
        with patch.object(self.engine, 'resource_step', return_value=dict(state='requires_review')):
            with self.assertRaisesRegex(ValueError, 'changed input'):
                journal.stage('resource-fixture', {}, lambda: self.engine.checked_resource_step(
                    self.api, None, self.workflow, self.args, self.root/'audit.json', self.row))
        self.assertEqual(record['stages']['resource-fixture']['state'], 'failed')
        self.assertFalse(list((self.root/'knowledge/update-stage-cache').glob('*.json')))

    def test_final_barrier_rejects_historical_change_during_bundle_preparation(self):
        extension = self.api.extension
        module = extension('resource-planning-v2')
        def scope_factory(index, args):
            scope = module.Scope(index, args)
            scope.table_baseline(self.row)  # Pin absence before bundle.prepare.
            return scope
        self.api.extension = lambda name: (SimpleNamespace(Scope=scope_factory)
            if name == 'resource-planning-v2' else extension(name))
        (self.fixture.knowledge/'update-engine.json').write_bytes((self.api.HERE/'knowledge/update-engine.json').read_bytes())
        publisher = self.fixture.modules['update-bundle']
        publisher.publish = unittest.mock.Mock(side_effect=AssertionError('No publication after mutation'))
        def prepare(*args):
            path = self.root/'table-study/index.json'; path.parent.mkdir(parents=True)
            path.write_text('{"tables":[]}', 'utf-8')
            return dict(bundles=[], next_profiles={}, queue=[], live_verified=False)
        publisher.prepare = prepare
        with self.assertRaisesRegex(ValueError, 'appeared or disappeared'):
            self.fixture.run_fixture()
        publisher.publish.assert_not_called()


if __name__ == '__main__':
    unittest.main()
