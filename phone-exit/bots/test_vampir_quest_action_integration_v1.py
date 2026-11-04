"""Source-bound QuestUpdate orchestration, exact matrices and ordinary update guards."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from test_vampir_update_contracts import load
import test_vampir_quest_reader_transfer_v1 as fixtures
import test_vampir_quest_reader_transfer_integration as normal

ACTION = load('quest-action-transfer-v1')
WIRE = load('quest-wire-native-v1')
HARNESS = load('quest-packet-harness-v1')
CASES = load('quest-wire-cases-v1')
DIGEST = fixtures.seed_fixtures.digest
WORKFLOW = fixtures.WORKFLOW


class ActionFixture:
    def __init__(self, case):
        self.f = fixtures.QuestReaderTransferTests()
        self.f.setUp()
        case.addCleanup(self.f.doCleanups)
        self.reader = self.f.run_reader()
        self.seed = self.f.seed
        self.args, self.index, self.sha = self.f.args, self.f.index, self.f.sha
        self.root = self.f.root
        self.base = self.f.f
        self.selector = self.args.knowledge / 'quest-action-transfer.json'
        self.rule = dict(schema=1, recipe=ACTION.RECIPE, baselines={name: self.base.context(
            name + '.json', dict(source_sha256=self.base.old_sha, functions={'root': '0x140001000'}))
            for name in ACTION.BASELINES})
        self.selector.write_bytes(WORKFLOW.canonical(self.rule))
        self.rule_file = self.root / 'action-rules.py'
        self.rule_file.write_bytes(b'synthetic reviewed action rules')
        self.package = dict(target_source_sha256=self.sha, counts=dict(whole_roots=19),
            target_contexts={'quest-update-wire': dict(source_sha256=self.sha,
                functions={str(i): hex(0x140010000 + i * 256) for i in range(14)}),
                'tutorial-dispatch': dict(source_sha256=self.sha, functions={'handler': '0x140020000'})},
            native_consumer_verified=False, runtime_activated=False, profile_activated=False)
        self.rules = SimpleNamespace(tools=lambda: {str(self.rule_file): DIGEST(self.rule_file)},
            transfer=Mock(side_effect=lambda *args: copy.deepcopy(self.package)), validate_package=self.validate)
        proof = self.base.snapshot('archive-wire-proofs', dict(source_sha256=self.sha))
        self.output = dict(source_sha256=self.sha, family='archive-wire', transfer_proof=proof)
        self.context = self.base.snapshot('generated-native-contexts', self.output)
        self.check = self.base.snapshot('native-adapter-checks', dict(source_sha256=self.sha))
        self.archive = SimpleNamespace(ADAPTER='archive-wire-v1', SCOPE='bounded_native_archive_wire',
            tools=lambda: {}, report_valid=Mock())
        self.declaration = dict(id='native-auto-archive-wire', adapter=self.archive.ADAPTER,
            scope=self.archive.SCOPE, context=self.context, proof=proof, dependencies={})
        self.outcome = dict(id=self.declaration['id'], state='passed', scope=self.archive.SCOPE,
            report=self.check['path'], sha256=self.check['sha256'])
        original = self.index.extension
        self.index.extension = lambda name: {'quest-action-transfer-rules-v1': self.rules,
            'quest-packet-harness-v1': HARNESS, 'quest-reader-transfer-v1': fixtures.READER,
            'update-native-archive-wire': self.archive}.get(name) or original(name)
        self.journal = fixtures.seed_fixtures.Journal()

    def validate(self, package, inputs):
        if (package != self.package or package['target_source_sha256'] != inputs['target_source_sha256']
                or any(package[key] is not False for key in
                    ('native_consumer_verified', 'runtime_activated', 'profile_activated'))):
            raise ValueError('Synthetic action package scope differs')

    def run(self):
        return ACTION.run(self.index, self.args, self.sha, self.journal, self.seed, self.reader,
                          dict(checks=[self.declaration]), [self.outcome])


class ActionTransferTests(unittest.TestCase):
    def setUp(self):
        self.f = ActionFixture(self)

    def test_cold_and_warm_transfer_keep_runtime_admission_closed(self):
        first = self.f.run()
        self.assertEqual(first['state'], 'prepared_static', first)
        self.assertEqual(first, self.f.run())
        self.f.rules.transfer.assert_called_once()
        self.assertEqual(self.f.journal.actions, 1)
        final = ACTION.finalize(self.f.index, self.f.args, first)
        self.assertTrue(final['final_validation_completed'])
        self.assertFalse(final['native_consumer_verified'])
        self.assertFalse(final['runtime_activated'])

    def test_foreign_input_invocation_rejects_before_transfer(self):
        self.f.args.source_store = copy.copy(self.f.args.source_store)
        self.assertEqual(self.f.run()['state'], 'requires_review')
        self.f.rules.transfer.assert_not_called()

    def test_missing_or_failed_output_proof_does_not_transfer(self):
        self.f.outcome['state'] = 'failed'
        self.assertIn('output_proof', self.f.run()['reason'])
        self.f.rules.transfer.assert_not_called()

    def test_different_archive_source_rejects_without_transfer(self):
        self.f.output['source_sha256'] = self.f.base.old_sha
        self.f.declaration['context'] = self.f.base.snapshot('generated-native-contexts', self.f.output)
        self.assertEqual(self.f.run()['state'], 'requires_review')
        self.f.rules.transfer.assert_not_called()

    def test_closed_owner_is_rejected_before_transfer(self):
        owner = SimpleNamespace(closed=True, finished=False)
        self.f.args._scope_v2_state = dict(owner=owner)
        self.f.args._quest_input_seed_v2_state['owner'] = owner
        self.f.args._quest_reader_transfer_v1_state['owner'] = owner
        self.assertIn('owner', self.f.run()['reason'])
        self.f.rules.transfer.assert_not_called()

    def test_corrupt_cached_proof_never_silently_rebuilds(self):
        result = self.f.run()
        Path(result['report']).write_bytes(b'corrupt action proof')
        self.assertEqual(self.f.run()['state'], 'requires_review')
        self.f.rules.transfer.assert_called_once()

    def test_freshly_hashed_proof_cannot_coerce_scope_boolean_to_number(self):
        result = self.f.run()
        proof = json.loads(Path(result['report']).read_bytes())
        proof['native_consumer_verified'] = 0
        pointer = self.f.base.snapshot(ACTION.CATEGORY, proof)
        cached = next(iter(self.f.journal.values.values()))
        cached.update(proof=pointer, report=pointer['path'], sha256=pointer['sha256'])
        self.assertEqual(self.f.run()['state'], 'requires_review')
        self.f.rules.transfer.assert_called_once()

    def test_rule_change_invalidates_the_static_stage(self):
        first = self.f.run()
        self.f.rule_file.write_bytes(b'changed reviewed action rules')
        second = self.f.run()
        self.assertEqual(second['state'], 'prepared_static', second)
        self.assertNotEqual(first['proof'], second['proof'])
        self.assertEqual(self.f.rules.transfer.call_count, 2)

    def test_final_mutation_blocks_publication(self):
        result = self.f.run()
        self.f.rule_file.write_bytes(b'late code mutation')
        with self.assertRaises(ValueError):
            ACTION.finalize(self.f.index, self.f.args, result)

    def test_final_owner_must_be_the_original_finished_owner(self):
        owner = SimpleNamespace(closed=False, finished=False)
        self.f.args._scope_v2_state = dict(owner=owner)
        self.f.args._quest_input_seed_v2_state['owner'] = owner
        self.f.args._quest_reader_transfer_v1_state['owner'] = owner
        result = self.f.run()
        self.assertEqual(result['state'], 'prepared_static', result)
        with self.assertRaises(ValueError):
            ACTION.finalize(self.f.index, self.f.args, result)
        owner.finished = True
        self.assertTrue(ACTION.finalize(self.f.index, self.f.args, result)['final_validation_completed'])
        self.f.args._scope_v2_state['owner'] = SimpleNamespace(finished=True)
        with self.assertRaises(ValueError):
            ACTION.finalize(self.f.index, self.f.args, result)


class WireOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.f = ActionFixture(self)
        self.action = self.f.run()
        self.assertEqual(self.action['state'], 'prepared_static', self.action)
        self.index, self.args = self.f.index, self.f.args
        self.selector = self.args.knowledge / 'quest-wire-native.json'
        self.selector.write_bytes(WORKFLOW.canonical(dict(schema=1, recipe=WIRE.RECIPE, families=list(WIRE.FAMILIES))))
        self.tool = self.f.root / 'wire-worker.py'
        self.tool.write_bytes(b'synthetic wire worker')
        self.runtime = dict(files={str(self.f.base.runtime_file): DIGEST(self.f.base.runtime_file)})
        harness = SimpleNamespace(pointer_document=HARNESS.pointer_document, verify_files=HARNESS.verify_files,
            tools=lambda: {str(self.tool): DIGEST(self.tool)}, runtime_inputs=lambda: copy.deepcopy(self.runtime))
        export = self.f.root / 'ghidra/request-exports' / self.f.sha / 'run-wire-fixture' / 'details.json'
        export.parent.mkdir(parents=True)
        export.write_bytes(b'{}')
        self.export = dict(path=str(export), sha256=DIGEST(export))
        addresses = self.f.package['target_contexts']['quest-update-wire']['functions'].values()
        self.collector = SimpleNamespace(collect_batches=Mock(return_value=[
            dict(address=at, state='ready', artifacts=[self.export]) for at in addresses]))
        self.verify = Mock(side_effect=self.native_report)
        cases = SimpleNamespace(expected_cases=CASES.expected_cases, verify=self.verify)
        original = self.index.extension
        self.index.extension = lambda name: {'quest-wire-harness-v1': harness,
            'quest-wire-cases-v1': cases, 'update-run': self.collector}.get(name) or original(name)
        self.journal = fixtures.seed_fixtures.Journal()

    def native_report(self, harness, context, root, store):
        def metrics(scope, calls):
            return dict(execution_scope=scope, source_sha256=context['source_sha256'],
                target_exports_verified=True, native_execution=True, call_counts=calls, abi_checks=calls,
                read_checks=1, write_checks=1, fixture_calls=1, runtime_activated=False, profile_activated=False)
        return dict(cases=CASES.expected_cases(), whole_io=metrics('whole_io', 768),
            raw_failure=metrics('raw_failure', 24), source_sha256=context['source_sha256'],
            packet_id=1810, network_used=False, runtime_activated=False, profile_activated=False)

    def run_wire(self):
        return WIRE.run(self.index, self.args, self.f.sha, self.journal, self.action, self.f.root / 'selected.sqlite3')

    def test_one_native_stage_is_reused_and_finalized(self):
        first = self.run_wire()
        self.assertEqual(first['state'], 'passed_bounded_native', first)
        self.assertEqual(first['cases'], 117)
        self.assertEqual(first, self.run_wire())
        self.verify.assert_called_once()
        self.assertEqual(self.journal.actions, 1)
        self.assertTrue(WIRE.finalize(self.index, self.args, first)['final_validation_completed'])

    def test_missing_export_does_not_run_native(self):
        self.collector.collect_batches.return_value.pop()
        self.assertIn('exports_incomplete', self.run_wire()['reason'])
        self.verify.assert_not_called()

    def test_changed_native_code_invalidates_only_wire_stage(self):
        self.run_wire()
        self.tool.write_bytes(b'changed wire implementation')
        self.assertEqual(self.run_wire()['state'], 'passed_bounded_native')
        self.assertEqual(self.verify.call_count, 2)
        self.f.rules.transfer.assert_called_once()

    def test_corrupt_cached_native_report_does_not_replay(self):
        result = self.run_wire()
        Path(result['checks']['quest-update-wire']['report']).write_bytes(b'corrupt wire report')
        self.assertEqual(self.run_wire()['state'], 'requires_review')
        self.verify.assert_called_once()

    def test_native_failure_is_a_specific_blocker(self):
        self.verify.side_effect = ValueError('QuestUpdate failure index 4 escaped a write guard')
        result = self.run_wire()
        self.assertEqual(result['state'], 'requires_review')
        self.assertIn('failure index 4', result['reason'])

    def test_freshly_hashed_native_report_must_match_exact_case_types(self):
        result = self.run_wire()
        report = json.loads(Path(result['checks']['quest-update-wire']['report']).read_bytes())
        changes = (lambda r: r['cases']['prefixes'][0].update(accepted=0),
                   lambda r: r['cases']['valid'].pop(),
                   lambda r: r['raw_failure'].update(call_counts=True),
                   lambda r: r['whole_io'].update(abi_checks=24),
                   lambda r: r.update(packet_id=1810.0),
                   lambda r: r.update(profile_activated=True),
                   lambda r: r['exports'][0].update(sha256='0' * 64))
        for change in changes:
            with self.subTest(change=change):
                altered = copy.deepcopy(report)
                change(altered)
                with self.assertRaises(ValueError):
                    WIRE.validate_report(self.index, altered, report['inputs']['context'], report['inputs'])

    def test_late_runtime_change_blocks_final_publication(self):
        result = self.run_wire()
        self.runtime['version'] = 'changed runtime'
        with self.assertRaises(ValueError):
            WIRE.finalize(self.index, self.args, result)

    def test_final_store_identity_cannot_be_replaced(self):
        result = self.run_wire()
        self.args.source_store = copy.copy(self.args.source_store)
        with self.assertRaises(ValueError):
            WIRE.finalize(self.index, self.args, result)


class OrdinaryActionIntegration(unittest.TestCase):
    def setUp(self):
        self.fixture = normal.QuestReaderTransferIntegration()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f, self.events = self.fixture.f, self.fixture.events
        for name in ('quest-action-transfer.json', 'quest-wire-native.json'):
            (self.f.knowledge / name).write_bytes(b'{}')
        self.action = dict(state='prepared_static', runtime_activated=False, profile_activated=False)
        self.wire = dict(state='passed_bounded_native', cases=117, runtime_activated=False, profile_activated=False)
        def action(*args):
            self.events.append('action')
            return copy.deepcopy(self.action)
        def wire(*args):
            self.events.append('wire')
            return copy.deepcopy(self.wire)
        def finish(name):
            def validate(index, args, result):
                self.events.append(name + '-finalize')
                return dict(result, final_validation_completed=True)
            return validate
        self.action_run = Mock(side_effect=action)
        self.wire_run = Mock(side_effect=wire)
        self.action_final = Mock(side_effect=finish('action'))
        self.wire_final = Mock(side_effect=finish('wire'))
        self.f.modules['quest-action-transfer-v1'] = SimpleNamespace(run=self.action_run, finalize=self.action_final)
        self.f.modules['quest-wire-native-v1'] = SimpleNamespace(run=self.wire_run, finalize=self.wire_final)

    def execute(self):
        result, _ = self.f.run_fixture()
        return result, json.loads(Path(result['run']).read_bytes())['payload']

    def test_ordinary_path_orders_dependencies_and_final_guards(self):
        result, record = self.execute()
        self.assertEqual(self.events, ['driver', 'seed', 'reader-transfer', 'action', 'wire',
                                      'finalize', 'reader-finalize', 'action-finalize', 'wire-finalize'])
        self.assertEqual(self.action_run.call_args.args[5], self.fixture.result)
        self.assertEqual(self.wire_run.call_args.args[4], self.action)
        self.assertEqual(record['quest_wire_native'], dict(self.wire, final_validation_completed=True))
        self.assertFalse(result['profile_activation'])

    def test_native_blocker_is_exposed_without_quest_admission(self):
        self.wire.update(state='requires_review', reason='Writer layout changed')
        result, record = self.execute()
        rows = [row for row in record['queue'] if row.get('reason') == 'quest_wire_native_requires_review']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['evidence'], self.wire)
        self.assertEqual(result['state'], 'needs_review')

    def test_failed_final_guard_stops_bundle_publication(self):
        publish = Mock()
        self.f.modules['update-bundle'].publish = publish
        self.wire_final.side_effect = ValueError('Wire proof mutated')
        with self.assertRaisesRegex(ValueError, 'Wire proof mutated'):
            self.execute()
        publish.assert_not_called()

    def test_absent_action_selector_skips_both_new_stages(self):
        (self.f.knowledge / 'quest-action-transfer.json').unlink()
        _, record = self.execute()
        self.action_run.assert_not_called()
        self.wire_run.assert_not_called()
        self.assertNotIn('quest_action_transfer', record)

    def test_plan_only_runs_neither_action_nor_native_cases(self):
        self.f.args.plan_only = True
        result, _ = self.execute()
        self.assertEqual(result['state'], 'planned')
        self.assertEqual(self.events, [])


if __name__ == '__main__':
    unittest.main()
