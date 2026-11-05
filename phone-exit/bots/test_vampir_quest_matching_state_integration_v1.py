"""Quest matching-state update ordering and exact cached-report contracts."""
import copy
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import test_vampir_quest_action_integration_v1 as action_integration
from test_vampir_update_contracts import load


STATE = load('quest-matching-state-native-v1')
CASES = load('quest-matching-state-cases-v1')
WORKFLOW = load('research-workflow')


class OrdinaryQuestMatchingStateIntegration(unittest.TestCase):
    def setUp(self):
        self.parent = action_integration.OrdinaryActionIntegration()
        self.parent.setUp()
        self.addCleanup(self.parent.doCleanups)
        self.f = self.parent.f
        reader_run = self.f.modules['quest-reader-transfer-v1'].run
        original_reader = reader_run.side_effect

        def capture_reader(*args):
            self.reader_result = original_reader(*args)
            return self.reader_result

        reader_run.side_effect = capture_reader
        self.selector = self.f.knowledge / 'quest-matching-state-native.json'
        self.selector.write_bytes(b'{}')
        self.report = dict(state='passed_bounded_native', recipe=STATE.RECIPE,
            checks={family: dict(state='passed', cases=len(CASES.expected_cases(family)))
                    for family in STATE.FAMILIES},
            cases=sum(len(CASES.expected_cases(family)) for family in STATE.FAMILIES),
            runtime_activated=False, profile_activated=False)

        def execute(*args):
            self.parent.events.append('matching-state')
            return copy.deepcopy(self.report)

        def finalize(index, args, result):
            self.parent.events.append('matching-state-finalize')
            return dict(result, final_validation_completed=True)

        def publish(*args, **kwargs):
            self.parent.events.append('publish')
            return dict(queue=[])

        self.state_run = Mock(side_effect=execute)
        self.finalize = Mock(side_effect=finalize)
        self.publish = Mock(side_effect=publish)
        self.f.modules[STATE.RECIPE] = SimpleNamespace(run=self.state_run, finalize=self.finalize)
        self.f.modules['update-bundle'].publish = self.publish

    def test_ordinary_path_uses_current_reader_and_finalizes_before_publication(self):
        result, record = self.parent.execute()
        args = self.state_run.call_args.args
        self.assertEqual(len(args), 6)
        self.assertIs(args[1], self.f.args)
        self.assertEqual(args[4], self.parent.fixture.result)
        self.assertIs(args[4], self.reader_result)
        self.assertEqual(self.parent.events, [
            'driver', 'seed', 'reader-transfer', 'action', 'wire', 'matching-state',
            'finalize', 'reader-finalize', 'action-finalize', 'wire-finalize',
            'matching-state-finalize', 'publish',
        ])
        self.assertEqual(record['quest_matching_state_native'], dict(self.report, final_validation_completed=True))
        self.assertFalse(result['profile_activation'])

    def test_only_failed_family_is_queued(self):
        failed = dict(state='requires_review', reason='Quest progress layout changed')
        self.report['state'] = 'requires_review'
        self.report['checks']['quest-matching-state'] = failed
        result, record = self.parent.execute()
        blockers = [row for row in record['queue'] if row['reason'] == 'quest_matching_state_requires_review']
        self.assertEqual([(row['contract'], row['capability'], row['evidence']) for row in blockers],
                         [('quests', 'quest-matching-state', failed)])
        self.assertEqual(result['state'], 'needs_review')
        self.assertFalse(result['profile_activation'])

    def test_final_guard_failure_prevents_bundle_publication(self):
        self.finalize.side_effect = ValueError('Quest matching-state proof changed')
        with self.assertRaisesRegex(ValueError, 'Quest matching-state proof changed'):
            self.parent.execute()
        self.publish.assert_not_called()

    def test_absent_selector_skips_state_and_preserves_upstream_checks(self):
        self.selector.unlink()
        _, record = self.parent.execute()
        self.state_run.assert_not_called()
        self.finalize.assert_not_called()
        self.assertIn('quest_wire_native', record)
        self.assertNotIn('quest_matching_state_native', record)

    def test_plan_only_does_not_execute_or_finalize_state(self):
        self.f.args.plan_only = True
        result, _ = self.parent.execute()
        self.assertEqual(result['state'], 'planned')
        self.state_run.assert_not_called()
        self.finalize.assert_not_called()
        self.publish.assert_not_called()
        self.assertEqual(self.parent.events, [])


class QuestMatchingStateReportContracts(unittest.TestCase):
    def valid_report(self, family):
        context = dict(source_sha256='a' * 64, functions={'apply': '0x1000'}, leaves={},
                       fixtures={'allocation': '0x2000'})
        inputs = dict(family=family, context=context)
        calls = CASES.expected_calls(family)
        report = dict(schema=1, recipe=STATE.RECIPE, family=family, method='bounded_native',
            source_sha256=context['source_sha256'], cases=CASES.expected_cases(family), inputs=inputs,
            limits=STATE.LIMITS[family], runtime_activated=False, profile_activated=False, network_used=False,
            metrics=dict(call_counts=calls, abi_checks=calls, read_checks=2, write_checks=3, fixture_calls=STATE.FIXTURE_CALLS[family],
                         entry_counts={'0x1000': calls, '0x2000': STATE.FIXTURE_CALLS[family]}))
        index = SimpleNamespace(extension={'research-workflow': WORKFLOW,
            'quest-matching-state-cases-v1': CASES}.__getitem__)
        return index, report, inputs

    def test_exact_case_matrix_and_scope_value_types_are_required(self):
        for family in STATE.FAMILIES:
            index, report, inputs = self.valid_report(family)
            STATE.validate_report(index, report, inputs)
            changes = (
                ('missing case', lambda row: row['cases'].pop()),
                ('duplicate case', lambda row: row['cases'].append(copy.deepcopy(row['cases'][0]))),
                ('boolean schema', lambda row: row.update(schema=True)),
                ('scope coercion', lambda row: row.update(profile_activated=0)),
                ('other source', lambda row: row.update(source_sha256='b' * 64)),
            )
            for name, mutate in changes:
                with self.subTest(family=family, change=name):
                    changed = copy.deepcopy(report)
                    mutate(changed)
                    with self.assertRaises(ValueError):
                        STATE.validate_report(index, changed, inputs)

    def test_metrics_require_expected_call_counts_and_declared_native_entries(self):
        for family in STATE.FAMILIES:
            index, report, inputs = self.valid_report(family)
            calls = CASES.expected_calls(family)
            changes = (
                ('wrong call count', lambda row: row['metrics'].update(call_counts=calls - 1)),
                ('float ABI count', lambda row: row['metrics'].update(abi_checks=float(calls))),
                ('missing native function', lambda row: row['metrics']['entry_counts'].pop('0x1000')),
                ('unknown native entry', lambda row: row['metrics']['entry_counts'].update({'0x3000': 1})),
                ('boolean fixture count', lambda row: row['metrics']['entry_counts'].update({'0x2000': True})),
                ('fixture sum', lambda row: row['metrics'].update(fixture_calls=2)),
            )
            for name, mutate in changes:
                with self.subTest(family=family, change=name):
                    changed = copy.deepcopy(report)
                    mutate(changed)
                    with self.assertRaises(ValueError):
                        STATE.validate_report(index, changed, inputs)

    def test_cached_outcome_must_match_the_checked_report(self):
        index, report, inputs = self.valid_report('quest-matching-state')
        original = index.extension
        helper = SimpleNamespace(pointer_document=Mock(return_value=report))
        index.extension = lambda name: helper if name == 'quest-wire-harness-v1' else original(name)
        outcome = dict(state='passed', report='checked-report', sha256='c' * 64, cases=len(report['cases']))
        root = Path('checked-library')
        self.assertIs(STATE.read_check(index, root, outcome, inputs), report)
        for changed in (dict(outcome, cases=outcome['cases'] - 1), dict(outcome, cases=float(outcome['cases'])),
                        dict(outcome, state='ready'), dict(outcome, unreviewed=True)):
            with self.subTest(outcome=changed):
                with self.assertRaisesRegex(ValueError, 'journal outcome differs'):
                    STATE.read_check(index, root, changed, inputs)


class MatchingCallbackProvenance(unittest.TestCase):
    def test_shared_sentinel_observes_actual_return_pc_before_comparing_transition(self):
        context = dict(functions={'state': '0x1000', 'progress': '0x2000'},
            leaf_roles={'copy': '0x3000', 'index_getter': '0x4000'},
            fixtures={'task_start': hex(CASES.CALLBACK), 'task_update': hex(CASES.CALLBACK)},
            callback_returns={'task_start': '0x1010', 'task_update': '0x2020'})
        # The first matrix row expects update. Drive only the callback boundary
        # with copied bytes and old state intact, then reject the wrong trace.
        for returning, message, finished in (
                (0x9999, 'callback return PC differs', False),
                (0x1010, 'actual native callback branch differs', True)):
            with self.subTest(returning=hex(returning)):
                memory = {}
                scratch, stack = 0x28000000, 0x28038008

                def write(address, data):
                    memory.update((address + offset, value) for offset, value in enumerate(data))

                def read(address, size):
                    return bytes(memory.get(address + offset, 0) for offset in range(size))

                uc = SimpleNamespace(mem_write=write, mem_read=read,
                    reg_read=lambda register: stack if register == 1 else scratch + 0x3000)
                callbacks = {}
                harness = SimpleNamespace(uc=uc, x=SimpleNamespace(UC_X86_REG_RSP=1, UC_X86_REG_RCX=2),
                    scratch=scratch, entry_counts={}, available_fixtures={CASES.CALLBACK},
                    finish=Mock(), reset_regions=Mock(), allow_read=Mock(), allow_write=Mock(),
                    add_fixture=lambda address, callback: callbacks.setdefault(address, callback))

                def enter_state(address, receiver, *, rdx, r8, budget):
                    self.assertEqual(address, 0x1000)
                    write(scratch + 0x3020, read(r8, 32))
                    write(stack, struct.pack('<Q', returning))
                    callbacks[CASES.CALLBACK](uc)

                harness.call = enter_state
                with self.assertRaisesRegex(ValueError, message):
                    CASES.verify(harness, context)
                self.assertEqual(harness.finish.call_count, int(finished))


if __name__ == '__main__':
    unittest.main()
