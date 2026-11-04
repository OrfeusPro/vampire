"""Ordinary update scheduling and cached Quest dispatch report contracts."""

import copy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import test_vampir_quest_action_integration_v1 as action_integration
from test_vampir_update_contracts import load


DISPATCH = load('quest-dispatch-native-v1')
WORKFLOW = load('research-workflow')


class OrdinaryQuestDispatchIntegration(unittest.TestCase):
    def setUp(self):
        self.parent = action_integration.OrdinaryActionIntegration()
        self.parent.setUp()
        self.addCleanup(self.parent.doCleanups)
        self.f = self.parent.f
        self.selector = self.f.knowledge / 'quest-dispatch-native.json'
        self.selector.write_bytes(b'{}')
        self.report = dict(state='passed_bounded_native', recipe=DISPATCH.RECIPE, cases=332,
                           checks={'tutorial-dispatch': dict(state='passed', cases=192),
                                   'quest-sync-dispatch': dict(state='passed', cases=140)},
                           runtime_activated=False, profile_activated=False)

        def run(*args):
            self.parent.events.append('dispatch')
            return copy.deepcopy(self.report)

        def finalize(index, args, result):
            self.parent.events.append('dispatch-finalize')
            return dict(result, final_validation_completed=True)

        def publish(*args, **kwargs):
            self.parent.events.append('publish')
            return dict(queue=[])

        self.dispatch_run = Mock(side_effect=run)
        self.finalize = Mock(side_effect=finalize)
        self.publish = Mock(side_effect=publish)
        self.f.modules[DISPATCH.RECIPE] = SimpleNamespace(run=self.dispatch_run, finalize=self.finalize)
        self.f.modules['update-bundle'].publish = self.publish

    def test_runs_after_both_upstreams_and_finalizes_before_publication(self):
        result, record = self.parent.execute()
        self.assertEqual(self.dispatch_run.call_args.args[4:6], (self.parent.fixture.result, self.parent.action))
        self.assertEqual(self.parent.events, [
            'driver', 'seed', 'reader-transfer', 'action', 'wire', 'dispatch',
            'finalize', 'reader-finalize', 'action-finalize', 'wire-finalize', 'dispatch-finalize', 'publish',
        ])
        self.assertEqual(record['quest_dispatch_native'], dict(self.report, final_validation_completed=True))
        self.assertFalse(result['profile_activation'])

    def test_queues_only_the_failed_family(self):
        failed = dict(state='requires_review', reason='QuestSync receiver export does not match the source')
        self.report['state'] = 'requires_review'
        self.report['checks']['quest-sync-dispatch'] = failed
        result, record = self.parent.execute()
        blockers = [row for row in record['queue'] if row['reason'] == 'quest_dispatch_native_requires_review']
        self.assertEqual([(row['contract'], row['capability'], row['evidence']) for row in blockers],
                         [('quests', 'quest-sync-dispatch', failed)])
        self.assertEqual(result['state'], 'needs_review')
        self.assertFalse(result['profile_activation'])

    def test_dispatch_finalizer_failure_blocks_publication(self):
        self.finalize.side_effect = ValueError('Dispatch proof mutated')
        with self.assertRaisesRegex(ValueError, 'Dispatch proof mutated'):
            self.parent.execute()
        self.publish.assert_not_called()

    def test_absent_selector_keeps_upstream_checks_and_skips_dispatch(self):
        self.selector.unlink()
        _, record = self.parent.execute()
        self.dispatch_run.assert_not_called()
        self.finalize.assert_not_called()
        self.assertIn('quest_wire_native', record)
        self.assertNotIn('quest_dispatch_native', record)


class QuestDispatchReportIntegration(unittest.TestCase):
    def test_validator_rejects_report_type_and_metric_mutations(self):
        for family, (module, packet, calls) in DISPATCH.SPECS.items():
            cases = load(module)
            index = SimpleNamespace(extension={'research-workflow': WORKFLOW, module: cases}.__getitem__)
            context = dict(source_sha256='a' * 64, functions={'receiver': '0x1000'}, leaves={},
                           fixtures={'model': '0x2000'})
            inputs = dict(family=family, context=context)
            report = dict(schema=1, recipe=DISPATCH.RECIPE, method='bounded_native', family=family,
                          source_sha256=context['source_sha256'], packet_id=packet, network_used=False,
                          profile_activated=False, runtime_activated=False, inputs=inputs,
                          limits=DISPATCH.LIMITS[family], cases=cases.expected_cases(),
                          metrics=dict(call_counts=calls, abi_checks=calls, read_checks=2, write_checks=3,
                                       fixture_calls=DISPATCH.FIXTURE_CALLS[family],
                                       entry_counts={'0x1000': calls, '0x2000': DISPATCH.FIXTURE_CALLS[family]}))
            DISPATCH.validate_report(index, report, inputs)
            changes = (
                ('type', lambda value: value.update(packet_id=float(packet))),
                ('case', lambda value: value['cases'].pop()),
                ('abi', lambda value: value['metrics'].update(abi_checks=calls - 1)),
                ('fixture', lambda value: value['metrics']['entry_counts'].update({'0x2000': True})),
                ('unknown entry', lambda value: value['metrics']['entry_counts'].update({'0x3000': 1})),
                ('activation', lambda value: value.update(profile_activated=0)),
            )
            for name, mutate in changes:
                with self.subTest(family=family, mutation=name):
                    changed = copy.deepcopy(report)
                    mutate(changed)
                    with self.assertRaises(ValueError):
                        DISPATCH.validate_report(index, changed, inputs)


if __name__ == '__main__':
    unittest.main()
