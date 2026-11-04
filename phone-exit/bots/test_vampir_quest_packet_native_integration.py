"""Normal update reaches bounded native packets and validates before publication."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import test_vampir_quest_reader_transfer_integration as fixtures


class PacketNativeIntegration(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.QuestReaderTransferIntegration()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture.f
        self.events = self.fixture.events
        (self.f.knowledge / 'quest-packet-native.json').write_text('{}', encoding='utf-8')
        self.result = dict(state='passed_bounded_native', cases=1178,
                           runtime_activated=False, profile_activated=False)
        def run(*args):
            self.events.append('packets')
            return copy.deepcopy(self.result)
        def finalize(index, args, result):
            self.events.append('packet-finalize')
            return dict(result, final_validation_completed=True)
        self.run = Mock(side_effect=run)
        self.finalize = Mock(side_effect=finalize)
        self.f.modules['quest-packet-native-v1'] = SimpleNamespace(run=self.run, finalize=self.finalize)

    def execute(self):
        result, _ = self.f.run_fixture()
        return result, json.loads(Path(result['run']).read_bytes())['payload']

    def test_ordinary_path_runs_packets_after_readers_and_finalizes_before_publish(self):
        result, record = self.execute()
        self.assertEqual(self.events, ['driver', 'seed', 'reader-transfer', 'packets', 'finalize', 'reader-finalize', 'packet-finalize'])
        self.assertEqual(self.run.call_args.args[4], self.fixture.result)
        self.assertEqual(record['quest_packet_native'], dict(self.result, final_validation_completed=True))
        self.assertFalse(result['profile_activation'])

    def test_failed_case_is_exposed_as_a_packet_blocker(self):
        self.result.update(state='requires_review', reason='Truncated record wrote out of bounds')
        result, record = self.execute()
        blockers = [row for row in record['queue'] if row.get('reason') == 'quest_packet_native_requires_review']
        self.assertEqual(len(blockers), 1)
        self.assertEqual(blockers[0]['evidence'], self.result)
        self.assertEqual(result['state'], 'needs_review')

    def test_late_native_report_change_prevents_publish(self):
        publish = Mock()
        self.f.modules['update-bundle'].publish = publish
        self.finalize.side_effect = ValueError('Native report changed after execution')
        with self.assertRaisesRegex(ValueError, 'Native report changed'):
            self.execute()
        publish.assert_not_called()

    def test_absent_selector_keeps_packet_stage_optional(self):
        (self.f.knowledge / 'quest-packet-native.json').unlink()
        _, record = self.execute()
        self.run.assert_not_called()
        self.finalize.assert_not_called()
        self.assertNotIn('quest_packet_native', record)

    def test_plan_only_does_not_execute_packets(self):
        self.f.args.plan_only = True
        result, _ = self.execute()
        self.assertEqual(result['state'], 'planned')
        self.assertEqual(self.events, [])


if __name__ == '__main__':
    unittest.main()
