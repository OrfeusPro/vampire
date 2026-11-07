"""Fail-closed checks for the bounded Dialog lifecycle proof contract."""
import csv
import io
import json
import unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


replay = load('replay-quest-dialogue-lifecycle-current-v1')
verifier = load('verify-quest-dialogue-lifecycle-current')
ROW = dict(task_id=110110030, quest_id=110110, index=2, class_info_id=1, dialog_group_id=11011110)


class ProofContractTests(unittest.TestCase):
    def context(self):
        return dict(schema=1, recipe=replay.RECIPE, source_sha256=replay.SOURCE,
                    roles=replay.ROLES.copy(), leaves=replay.LEAVES.copy())

    def receipt(self):
        return dict(recipe=replay.RECIPE, source_sha256=replay.SOURCE, task=ROW.copy(),
                    whole_functions=replay.ROLES.copy(), cases=[replay.expected(mode) for mode in replay.MODES],
                    limits=list(replay.LIMITS), native_execution=True, network_used=False,
                    action_admitted=False, dialogue_playback_verified=False,
                    native_entries={replay.ROLES['completion_schedule']: 6, replay.ROLES['delayed_callback']: 5,
                                    replay.ROLES['event_callback']: 3, replay.ROLES['completion']: 5,
                                    replay.ROLES['enqueue']: 4}, abi_checks=14, fixture_abi_checks=101)

    def test_fixture_receipt_cannot_claim_playback_or_runtime_admission(self):
        # Receipt validation is a separate boundary from producing native proof.
        # This synthetic dictionary is never published or counted as execution.
        for key in ('action_admitted', 'dialogue_playback_verified', 'network_used'):
            receipt = self.receipt()
            receipt[key] = True
            with self.subTest(key=key), self.assertRaises(ValueError):
                replay.validate(receipt, self.context(), ROW)

    def test_another_client_or_function_role_is_rejected(self):
        for key, value in (('source_sha256', '0' * 64), ('roles', dict(replay.ROLES, event_callback='0x1455d2dc1'))):
            context = self.context()
            context[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                replay.validate(self.receipt(), context, ROW)

    def test_queue_dedup_and_event_boundary_cannot_be_silently_widened(self):
        receipt = self.receipt()
        receipt['cases'][2]['pending_count'] = 2
        with self.assertRaises(ValueError):
            replay.validate(receipt, self.context(), ROW)
        receipt = self.receipt()
        receipt['cases'][-2]['start_forwards'] = 2
        with self.assertRaises(ValueError):
            replay.validate(receipt, self.context(), ROW)

    def csv(self, branches, *, reorder=False):
        stream = io.StringIO(newline='')
        writer = csv.DictWriter(stream, fieldnames=('Id', 'QuestInfoId', 'ServerServiceGroupId', 'Type', 'Param'))
        writer.writeheader()
        ids = list(verifier.TASKS)
        if reorder:
            ids[1], ids[2] = ids[2], ids[1]
        for task in ids:
            writer.writerow(dict(Id=task, QuestInfoId=110110, ServerServiceGroupId='', Type=6,
                                 Param=json.dumps(dict(type='Dialog', classBranch=branches))))
        return stream.getvalue().encode('utf-8')

    def test_task_index_and_unique_class_branch_are_required(self):
        branches = [dict(classInfoId='1', dialogGroupId=11011110)]
        self.assertEqual(verifier.read_row(self.csv(branches)), ROW)
        for raw in (self.csv(branches, reorder=True), self.csv(branches * 2),
                    self.csv([dict(classInfoId='1', dialogGroupId=11011112)])):
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                verifier.read_row(raw)


if __name__ == '__main__':
    unittest.main()
