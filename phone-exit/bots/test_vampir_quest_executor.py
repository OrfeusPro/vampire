import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('executor', Path(__file__).parent / 'vampir/quest_executor.py')
executor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(executor)


class Host:
    def __init__(self, mode='ok'):
        self.mode, self.calls = mode, []

    def call(self, command, **args):
        self.calls.append((command, args))
        if self.mode == 'lost_ack':
            raise RuntimeError('transport_timeout_after_input')
        return {'performed': self.mode != 'rejected'}


class QuestExecutor(unittest.TestCase):
    def setUp(self):
        self.host, self.records = Host(), {}
        self.frame = {'width': 1280, 'height': 720}
        self.button = {'rect': [500, 300, 600, 400]}
        self.policy = {'id': 'control', 'retry_wait_sec': 8, 'max_attempts': 2}

    def execute(self, now=1000):
        return executor.execute(self.host, self.records, self.button, self.frame, now,
                                [550, 350], self.policy)

    def test_lost_android_ack_never_repeats_even_after_wait(self):
        self.host.mode = 'lost_ack'
        self.assertEqual(self.execute()['error'], 'quest_input_outcome_unknown')
        self.assertEqual(self.execute(1030)['error'], 'quest_input_outcome_unknown')
        self.assertEqual(len(self.host.calls), 1)

    def test_reservation_exists_before_android_receives_input(self):
        outer = self
        class InspectHost:
            def call(self, command, **args):
                outer.assertEqual(outer.records['control']['outcome'], 'unknown')
                return {'performed': True}
        self.host = InspectHost()
        self.assertEqual(self.execute()['phase'], 'sent')
        self.assertEqual(self.records['control']['outcome'], 'input_acknowledged')

    def test_slow_device_waits_then_stuck_control_has_bounded_attempts(self):
        self.execute()
        for now in (1001, 1003, 1007):
            self.assertEqual(self.execute(now)['phase'], 'wait')
        self.assertEqual(self.execute(1008)['phase'], 'sent')
        self.assertEqual(self.execute(1016)['phase'], 'exhausted')
        self.assertEqual(len(self.host.calls), 2)

    def test_one_attempt_action_cannot_repeat(self):
        self.policy['max_attempts'] = 1
        self.execute()
        self.assertEqual(self.execute(1020)['phase'], 'exhausted')
        self.assertEqual(len(self.host.calls), 1)

    def test_invalid_or_out_of_screen_geometry_never_reaches_android(self):
        for rect in (None, [0, 0, 500, 720], [0, 0, 1500, 720], [0, 0, float('nan'), 720]):
            self.button['rect'] = rect
            self.assertEqual(self.execute()['error'], 'quest_target_geometry')
        self.assertEqual(self.host.calls, [])
        self.assertEqual(self.records, {})

    def test_source_link_is_stored_without_claiming_quest_completion(self):
        source = {'step_id': '4002004', 'expected_next_observation': '4002006'}
        executor.execute(self.host, self.records, self.button, self.frame, 1000,
                         [550, 350], self.policy, source)
        self.assertEqual(self.records['control']['source_step'], '4002004')
        self.assertEqual(self.records['control']['expected_source_step'], '4002006')
        self.assertNotIn('quest_completed', self.records['control'])

    def test_rejected_input_pauses_instead_of_claiming_success(self):
        self.host.mode = 'rejected'
        self.assertEqual(self.execute()['error'], 'quest_input_rejected')
        self.assertEqual(self.records['control']['outcome'], 'rejected')


if __name__ == '__main__':
    unittest.main()
