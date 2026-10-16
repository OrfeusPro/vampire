import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).parent / 'vampir'
spec = importlib.util.spec_from_file_location('messages', ROOT / 'messages.py')
messages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(messages)


class Messages(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / 'vision.json').read_text('utf-8'))
        self.config['_prepared_scale'] = 1
        self.state, self.taps = {}, []
        self.visible = {'idle_disconnected', 'connection_terminated_confirm'}
        self.button = [640, 448]

    def match(self, name):
        return dict(found=name in self.visible,
                    point=self.button if name == 'connection_terminated_confirm' else [640, 320])

    def call(self, command, **args):
        self.taps.append((command, args))

    def tick(self, now=1000):
        return messages.tick(self, self.state, dict(width=1280, height=720),
                             self.config, self.match, now)

    def test_once_and_unknown_outcome(self):
        self.assertEqual(self.tick()['step'], 'message_confirm_wait')
        self.tick(1001)
        self.assertEqual(self.tick(1012)['error'], 'message_confirm_outcome_unknown')
        self.assertEqual(len(self.taps), 1)

    def test_disappeared_then_reappeared_never_repeated(self):
        self.tick()
        self.visible = set()
        self.assertEqual(self.tick(1003)['step'], 'message_confirm_dismissed')
        self.assertIsNone(self.tick(1004))
        self.visible = {'idle_disconnected', 'connection_terminated_confirm'}
        self.assertEqual(self.tick(1005)['step'], 'message_confirm_reappeared')
        self.assertEqual(len(self.taps), 1)

    def test_button_without_message(self):
        self.visible = {'connection_terminated_confirm'}
        self.assertIsNone(self.tick())
        self.assertFalse(self.taps)

    def test_missing_button_pauses(self):
        self.visible = {'idle_disconnected'}
        self.assertTrue(self.tick()['pause'])
        self.assertFalse(self.taps)

    def test_wrong_geometry_pauses(self):
        self.button = [900, 448]
        self.assertEqual(self.tick()['step'], 'message_confirm_geometry_unknown')
        self.assertFalse(self.taps)

    def test_uncertain_ipc_is_not_repeated(self):
        def fail(command, **args):
            self.taps.append((command, args))
            raise RuntimeError('timeout')
        self.call = fail
        self.assertTrue(self.tick()['pause'])
        self.tick(1012)
        self.assertEqual(len(self.taps), 1)


if __name__ == '__main__':
    unittest.main()
