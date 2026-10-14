import importlib.util
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent / 'rfonlinenext'
spec = importlib.util.spec_from_file_location('rfnext', ROOT / 'bot.py')
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)


class Host:
    def __init__(self):
        self.package = 'net.phoneexit'
        self.visible = set()
        self.calls = []

    def call(self, command, **args):
        self.calls.append((command, args))
        if command == 'foreground':
            return {'package': self.package}
        if command == 'match':
            return {'found': args['name'] in self.visible, 'point': [400, 300]}
        if command == 'capture':
            return {'width': 1280, 'height': 576}
        return {}


class Launch(unittest.TestCase):
    def setUp(self):
        self.host = Host()
        self.state = {}
        self.settings = {'autostart_enabled': True}
        self.now = 1000

    def tick(self, visible=(), after=1):
        self.now += after
        self.host.visible = set(visible)
        if 'touch_to_start' in self.host.visible:
            self.host.visible.add('title_account')
        with patch.object(bot.time, 'monotonic', return_value=self.now):
            return bot.tick(self.host, self.settings, self.state, str(ROOT))

    def test_full_entry_and_no_input_on_loaded_character(self):
        self.assertEqual(self.tick()['step'], 'launch_game')
        self.host.package = bot.PACKAGE
        self.assertEqual(self.tick()['step'], 'waiting_game_entry')
        self.assertEqual(self.tick(['touch_to_start'])['step'], 'press_touch_to_start')
        self.assertEqual(self.tick(['choose_hero'])['step'], 'press_choose_hero')
        self.assertEqual(self.tick(['hud_eye', 'hud_auto'])['step'], 'game_ready')
        self.tick(['hud_eye', 'hud_auto'])
        self.assertEqual(sum(cmd == 'tap' for cmd, _ in self.host.calls), 2)

    def test_launch_is_not_repeated_when_foreground_does_not_change(self):
        self.tick()
        self.tick(after=10)
        self.assertEqual(self.tick(after=120)['error'], 'game_launch_timeout')
        self.assertEqual(sum(cmd == 'launch' for cmd, _ in self.host.calls), 1)

    def test_hidden_button_is_not_tapped_again_when_it_reappears(self):
        self.host.package = bot.PACKAGE
        self.tick(['touch_to_start'])
        self.tick([])
        self.tick(['touch_to_start'])
        self.assertEqual(self.tick(['touch_to_start'], after=21)['error'], 'game_launch_button_not_closed')
        self.assertEqual(sum(cmd == 'tap' for cmd, _ in self.host.calls), 1)

    def test_unknown_screen_times_out_without_blind_taps(self):
        self.host.package = bot.PACKAGE
        self.tick(['hud_eye'])
        result = self.tick(after=121)
        self.assertEqual(result['error'], 'game_entry_not_recognized')
        self.assertTrue(result['pause'])
        self.assertFalse(any(cmd == 'tap' for cmd, _ in self.host.calls))

    def test_disable_autostart_pauses_without_launch(self):
        self.settings['autostart_enabled'] = False
        self.assertTrue(self.tick()['pause'])
        self.assertEqual(self.host.calls, [])

    def test_title_text_without_logo_never_taps_gameplay(self):
        self.host.package = bot.PACKAGE
        self.host.visible = {'touch_to_start'}
        with patch.object(bot.time, 'monotonic', return_value=self.now):
            self.assertEqual(bot.tick(self.host, self.settings, self.state, str(ROOT))['step'], 'waiting_game_entry')
        self.assertFalse(any(cmd == 'tap' for cmd, _ in self.host.calls))

    def test_foreground_loss_after_success_restarts_launch_recognition(self):
        self.host.package = bot.PACKAGE
        self.tick(['hud_eye', 'hud_auto'])
        self.host.package = 'com.android.launcher'
        self.assertEqual(self.tick()['step'], 'launch_game')

    def test_transient_foreground_unavailable_waits_without_consuming_a_restart(self):
        original = self.host.call
        def unavailable(command, **args):
            if command == 'foreground':
                raise RuntimeError('foreground_unavailable')
            return original(command, **args)
        self.host.call = unavailable
        self.assertEqual(self.tick()['step'], 'waiting_game_foreground')
        self.assertIsNone(self.tick(after=5)['error'])
        self.host.call = original
        self.assertEqual(self.tick()['step'], 'launch_game')

    def test_stuck_foreground_unavailable_reports_a_bounded_error(self):
        def unavailable(command, **args):
            raise RuntimeError('foreground_unavailable')
        self.host.call = unavailable
        self.tick()
        self.assertEqual(self.tick(after=21)['error'], 'foreground_unavailable')

    def test_game_ready_does_not_erase_pending_farm_route(self):
        self.host.package=bot.PACKAGE
        self.settings['farm_enabled']=True
        self.state['route']={'phase':'open','since':self.now}
        old=bot._navigators.get(str(ROOT))
        bot._navigators[str(ROOT)]=SimpleNamespace(tick=lambda *args:None)
        try:
            self.assertEqual(self.tick(['hud_eye','hud_auto'])['step'],'waiting_map_anchor')
            self.assertIn('route',self.state)
            result=self.tick(['hud_eye','hud_auto'],after=21)
            self.assertEqual(result['error'],'farm_map_anchor_not_recognized')
            self.assertFalse(result['retryable'])
        finally:
            if old is None:bot._navigators.pop(str(ROOT),None)
            else:bot._navigators[str(ROOT)]=old


if __name__ == '__main__':
    unittest.main()
