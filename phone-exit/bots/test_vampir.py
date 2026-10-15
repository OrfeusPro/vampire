import copy
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent / 'vampir'
spec = importlib.util.spec_from_file_location('vampir_bot', ROOT / 'bot.py')
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)


class Host:
    def __init__(self):
        self.package = bot.PACKAGE
        self.visible = set()
        self.calls = []

    def call(self, command, **args):
        self.calls.append((command, args))
        if command == 'foreground':
            return dict(package=self.package)
        if command == 'capture':
            return dict(width=1280, height=720)
        if command == 'match':
            return dict(found=args['name'] in self.visible, point=[640, 580])
        return {}


class Vampir(unittest.TestCase):
    def setUp(self):
        self.host = Host()
        self.state = {}
        self.now = 1000
        self.directory = str(ROOT)
        self.settings = json.loads((ROOT / 'defaults.json').read_text())
        self.config = json.loads((ROOT / 'vision.json').read_text())
        bot._configs[self.directory] = copy.deepcopy(self.config)

    def tick(self, visible=(), after=1):
        self.now += after
        self.host.visible = set(visible)
        with patch.object(bot.time, 'monotonic', return_value=self.now):
            return bot.tick(self.host, self.settings, self.state, self.directory)

    def test_patch_download_never_clicks_or_restarts(self):
        for _ in range(5):
            self.assertEqual(self.tick(['patch_download'], 1000)['step'], 'waiting_game_download')
        self.assertFalse(any(c in ('tap', 'launch') for c, _ in self.host.calls))

    def test_launch_once_then_bound_wait(self):
        self.host.package = 'com.og.launcher'
        self.assertEqual(self.tick()['step'], 'launch_game')
        self.assertEqual(self.tick()['step'], 'waiting_game_foreground')
        self.assertEqual(self.tick(after=91)['error'], 'game_launch_timeout')
        self.assertEqual(sum(c == 'launch' for c, _ in self.host.calls), 1)

    def test_package_alone_is_not_loaded_character(self):
        self.assertEqual(self.tick()['status'], 'waiting')
        result = self.tick(after=121)
        self.assertEqual(result['error'], 'game_entry_not_recognized')
        self.assertFalse(result['retryable'])
        self.assertFalse(any(c == 'tap' for c, _ in self.host.calls))

    def test_disabled_does_not_touch_phone(self):
        self.settings['autostart_enabled'] = False
        self.assertTrue(self.tick()['pause'])
        self.assertEqual(self.host.calls, [])

    def test_known_button_clicked_once_until_screen_changes(self):
        config = bot._configs[self.directory]
        config['launch_buttons'] = ['start']
        config['templates']['start'] = {}
        self.assertEqual(self.tick(['start'])['step'], 'press_start')
        self.tick(['start'])
        self.assertEqual(self.tick(['start'], 21)['error'], 'game_launch_button_not_closed')
        self.assertEqual(sum(c == 'tap' for c, _ in self.host.calls), 1)

    def test_two_hud_anchors_required(self):
        config = bot._configs[self.directory]
        config['ready_anchors'] = ['minimap', 'inventory']
        config['templates'].update(minimap={}, inventory={})
        self.assertNotEqual(self.tick(['minimap'])['step'], 'game_ready')
        self.assertEqual(self.tick(['minimap', 'inventory'])['step'], 'game_ready')

    def test_resolution_change_scales_from_original_without_compounding(self):
        config = dict(templates=dict(button=dict(scales=[1, 1.5])))
        bot.prepare_templates(config, dict(width=1600, height=900))
        self.assertEqual(config['templates']['button']['scales'], [1.25, 1.875])
        bot.prepare_templates(config, dict(width=960, height=540))
        self.assertEqual(config['templates']['button']['scales'], [.75, 1.125])
        bot.prepare_templates(config, dict(width=1280, height=720))
        self.assertEqual(config['templates']['button']['scales'], [1, 1.5])

    def test_template_specific_reference_size_does_not_scale_twice(self):
        config = dict(templates=dict(normal=dict(scales=[1]), compact=dict(scales=[1], reference_size=[960, 540])))
        bot.prepare_templates(config, dict(width=1280, height=720))
        self.assertEqual(config['templates']['normal']['scales'], [1])
        self.assertEqual(config['templates']['compact']['scales'], [1.333333])
        bot.prepare_templates(config, dict(width=960, height=540))
        self.assertEqual(config['templates']['normal']['scales'], [.75])
        self.assertEqual(config['templates']['compact']['scales'], [1])

    def test_aspect_change_recomputes_each_template_even_with_same_global_scale(self):
        config = dict(templates=dict(portrait=dict(scales=[1], reference_size=[720, 1280])))
        bot.prepare_templates(config, dict(width=1280, height=720))
        self.assertEqual(config['templates']['portrait']['scales'], [.5625])
        bot.prepare_templates(config, dict(width=1280, height=800))
        self.assertEqual(config['templates']['portrait']['scales'], [.625])

    def test_character_creation_is_left_to_user(self):
        result = self.tick(['character_creation'])
        self.assertEqual(result['step'], 'waiting_character_creation')
        self.assertTrue(result['pause'])
        self.assertIsNone(result['error'])
        self.assertFalse(any(c == 'tap' for c, _ in self.host.calls))

    def test_inspect_message_prevents_shop_or_quest_input(self):
        self.settings['quest_enabled'] = True
        result = self.tick(['connection_terminated_inspect', 'shop_guide_title', 'shop_guide_task'])
        self.assertTrue(result['pause'])
        self.assertEqual(result['reason'], 'source_text:KICKOUT_FOR_INSPECT')
        self.assertFalse(any(c in ('tap', 'launch') for c, _ in self.host.calls))

    def test_inspect_alternative_preserves_source_key_and_prevents_input(self):
        self.settings['quest_enabled'] = True
        result = self.tick(['connection_terminated_inspect_compact', 'shop_guide_title', 'shop_guide_task'])
        self.assertTrue(result['pause'])
        self.assertEqual(result['reason'], 'source_text:KICKOUT_FOR_INSPECT')
        self.assertFalse(any(c in ('tap', 'launch') for c, _ in self.host.calls))


if __name__ == '__main__':
    unittest.main()
