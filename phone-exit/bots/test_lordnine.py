"""Replay screen outcomes; actions must follow fresh observations, not elapsed time."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).parent / 'lordnine'


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bot = load('bot')
navigation = load('navigation')


class Host:
    def __init__(self):
        self.visible = set()
        self.calls = []
        self.now = 1000

    def call(self, command, **args):
        self.calls.append((command, args))
        if command == 'foreground':
            return {'package': 'com.smilegate.l9asia.stove.google'}
        if command == 'capture':
            return {'width': 1280, 'height': 720}
        if command == 'match':
            found = args['name'] in self.visible
            value = {'found': found, 'confidence': .99 if found else 0, 'point': [500, 300]}
            if args['name'] == 'farm_minimap_pin' and 'dungeon_minimap_toggle_icon' in self.visible:
                value.update(found=True, panelVisible=True)
            return value
        return {'performed': True}


def settings():
    return {'settingsVersion': 1, 'farm_enabled': False, 'recovery_enabled': True,
            'auto_dismantle_enabled': False, 'autostart_enabled': False,
            'farm_map_spots': [], 'active_farm_map_spot_id': None}


class Replay(unittest.TestCase):
    def test_initial_loading_waits_for_connect_without_blind_input(self):
        self.settings['autostart_enabled'] = True
        self.assertEqual(self.tick([])['step'], 'waiting_game_launch')
        self.assertEqual(self.tick([], 14)['step'], 'waiting_game_launch')
        self.assertFalse(any(cmd in ('tap', 'launch', 'back') for cmd, _ in self.host.calls))
        self.assertEqual(self.tick(['launch_connect'], 3)['step'], 'launch_account_connect')

    def test_initial_loading_has_bounded_twenty_second_budget(self):
        self.settings['autostart_enabled'] = True
        self.tick([])
        result = self.tick([], 21)
        self.assertEqual(result['error'], 'game_launch_timeout')
        self.assertTrue(result['pause'])

    def test_long_initial_wait_does_not_hide_unknown_screen_during_gameplay(self):
        self.settings['autostart_enabled'] = True
        self.tick(['game_inventory_icon'])
        self.tick([])
        result = self.tick([], 13)
        self.assertEqual(result['error'], 'unrecognized_game_screen')

    def test_approved_rare_warning_confirms_once_then_waits_for_result(self):
        self.settings.update(auto_dismantle_enabled=True, confirm_rare_dismantle_enabled=True)
        self.state.update(phase='dismantle_result', since=self.host.now)
        result = self.tick(['dismantle_rare_warning', 'dismantle_rare_ok'])
        self.assertEqual(result['step'], 'confirm_dismantle_rare_items')
        self.assertIsNone(result['error'])
        self.tick(['dismantle_rare_warning', 'dismantle_rare_ok'])
        self.assertEqual(sum(cmd == 'tap' for cmd, _ in self.host.calls), 1)
        result = self.tick(['dismantle_result'])
        self.assertEqual(result['step'], 'waiting_dismantle_result')
        self.assertEqual(self.state['phase'], 'dismantle_result_closed')

    def test_rare_warning_without_button_never_guesses_coordinates(self):
        self.settings.update(auto_dismantle_enabled=True, confirm_rare_dismantle_enabled=True)
        self.tick(['dismantle_rare_warning'])
        result = self.tick(['dismantle_rare_warning'], 13)
        self.assertEqual(result['error'], 'dismantle_rare_ok_not_found')
        self.assertFalse(any(cmd == 'tap' for cmd, _ in self.host.calls))

    def test_stuck_rare_warning_never_repeats_destructive_confirmation(self):
        self.settings.update(auto_dismantle_enabled=True, confirm_rare_dismantle_enabled=True)
        self.tick(['dismantle_rare_warning', 'dismantle_rare_ok'])
        result = self.tick(['dismantle_rare_warning', 'dismantle_rare_ok'], 13)
        self.assertEqual(result['error'], 'dismantle_rare_confirmation_not_closed')
        self.assertEqual(sum(cmd == 'tap' for cmd, _ in self.host.calls), 1)

    def test_timeout_notice_discards_interrupted_purchase_and_reenters_login(self):
        self.settings['autostart_enabled'] = True
        self.state.update(phase='shop_confirm', route=[{'map_id':'old'}], at_farm=True)
        result = self.tick(['timeout_notification', 'timeout_notification_ok', 'game_inventory_icon'])
        self.assertEqual(result['step'], 'dismiss_session_timeout')
        self.assertNotIn('route', self.state)
        self.assertNotIn('at_farm', self.state)
        result = self.tick(['launch_connect'], 3)
        self.assertEqual(result['step'], 'launch_account_connect')

    def test_network_notice_retries_with_backoff_and_recognized_button(self):
        self.settings['autostart_enabled'] = True
        self.state.update(phase='farm_transition', wait_until=1100, route=[{'map_id':'old'}])
        result = self.tick(['game_server_error_t005', 'game_notice_ok'])
        self.assertEqual(result['step'], 'dismiss_network_error')
        self.assertNotIn('route', self.state)
        self.tick(['game_server_error_t005', 'game_notice_ok'], 3)
        self.assertEqual(sum(cmd == 'tap' for cmd, _ in self.host.calls), 1)
        self.tick(['game_server_error_t005', 'game_notice_ok'], 13)
        self.assertEqual(sum(cmd == 'tap' for cmd, _ in self.host.calls), 2)
        self.assertEqual(self.state['notice_retry_at'], self.host.now + 30)

    def test_network_notice_new_occurrence_drops_new_interrupted_action(self):
        self.settings['autostart_enabled'] = True
        self.tick(['game_server_error_t005', 'game_notice_ok'])
        self.tick(['game_inventory_icon'], 3)
        self.state.update(phase='shop_confirm', route=[{'map_id':'new'}])
        self.tick(['game_server_error_t005', 'game_notice_ok'], 16)
        self.assertNotIn('route', self.state)
        self.assertEqual(self.state['phase'], 'monitoring')

    def test_unknown_notice_title_and_missing_network_button_are_not_auto_confirmed(self):
        self.settings['autostart_enabled'] = True
        result = self.tick(['game_update_notice_title', 'game_notice_ok'])
        self.assertEqual(result['error'], 'game_notice_requires_attention')
        self.assertFalse(any(cmd == 'tap' for cmd, _ in self.host.calls))
        self.tick(['game_server_error_t005'])
        result = self.tick(['game_server_error_t005'], 16)
        self.assertEqual(result['error'], 'game_notice_ok_not_found')
        self.assertFalse(any(cmd == 'tap' for cmd, _ in self.host.calls))

    def test_rare_item_warning_pauses_without_confirming_or_repeating_dismantle(self):
        self.state.update(phase='dismantle_result',since=self.host.now)
        result=self.tick(['dismantle_rare_warning'])
        self.assertEqual(result['error'],'dismantle_rare_items_confirmation_required')
        self.assertTrue(result['pause'])
        self.assertFalse(any(c[0] in ('tap','swipe','back') for c in self.host.calls))

    def test_death_recovery_dismantles_without_red_weight_before_supplies(self):
        self.settings['auto_dismantle_enabled']=True
        self.tick(['death_popup','revive_button'])
        self.tick(['game_inventory_icon','town_supplies_icon'],11)
        result=self.tick(['game_inventory_icon','town_supplies_icon'])
        self.assertEqual(result['step'],'recovery_dismantle_before_supplies')
        self.assertEqual(self.state['phase'],'dismantle_inventory')
        self.assertFalse(self.state.get('recovery_dismantle_pending'))
        self.tick(['dismantle_quick_add_button'])
        self.tick(['dismantle_quick_add_button'])
        self.tick(['dismantle_quick_add_button'])
        self.tick(['dismantle_quick_add_button'])
        self.tick(['game_inventory_icon','town_supplies_icon'])
        result=self.tick(['game_inventory_icon','town_supplies_icon'])
        self.assertEqual(result['step'],'buy_supplies')
        self.assertEqual(self.state['phase'],'shop_open')

    def test_gameplay_hud_with_auto_and_minimap_survives_occluded_inventory(self):
        for i in range(3):
            result = self.tick(['auto_battle_on', 'dungeon_minimap_toggle_icon'], 10)
            self.assertEqual(result['step'], 'monitoring')
            self.assertIsNone(result['error'])
        self.assertFalse(any(c[0] in ('tap','swipe','back') for c in self.host.calls))

    def test_auto_without_minimap_does_not_end_unrecognised_screen(self):
        self.tick(['auto_battle_on'])
        result = self.tick(['auto_battle_on'], 13)
        self.assertEqual(result['error'], 'unrecognized_game_screen')
        self.assertFalse(any(c[0] in ('tap','swipe','back') for c in self.host.calls))

    def test_foreground_changes_between_capture_and_input_discards_action(self):
        self.settings['autostart_enabled'] = True
        self.state.update(phase='shop_open', route=[{'map_id':'old'}])
        original = self.host.call
        def race(command, **args):
            if command == 'tap':
                raise RuntimeError('bot_game_not_foreground')
            return original(command, **args)
        self.host.call = race
        result = self.tick(['supplies_shop', 'auto_purchase'])
        self.assertEqual(result['step'], 'waiting_game_foreground')
        self.assertIsNone(result['error'])
        self.assertNotIn('route', self.state)
        self.assertEqual(self.state['phase'], 'monitoring')

    def test_power_saving_fallback_needs_both_original_colors_and_emblem(self):
        result = self.tick(['power_saving_colors', 'power_saving_emblem'])
        self.assertEqual(result['step'], 'wake_power_saving')
        self.assertEqual(sum(c[0]=='back' for c in self.host.calls), 1)

    def test_power_saving_emblem_alone_never_wakes_launch_screen(self):
        result = self.tick(['power_saving_emblem'])
        self.assertEqual(result['step'], 'recognizing_screen')
        self.assertFalse(any(c[0] in ('back','tap','swipe') for c in self.host.calls))

    def outside_game(self):
        original = self.host.call
        def outside(command, **args):
            if command == 'foreground':
                self.host.calls.append((command, args))
                return {'package':'com.android.launcher'}
            return original(command, **args)
        self.host.call = outside

    def test_autostart_during_action_wait_discards_old_route(self):
        self.outside_game()
        self.settings['autostart_enabled'] = True
        self.state.update(phase='farm_travel_confirm', wait_until=self.host.now+20,
                          route=[{'map_id':'old'}], at_farm=True)
        result = self.tick([])
        self.assertEqual(result['step'], 'launch_game')
        self.assertEqual(self.state['phase'], 'monitoring')
        self.assertNotIn('route', self.state)
        self.assertNotIn('at_farm', self.state)
        self.assertNotIn('wait_until', self.state)
        self.assertEqual(sum(c[0]=='launch' for c in self.host.calls), 1)
        self.assertFalse(any(c[0] in ('tap','back','swipe') for c in self.host.calls))

    def test_autostart_waits_then_times_out_without_relaunch_loop(self):
        self.outside_game()
        self.settings['autostart_enabled'] = True
        self.tick([])
        self.assertEqual(self.tick([], 5)['step'], 'waiting_game_launch')
        result = self.tick([], 90)
        self.assertTrue(result['pause'])
        self.assertEqual(result['error'], 'game_launch_timeout')
        self.assertEqual(sum(c[0]=='launch' for c in self.host.calls), 1)

    def test_disabled_autostart_leaves_other_application_untouched(self):
        self.outside_game()
        result = self.tick([])
        self.assertTrue(result['pause'])
        self.assertFalse(any(c[0]=='launch' for c in self.host.calls))

    def test_service_checks_ready_shop_before_expired_wait(self):
        self.state.update(phase='shop_open', since=self.host.now - 20)
        result = self.tick(['supplies_shop', 'auto_purchase'])
        self.assertEqual(result['step'], 'open_supplies')
        self.assertNotIn('pause', result)
        self.assertEqual(self.state['phase'], 'shop_confirm')
        self.assertEqual(sum(c[0] == 'tap' for c in self.host.calls), 1)

    def test_service_missing_shop_still_times_out_without_purchase(self):
        self.state.update(phase='shop_open', since=self.host.now - 20)
        result = self.tick(['game_inventory_icon'])
        self.assertTrue(result['pause'])
        self.assertEqual(result['error'], 'game_step_timeout_shop_open')
        self.assertFalse(any(c[0] == 'tap' for c in self.host.calls))

    def test_wake_cancels_quit_popup_before_fallback_swipe(self):
        self.tick(['power_saving'])
        self.host.calls.clear()
        result = self.tick(['power_saving', 'quit_game_popup', 'quit_game_cancel'], 3)
        self.assertEqual(result['step'], 'close_quit_popup')
        self.assertEqual(sum(c[0] == 'tap' for c in self.host.calls), 1)
        self.assertFalse(any(c[0] in ('swipe', 'back') for c in self.host.calls))
        self.assertEqual(self.state['wake_attempts'], 0)

    def test_recovery_preserves_original_revive_and_restore_pauses(self):
        self.tick(['death_popup', 'revive_button'])
        self.assertEqual(self.state['wait_until'] - self.host.now, 10)
        self.tick(['game_inventory_icon'], 11)
        self.tick(['stat_restore_window', 'restore_button'])
        self.assertEqual(self.state['wait_until'] - self.host.now, 3)

    def test_weak_restore_icon_does_not_trigger_restoration(self):
        original = self.host.call
        def weak_icon(command, **args):
            result = original(command, **args)
            if command == 'match' and args['name'] == 'restore_icon':
                result.update(found=True, confidence=.80)
            return result
        self.host.call = weak_icon
        self.tick(['town_supplies_icon'])
        config, _, _ = bot.resources(str(ROOT))
        icon = config['tap_points']['restore_icon']
        self.assertFalse(any(command == 'tap' and args['x'] == round(icon[0]*1280)
                             and args['y'] == round(icon[1]*720)
                             for command, args in self.host.calls))

    def test_dark_login_layout_cannot_skip_connect(self):
        original = self.host.call
        def dark_layout(command, **args):
            if command == 'match' and args['name'].startswith('farm_map_'):
                return {'found': False, 'confidence': 0, 'pathRatio': .2,
                        'dark70Ratio': .9, 'dark60Ratio': .9,
                        'dark80Ratio': .9, 'edgeRatio': .1}
            return original(command, **args)
        self.host.call = dark_layout
        self.settings['autostart_enabled'] = True
        result = self.tick(['launch_connect'])
        self.assertEqual(result['step'], 'launch_account_connect')
        self.assertEqual(sum(c[0] == 'tap' for c in self.host.calls), 1)
        self.assertNotIn('route', self.state)

    def test_explicit_game_launch_waits_original_start_timeout_without_input(self):
        self.settings['autostart_enabled'] = True
        self.state['last_launch'] = self.host.now
        result = self.tick([], 20)
        self.assertEqual(result['step'], 'waiting_game_launch')
        self.assertFalse(any(c[0] in ('tap', 'back', 'launch') for c in self.host.calls))

    def test_missing_foreground_waits_without_input_and_recovers(self):
        original = self.host.call
        def unavailable(command, **args):
            if command == 'foreground':
                raise RuntimeError('foreground_unavailable')
            return original(command, **args)
        self.host.call = unavailable
        self.state.update(phase='farm_arrival', wait_until=self.host.now + 5)
        result = self.tick([], 1)
        self.assertEqual(result['step'], 'waiting_foreground')
        self.assertFalse(result['pause'])
        self.assertEqual(self.host.calls, [])
        self.host.call = original
        self.tick(['game_inventory_icon'], 1)
        self.assertNotIn('foreground_missing_since', self.state)
        self.assertFalse(any(c[0] in ('launch', 'tap', 'back') for c in self.host.calls))

    def test_missing_foreground_times_out_without_actions(self):
        def unavailable(command, **args):
            self.assertEqual(command, 'foreground')
            raise RuntimeError('foreground_unavailable')
        self.host.call = unavailable
        self.assertFalse(self.tick([])['pause'])
        result = self.tick([], 10)
        self.assertTrue(result['pause'])
        self.assertEqual(result['error'], 'foreground_unavailable')

    def setUp(self):
        self.host, self.state, self.settings = Host(), {}, settings()
        self.clock = bot.time.monotonic
        bot.time.monotonic = lambda: self.host.now

    def test_map_preflight_does_not_toggle_existing_autobattle(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, recovery_enabled=False,
                             farm_map_spots=[spot], active_farm_map_spot_id='a')
        result = self.tick(['game_inventory_icon', 'auto_battle_on', 'dungeon_minimap_toggle_icon'])
        self.assertEqual(result['step'], 'open_farm_map')
        self.assertFalse(any(command in ('tap','back','swipe') for command, _ in self.host.calls))
        result = self.tick(['game_inventory_icon', 'auto_battle_on', 'dungeon_minimap_toggle_icon'])
        self.assertEqual(result['step'], 'retry_open_farm_map')
        config, _, _ = bot.resources(str(ROOT))
        point = config['tap_points']['dungeon_map_open']
        taps = [args for command, args in self.host.calls if command == 'tap']
        self.assertEqual([(item['x'],item['y']) for item in taps],
                         [(round(point[0]*1280), round(point[1]*720))])

    def test_disabled_autobattle_is_enabled_only_after_game_entry(self):
        self.state['entry_autobattle_pending'] = True
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, recovery_enabled=False,
                             farm_map_spots=[spot], active_farm_map_spot_id='a')
        result=self.tick(['game_inventory_icon','auto_battle_off'])
        self.assertEqual(result['step'],'enable_autobattle_before_map')
        self.assertNotIn('route',self.state)
        self.assertEqual(len([c for c in self.host.calls if c[0]=='tap']),1)
        result=self.tick(['game_inventory_icon','auto_battle_on'],3)
        self.assertEqual(result['step'],'open_farm_map')
        self.assertEqual(len([c for c in self.host.calls if c[0]=='tap']),1)

    def test_town_never_enables_autobattle_before_map(self):
        self.state['entry_autobattle_pending'] = True
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True,recovery_enabled=False,
                             farm_map_spots=[spot],active_farm_map_spot_id='a')
        self.assertEqual(self.tick(['town_supplies_icon','auto_battle_off'])['step'],'open_farm_map')
        self.assertFalse(any(c[0]=='tap' for c in self.host.calls))

    def test_starting_bot_on_character_does_not_enable_auto_before_route(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, recovery_enabled=False, farm_map_spots=[spot], active_farm_map_spot_id='a')
        result = self.tick(['game_inventory_icon','auto_battle_off'])
        self.assertEqual(result['step'], 'open_farm_map')
        self.assertFalse(any(c[0]=='tap' for c in self.host.calls))

    def test_editor_never_routes_or_toggles_auto_on_unknown_location(self):
        self.settings['editor_request']={'kind':'point','map_id':'tab1_row1_dien_port'}
        result=self.tick(['world_map_title','auto_battle_off'])
        self.assertEqual(result['error'],'editor_current_location_mismatch')
        self.assertTrue(result['pause'])
        self.assertFalse(any(c[0] in ('tap','back','swipe') for c in self.host.calls))

    def test_editor_capture_is_training_sample_not_old_template_match(self):
        self.settings['editor_request']={'kind':'capture','map_id':'tab1_row1_dien_port'}
        result=self.tick(['world_map_title'])
        self.assertEqual(result['reason'],'editor_capture_ready')
        self.assertTrue(result['pause'])
        self.assertFalse(any(c[0] in ('tap','back','swipe') for c in self.host.calls))

    def tearDown(self):
        bot.time.monotonic = self.clock

    def tick(self, visible, after=2):
        self.host.now += after
        self.host.visible = set(visible)
        return bot.tick(self.host, self.settings, self.state, str(ROOT))

    def test_revive_wait_then_restore_closes_without_repeating_restore(self):
        self.tick(['death_popup', 'revive_button'])
        taps = len([c for c in self.host.calls if c[0] == 'tap'])
        self.tick(['death_popup', 'revive_button'], .1)
        self.assertEqual(taps, len([c for c in self.host.calls if c[0] == 'tap']))
        self.tick(['game_inventory_icon'], 11)
        self.tick(['stat_restore_window', 'restore_button'])
        result = self.tick(['stat_restore_window', 'restore_button'], 4)
        self.assertEqual(result['step'], 'close_restore_window')
        config, _, _ = bot.resources(str(ROOT))
        last = [c for c in self.host.calls if c[0] == 'tap'][-1][1]
        self.assertEqual(last['x'], round(config['tap_points']['close_stat_window'][0]*1280))

    def test_unknown_screen_pauses_and_never_sends_input(self):
        self.tick([])
        result = self.tick([], 13)
        self.assertTrue(result['pause'])
        self.assertEqual(result['error'], 'unrecognized_game_screen')
        self.assertFalse(any(c[0] in ('tap', 'swipe', 'back') for c in self.host.calls))

    def test_settings_change_cancels_old_route_before_any_host_command(self):
        self.tick(['game_inventory_icon'])
        self.state.update(phase='farm_target', route=[{'map_id': 'old'}], at_farm=True)
        self.settings['active_farm_map_spot_id'] = 'new'
        self.host.calls.clear()
        result = self.tick(['world_map_title'])
        self.assertTrue(result['pause'])
        self.assertEqual(result['error'], 'settings_changed_during_action')
        self.assertEqual(self.host.calls, [])
        self.assertNotIn('route', self.state)
        self.assertNotIn('at_farm', self.state)

    def test_disabled_service_cannot_finish_old_confirmation(self):
        self.tick(['game_inventory_icon'])
        self.state['phase'] = 'restore_close'
        self.settings['recovery_enabled'] = False
        self.host.calls.clear()
        self.assertTrue(self.tick(['stat_restore_window', 'restore_button'])['pause'])
        self.assertEqual(self.host.calls, [])

    def test_launch_uses_calibrated_point_and_limits_repeated_skip(self):
        self.settings['autostart_enabled'] = True
        self.tick(['launch_skip'], 3)
        self.tick(['launch_skip'], 3)
        result = self.tick(['launch_skip'], 3)
        taps = [args for command, args in self.host.calls if command == 'tap']
        self.assertEqual(len(taps), 2)
        self.assertEqual((taps[0]['x'], taps[0]['y']), (1203, 50))
        self.assertEqual(result['step'], 'waiting_launch_intro_skip')

    def test_character_start_waits_for_hud_without_replaying_start(self):
        self.settings['autostart_enabled'] = True
        self.tick(['launch_start'])
        result = self.tick(['launch_start'], 13)
        self.assertEqual(result['step'], 'waiting_game_launch_done')
        self.assertEqual(sum(c[0] == 'tap' for c in self.host.calls), 1)
        result = self.tick(['launch_start'], 71)
        self.assertIsNone(result['error'])
        result = self.tick([], 31)
        self.assertEqual(result['error'], 'game_launch_done_timeout')

    def test_login_interrupts_farm_transition_before_old_floor_timeout(self):
        self.settings['autostart_enabled'] = True
        self.state.update(phase='farm_transition', since=800, arrival_started=800,
                          route=[{'map_id':'old'}], at_farm=True, serviced=True, gameplay_seen=True)
        result = self.tick(['launch_connect'])
        self.assertEqual(result['step'], 'launch_account_connect')
        self.assertIsNone(result['error'])
        self.assertNotIn('route', self.state)
        self.assertNotIn('serviced', self.state)

    def test_login_interrupts_old_purchase_without_replaying_confirmation(self):
        self.settings['autostart_enabled'] = True
        self.state.update(phase='shop_confirm', since=800, gameplay_seen=True)
        result = self.tick(['launch_connect'])
        self.assertEqual(result['step'], 'launch_account_connect')
        config, _, _ = bot.resources(str(ROOT))
        taps = [v for cmd, v in self.host.calls if cmd == 'tap']
        self.assertEqual(len(taps), 1)
        self.assertEqual(taps[0]['x'], round(config['tap_points']['launch_connect'][0]*1280))

    def test_login_offer_closes_before_completed_launch_runs_service(self):
        self.settings['autostart_enabled'] = True
        self.tick(['launch_start'])
        result = self.tick(['game_inventory_icon','town_supplies_icon','launch_offer_close'], 13)
        self.assertEqual(result['step'], 'close_launch_offer')
        self.assertNotIn('gameplay_seen', self.state)
        result = self.tick(['game_inventory_icon','town_supplies_icon'], 2)
        self.assertEqual(result['step'], 'buy_supplies')
        self.assertNotIn('launch_offer_close_count', self.state)

    def test_launch_offer_is_bounded_and_never_taps_after_three_attempts(self):
        self.settings['autostart_enabled'] = True
        self.state['entry_autobattle_pending'] = True
        for i in range(3):
            self.assertEqual(self.tick(['game_inventory_icon','launch_offer_close'])['step'], 'close_launch_offer')
        self.assertEqual(self.tick(['game_inventory_icon','launch_offer_close'])['error'], 'launch_offer_not_closed')
        self.assertEqual(sum(cmd == 'tap' for cmd, _ in self.host.calls), 3)

    def test_launch_fallback_handles_returned_connect_and_preserves_imported_pause(self):
        self.settings['autostart_enabled'] = True
        self.tick(['launch_start'])
        result = self.tick(['launch_connect'], 84)
        self.assertEqual(result['step'], 'launch_account_connect')
        self.assertEqual(self.state['wait_until'], self.host.now+5)
        self.assertEqual(self.state['launch_fallback_actions'], 1)

    def test_after_launch_unknown_auto_waits_without_tapping_and_on_is_untouched(self):
        self.settings.update(autostart_enabled=True, recovery_enabled=False)
        self.state['entry_autobattle_pending'] = True
        result = self.tick(['game_inventory_icon'])
        self.assertEqual(result['step'], 'waiting_launch_autobattle')
        self.assertEqual(self.state['wait_until'], self.host.now+2)
        self.assertFalse(any(cmd == 'tap' for cmd, _ in self.host.calls))
        self.tick(['game_inventory_icon','auto_battle_on'], 3)
        self.assertFalse(any(cmd == 'tap' for cmd, _ in self.host.calls))
        self.assertNotIn('entry_autobattle_pending', self.state)

    def test_launch_hud_clears_action_budget(self):
        self.settings['autostart_enabled'] = True
        self.tick(['launch_tap_to_start'])
        self.tick(['game_inventory_icon'], 4)
        self.assertNotIn('launch_actions', self.state)

    def test_logo_matching_broad_hud_bars_cannot_skip_original_login_flow(self):
        self.settings['autostart_enabled'] = True
        result = self.tick(['game_hud','game_hud_bars','launch_connect'])
        self.assertEqual(result['step'], 'launch_account_connect')
        self.assertNotEqual(self.state['phase'], 'farm_map_open')

    def test_dismantle_requires_red_weight_and_active_confirmation(self):
        self.settings['auto_dismantle_enabled'] = True
        self.tick(['game_inventory_icon'])
        self.assertFalse(any(c[0] == 'tap' for c in self.host.calls))
        self.tick(['game_inventory_icon', 'inventory_weight_red'], 61)
        self.tick(['inventory_dismantle_button'])
        self.tick(['dismantle_quick_add_button'])
        self.tick(['dismantle_selection_options', 'dismantle_selection_quick_add'])
        before = len([c for c in self.host.calls if c[0] == 'tap'])
        result = self.tick([])
        self.assertEqual(result['step'], 'waiting_dismantle_selection')
        self.assertEqual(before, len([c for c in self.host.calls if c[0] == 'tap']))
        self.tick(['confirm_teal'])
        self.assertEqual(before+1, len([c for c in self.host.calls if c[0] == 'tap']))

    def test_travel_confirmation_uses_current_frame_without_second_capture(self):
        spot = {'id': 'a', 'map_id': 'tab1_row1_dien_port', 'map_points': [[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.state.update(phase='farm_travel_confirm', since=1000, route=[
            navigation.leg(spot['map_id'], [.4,.5], True, spot['map_id'])], route_index=0)
        self.tick(['farm_fast_travel_ok', 'farm_cancel_button'])
        self.assertEqual(sum(c[0] == 'capture' for c in self.host.calls), 1)
        self.assertEqual(self.state['phase'], 'farm_arrival')

    def test_entry_color_confirmation_precedes_map_checks_and_keeps_load_pause(self):
        spot = {'id':'a', 'map_id':'tab3_row4_desert_of_the_screaming_lv_6268', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.state.update(phase='farm_transition', since=1000, arrival_started=1000, route=[
            navigation.leg(spot['map_id'], [.4,.5], False, navigation.TYRIOSA_FLOORS['1F'], transition=True)], route_index=0)
        result = self.tick(['farm_ok_button', 'farm_cancel_button', 'world_map_title'])
        self.assertEqual(result['step'], 'confirm_farm_entry')
        self.assertEqual(sum(c[0] == 'tap' for c in self.host.calls), 1)
        self.assertEqual(self.state['wait_until'], self.host.now + 6)
        self.host.calls.clear()
        self.tick(['world_map_title'], 5)
        self.assertFalse(any(cmd in ('tap','back','swipe','launch') for cmd,args in self.host.calls))

    def test_original_responsive_wait_detects_death_without_repeating_route_input(self):
        self.state.update(phase='farm_transition', wait_until=1020, since=1000)
        self.tick(['death_popup','revive_button'], 1)
        self.assertEqual(self.state['phase'], 'revive_wait')
        self.assertFalse(self.state['at_farm'])
        taps = [args for cmd,args in self.host.calls if cmd == 'tap']
        self.assertEqual(len(taps), 1)
        self.host.calls.clear()
        self.tick(['death_popup','revive_button'], 1)
        self.assertFalse(any(cmd in ('tap','swipe','back') for cmd,args in self.host.calls))

    def test_entry_confirmation_has_priority_over_false_quit_dialog_match(self):
        spot = {'id':'a', 'map_id':navigation.TYRIOSA_DESERT, 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.state.update(phase='farm_transition', since=1000, arrival_started=1000, route=[navigation.leg(spot['map_id'], [.4,.5], False, navigation.TYRIOSA_FLOORS['1F'], transition=True)], route_index=0)
        result = self.tick(['farm_ok_button','farm_cancel_button','quit_game_popup','quit_game_cancel'])
        self.assertEqual(result['step'], 'confirm_farm_entry')
        self.assertFalse(any(cmd == 'back' for cmd,args in self.host.calls))

    def test_loading_ends_fast_travel_attempts_and_preserves_post_travel_pause(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.state.update(phase='farm_travel_confirm', since=1000, route=[navigation.leg(spot['map_id'], [.4,.5], True, spot['map_id'])], route_index=0)
        self.tick(['loading'])
        self.assertEqual(self.tick(['game_inventory_icon'])['step'], 'waiting_after_farm_loading')
        self.assertEqual(self.state['phase'], 'farm_arrival')
        self.assertEqual(self.state['wait_until'], self.host.now + 5)
        self.assertFalse(any(cmd == 'tap' for cmd,args in self.host.calls))

    def test_pause_starts_after_action_finishes(self):
        self.settings['autostart_enabled'] = True
        original = self.host.call
        def slow_action(command, **args):
            result = original(command, **args)
            if command == 'tap': self.host.now += 4
            return result
        self.host.call = slow_action
        self.tick(['launch_tap_to_start'])
        self.assertEqual(self.state['wait_until'], self.host.now + 3)

    def test_autobattle_prefers_stronger_on_match_and_never_toggles_it_off(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.state.update(at_farm=True, active_spot='a')
        original = self.host.call
        def scores(command, **args):
            value = original(command, **args)
            if command == 'match' and args['name'] == 'auto_battle_off': value['confidence'] = .85
            return value
        self.host.call = scores
        self.assertEqual(self.tick(['game_inventory_icon','auto_battle_on','auto_battle_off'])['step'], 'farming')
        self.assertFalse(any(c[0] == 'tap' for c in self.host.calls))

    def test_autobattle_uses_template_center_and_original_settle_before_retry(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.state.update(at_farm=True, active_spot='a')
        self.tick(['game_inventory_icon','auto_battle_off'])
        self.assertEqual(self.state['wait_until'], self.host.now + .8)
        self.assertEqual(self.state['autobattle_settle_until'], self.host.now + 2.5)
        taps = [args for cmd,args in self.host.calls if cmd == 'tap']
        self.assertEqual((taps[0]['x'],taps[0]['y']), (500,300))
        self.tick(['game_inventory_icon','auto_battle_off'], 1)
        self.assertEqual(sum(c[0] == 'tap' for c in self.host.calls), 1)
        self.tick(['game_inventory_icon','auto_battle_on'], 2)
        self.assertNotIn('autobattle_attempts', self.state)

    def test_fast_travel_retries_only_on_confirmed_map_then_stops_on_popup(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.state.update(phase='farm_target', since=1000, route=[navigation.leg(spot['map_id'], [.4,.5], True, spot['map_id'])], route_index=0)
        self.tick(['world_map_title'])
        self.tick(['world_map_title'], 4)
        self.assertEqual(sum(c[0] == 'tap' for c in self.host.calls), 1)
        self.tick(['world_map_title'], 1)
        self.assertEqual(sum(c[0] == 'tap' for c in self.host.calls), 2)
        self.tick(['farm_ok_button','farm_cancel_button'], 1)
        self.assertEqual(self.state['phase'], 'farm_arrival')
        self.assertEqual(self.state['travel_attempt'], 1)

    def test_party_overlay_closes_once_and_waits_for_verified_disappearance(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.state.update(phase='farm_map_open', since=1000, route=[navigation.leg(spot['map_id'], [.4,.5], True, spot['map_id'])], route_index=0)
        self.tick(['party_search_title','party_search_close'])
        self.tick(['party_search_title','party_search_close'])
        self.assertEqual(sum(c[0] == 'tap' for c in self.host.calls), 1)
        self.assertEqual(self.tick(['party_search_title','party_search_close'], 13)['error'], 'party_search_not_closed')

    def test_shop_preflight_preserves_two_close_attempts_and_original_pause(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.state.update(phase='farm_map_open', since=1000, route=[navigation.leg(spot['map_id'], [.4,.5], True, spot['map_id'])], route_index=0)
        self.tick(['auto_purchase'])
        self.assertEqual(self.state['wait_until'], self.host.now + 2)
        self.tick(['auto_purchase'], 2)
        self.assertEqual(sum(cmd == 'tap' for cmd,args in self.host.calls), 2)
        self.assertEqual(self.tick(['auto_purchase'], 2)['error'], 'farm_supplies_shop_not_closed')

    def test_marker_cannot_enable_battle_before_intermediate_map_close_is_verified(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.state.update(phase='farm_travel_confirm', since=1000, walk_retried=True, route=[navigation.leg(spot['map_id'], [.4,.5], False, spot['map_id'], transition=True)], route_index=0)
        self.tick(['world_map_title','world_map_exit'])
        self.assertEqual(self.state['phase'], 'farm_close_map')
        self.tick(['game_inventory_icon'])
        self.assertEqual(self.state['phase'], 'farm_transition')
        self.assertFalse(self.state.get('at_farm', False))
        self.assertEqual(self.state['wait_until'], self.host.now + .8)

    def test_original_selected_name_warning_does_not_replace_map_closed_error(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.state.update(phase='farm_selected', since=1000, route=[navigation.leg(spot['map_id'], [.4,.5], True, spot['map_id'])], route_index=0)
        result = self.tick(['world_map_title'])
        self.assertEqual(result['reason'], 'selected_map_name_unconfirmed')
        self.assertEqual(self.state['phase'], 'farm_target')
        self.state['phase'] = 'farm_selected'
        self.assertEqual(self.tick(['game_inventory_icon'])['error'], 'farm_map_closed_after_selection')

    def test_run_after_teleport_requires_point_before_opening_map(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[], 'teleport_point':[.4,.5], 'run_after_teleport':True}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.assertEqual(self.tick(['game_inventory_icon'])['error'], 'farm_point_required')
        self.assertFalse(any(cmd == 'tap' for cmd,args in self.host.calls))

    def test_map_arrival_is_not_inferred_from_timeout(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.state.update(phase='farm_arrival', since=900, route=[
            navigation.leg(spot['map_id'], [.4,.5], True, spot['map_id'])], route_index=0)
        result = self.tick(['world_map_title'])
        self.assertEqual(result['error'], 'farm_arrival_not_verified')
        self.assertFalse(self.state.get('at_farm', False))

    def test_map_selection_uses_navigation_timeout_not_service_timeout(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.state.update(phase='farm_map_open', since=980, route=[
            navigation.leg(spot['map_id'], [.4,.5], True, spot['map_id'])], route_index=0)
        result = self.tick(['world_map_title'])
        self.assertFalse(result.get('pause', False))
        self.assertEqual(self.state['phase'], 'farm_tab')

    def test_restart_on_open_map_recognizes_map_without_toggling_it_closed(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        result = self.tick(['world_map_title'])
        self.assertEqual(result['step'], 'open_farm_map')
        self.assertEqual(self.state['phase'], 'farm_map_open')
        self.assertFalse(any(c[0] in ('tap', 'back', 'swipe') for c in self.host.calls))

    def test_arrival_opens_map_to_verify_imported_location_label(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.state.update(phase='farm_arrival', since=1000, route=[
            navigation.leg(spot['map_id'], [.4,.5], True, spot['map_id'])], route_index=0)
        result = self.tick(['game_inventory_icon'])
        self.assertEqual(result['step'], 'open_arrival_map')
        self.assertFalse(self.state.get('at_farm', False))
        self.assertEqual(self.state['map_return_phase'], 'farm_arrival')
        self.assertFalse(any(c[0] == 'tap' for c in self.host.calls))

    def test_map_retry_requires_confirmed_pin_and_is_bounded(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.state.update(phase='farm_map_open', since=980, route=[
            navigation.leg(spot['map_id'], [.4,.5], True, spot['map_id'])], route_index=0)
        self.assertEqual(self.tick(['game_inventory_icon'])['step'], 'waiting_minimap_confirmation')
        self.assertFalse(any(c[0] == 'tap' for c in self.host.calls))
        self.tick(['game_inventory_icon', 'dungeon_minimap_toggle_icon'], 13)
        self.tick(['game_inventory_icon', 'dungeon_minimap_toggle_icon'], 13)
        self.tick(['game_inventory_icon', 'dungeon_minimap_toggle_icon'], 13)
        result = self.tick(['game_inventory_icon', 'dungeon_minimap_toggle_icon'], 13)
        self.assertEqual(result['error'], 'farm_map_not_opened')
        self.assertEqual(sum(c[0] == 'tap' for c in self.host.calls), 2)

    def test_unknown_minimap_retries_fresh_frames_without_blind_taps(self):
        spot={'id':'a','map_id':'tab1_row1_dien_port','map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True,farm_map_spots=[spot],active_farm_map_spot_id='a')
        self.state.update(phase='farm_map_open',since=980,route=[navigation.leg(spot['map_id'],[.4,.5],True,spot['map_id'])],route_index=0)
        self.assertEqual(self.tick(['game_inventory_icon'])['step'],'waiting_minimap_confirmation')
        self.assertEqual(self.tick(['game_inventory_icon'])['step'],'waiting_minimap_confirmation')
        result=self.tick(['game_inventory_icon'])
        self.assertEqual(result['error'],'farm_minimap_not_confirmed')
        self.assertFalse(any(c[0]=='tap' for c in self.host.calls))

    def test_transition_closes_map_using_exit_glyph_instead_of_android_back(self):
        spot = {'id':'a', 'map_id':'tab1_row1_dien_port', 'map_points':[[.4,.5]]}
        self.settings.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        self.state.update(phase='farm_travel_confirm', since=1000, walk_retried=True, route=[
            navigation.leg(spot['map_id'], [.4,.5], False, spot['map_id'], transition=True)], route_index=0)
        self.tick(['world_map_title', 'world_map_exit'])
        self.assertFalse(any(c[0] == 'back' for c in self.host.calls))
        taps = [args for command,args in self.host.calls if command == 'tap']
        self.assertEqual((taps[-1]['x'], taps[-1]['y']), (500,300))


class TravelPlans(unittest.TestCase):
    def test_arrived_marker_is_checked_locally_without_full_map_scan(self):
        config, catalog, _ = bot.resources(str(ROOT))
        options=navigation.marker_options(config,navigation.TYRIOSA_FLOORS['3F'])
        calls=[]
        def match(name,spec):
            calls.append((name,spec))
            return {'found':True,'confidence':.9,'point':[756,471]}
        result=navigation.find_marker(match,options,config['vision'],{},[756/1280,471/720],1280,720)
        self.assertTrue(result['found'])
        self.assertTrue(all(name.endswith('_arrival') for name,spec in calls))
        self.assertTrue(all(spec['goldNeighborhood'] and spec['blackMask'] for name,spec in calls))
        self.assertTrue(all((spec['region'][2]-spec['region'][0])*1280<=96.01 for name,spec in calls))

    def test_local_missing_or_distant_arrow_falls_back_to_full_scan(self):
        config, _, _ = bot.resources(str(ROOT))
        options=navigation.marker_options(config,navigation.TYRIOSA_FLOORS['3F'])
        for local_found in (False,True):
            calls=[]
            def match(name,spec):
                calls.append(name)
                return {'found':local_found if name.endswith('_arrival') else True,'confidence':.9,'point':[400,300]}
            result=navigation.find_marker(match,options,config['vision'],{},[756/1280,471/720],1280,720)
            self.assertTrue(result['found'])
            self.assertTrue(any(not name.endswith('_arrival') for name in calls))
            self.assertEqual(result['point'],[400,300])

    def test_tyriosa_marker_uses_old_angles_radius_and_strict_confirmation(self):
        config, _, _ = bot.resources(str(ROOT))
        options = navigation.marker_options(config, navigation.TYRIOSA_FLOORS['3F'])
        self.assertEqual(len(options['angles']), 32)
        self.assertEqual(options['radius'], 70)
        self.assertEqual(options['timeout'], 180)
        self.assertEqual(options['checks'], 2)
        self.assertEqual(options['best_distance'], 0)
        self.assertEqual(len(options['templates']), 3)
        self.assertEqual(options['static_templates'], [])

    def test_marker_motion_cannot_confirm_arrival(self):
        host, state, profile = Host(), {}, settings()
        spot = {'id': 'a', 'map_id': 'tab1_row1_dien_port', 'map_points': [[500/1280,300/720]]}
        profile.update(farm_enabled=True, farm_map_spots=[spot], active_farm_map_spot_id='a')
        state.update(phase='farm_verify_marker', since=host.now, arrival_started=host.now,
                     route=[navigation.leg(spot['map_id'], spot['map_points'][0], False, spot['map_id'], marker=True)], route_index=0)
        host.visible={'world_map_title', 'marker_map_navigation_player_arrow_vmos_http.png_0'}
        clock=bot.time.monotonic
        try:
            bot.time.monotonic=lambda:host.now
            bot.tick(host,profile,state,str(ROOT))
            self.assertEqual(state['arrival_checks'],1)
            state['previous_marker']=[490,300]
            host.now += 2
            bot.tick(host,profile,state,str(ROOT))
            self.assertEqual(state['arrival_checks'],1)
            self.assertFalse(state.get('at_farm',False))
            host.now += 2
            bot.tick(host,profile,state,str(ROOT))
            self.assertEqual(state['phase'], 'farm_close_map')
            self.assertFalse(state.get('at_farm', False))
            host.now += 4
            bot.tick(host,profile,state,str(ROOT))
            self.assertFalse(state.get('at_farm', False))
            host.visible={'game_inventory_icon'}
            host.now += 4
            bot.tick(host,profile,state,str(ROOT))
            self.assertTrue(state['at_farm'])
        finally:bot.time.monotonic=clock

    def test_tyriosa_three_uses_direct_one_to_three_old_route(self):
        spot = {'map_id': navigation.TYRIOSA_FLOORS['3F']}
        legs = navigation.route(spot, [.4,.5])
        self.assertEqual([l['point'] for l in legs[:3]], [[.85297,.382],[.85297,.518],[.85297,.215]])
        self.assertEqual(legs[2]['arrival_map'], navigation.TYRIOSA_FLOORS['3F'])
        self.assertTrue(legs[-1]['marker'])

    def test_verified_floor_skips_entrance_but_reverse_route_is_rejected(self):
        spot = {'map_id': navigation.TYRIOSA_FLOORS['3F']}
        legs = navigation.route(spot, [.4,.5], navigation.TYRIOSA_FLOORS['2F'])
        self.assertEqual(legs[0]['point'], [.85297,.246])
        with self.assertRaises(RuntimeError):
            navigation.route({'map_id':navigation.TYRIOSA_FLOORS['1F']}, [.4,.5], navigation.TYRIOSA_FLOORS['3F'])

    def test_deadmans_entrance_nudge_and_destination_chain(self):
        legs = navigation.route({'map_id':navigation.DEADMANS_DISTRICTS['3']}, None)
        self.assertEqual([l['point'] for l in legs], [[.85297,.254],[.85297,.586],[.85297,.185]])
        self.assertTrue(legs[1]['nudge'])
        self.assertEqual(legs[-1]['arrival_map'], navigation.DEADMANS_DISTRICTS['3'])


if __name__ == '__main__':
    unittest.main()
