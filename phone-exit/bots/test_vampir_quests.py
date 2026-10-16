import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).parent / 'vampir'
spec = importlib.util.spec_from_file_location('vampir_quests', ROOT / 'quests.py')
quests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quests)


class Host:
    def __init__(self):
        self.visible = set()
        self.calls = []

    def call(self, command, **args):
        self.calls.append((command, args))
        if command == 'match':
            return dict(found=args['name'] in self.visible, point=[608, 246], rect=[597, 235, 619, 257])
        return {}


class QuestMode(unittest.TestCase):
    def setUp(self):
        self.host = Host()
        self.state = {}
        self.now = 1000
        self.config = json.loads((ROOT / 'vision.json').read_text(encoding='utf-8'))
        self.config['_chain_catalog'] = json.loads((ROOT / 'quest-runtime.json').read_text(encoding='utf-8'))
        self.config['interaction'] = dict(tap_jitter_px=0, delay_jitter_sec=[0, 0], retry_wait_sec=8)
        self.settings = dict(quest_enabled=True, skip_cutscenes_enabled=True)

    def tick(self, visible=(), after=3):
        self.now += after
        self.host.visible = set(visible)
        return quests.tick(self.host, self.settings, self.state, dict(width=1280, height=720), self.config, self.now)

    def hud(self, *other):
        return [*self.config['ready_anchors'], *other]

    def test_active_autoquest_is_never_toggled_by_repeated_taps(self):
        for _ in range(20):
            self.assertIn(self.tick(self.hud('quest_auto_on'))['step'], ('quest_auto_running', 'quest_auto_observing'))
        self.assertFalse(any(c == 'tap' for c, _ in self.host.calls))

    def test_off_state_activates_once_then_waits_for_confirmation(self):
        self.assertEqual(self.tick(self.hud('quest_auto_off', 'quest_anchor'))['step'], 'quest_start_auto')
        self.tick(self.hud('quest_auto_off', 'quest_anchor'))
        self.assertEqual(sum(c == 'tap' for c, _ in self.host.calls), 1)
        self.assertEqual(self.tick(self.hud('quest_auto_on'))['step'], 'quest_auto_running')

    def test_failed_activation_pauses_instead_of_switching_again(self):
        self.tick(self.hud('quest_auto_off', 'quest_anchor'))
        self.assertEqual(self.tick(self.hud('quest_auto_off', 'quest_anchor'), 21)['error'], 'quest_auto_not_enabled')
        self.assertEqual(sum(c == 'tap' for c, _ in self.host.calls), 1)

    def test_skip_requires_scene_not_normal_hud(self):
        self.tick(self.hud('scene_skip', 'quest_auto_on'))
        self.assertFalse(any(c == 'tap' for c, _ in self.host.calls))
        self.assertEqual(self.tick(['scene_skip', 'dialog_auto_header'])['step'], 'quest_skip_scene')

    def test_skip_disabled_preserves_dialog(self):
        self.settings['skip_cutscenes_enabled'] = False
        self.tick(['scene_skip', 'dialog_auto_header'])
        self.assertFalse(any(c == 'tap' for c, _ in self.host.calls))

    def test_stuck_skip_is_bounded(self):
        for _ in range(3):
            self.tick(['scene_skip', 'dialog_auto_header'])
        self.assertEqual(self.tick(['scene_skip', 'dialog_auto_header'])['error'], 'quest_scene_skip_not_closed')

    def test_skip_on_unknown_tutorial_is_not_a_cinematic(self):
        self.tick(['scene_skip'])
        self.assertFalse(any(c == 'tap' for c, _ in self.host.calls))

    def test_drain_requires_prompt_and_fresh_target(self):
        result = self.tick(['tutorial_drain'])
        self.assertIsNone(result['error'])
        self.assertEqual(self.tick(['tutorial_drain'], after=21)['error'], 'quest_tutorial_target_not_found')
        self.assertFalse(any(c == 'tap' for c, _ in self.host.calls))
        self.assertEqual(self.tick(['tutorial_drain', 'tutorial_target_corner'])['step'], 'quest_tutorial_drain')
        _, args = self.host.calls[-1]
        self.assertEqual([args['x'], args['y']], [638, 278])

    def test_unknown_screen_does_not_receive_blind_input(self):
        self.assertIsNone(self.tick())
        result = self.tick(after=121)
        self.assertEqual(result['error'], 'quest_screen_not_recognized')
        self.assertFalse(result['retryable'])
        self.assertFalse(any(c == 'tap' for c, _ in self.host.calls))

    def test_disabled_quest_mode_never_calls_phone(self):
        self.settings['quest_enabled'] = False
        self.assertIsNone(self.tick(['tutorial_drain', 'tutorial_target_corner']))
        self.assertEqual(self.host.calls, [])

    def test_adrenaline_requires_prompt_and_target_and_bounds_retries(self):
        self.assertIsNone(self.tick(['tutorial_adrenaline'])['error'])
        self.assertFalse(any(c == 'tap' for c, _ in self.host.calls))
        for _ in range(2):
            self.assertEqual(self.tick(['tutorial_adrenaline', 'tutorial_adrenaline_frame'], after=9)['step'], 'quest_tutorial_adrenaline')
        self.assertEqual(self.tick(['tutorial_adrenaline', 'tutorial_adrenaline_frame'], after=9)['error'], 'quest_tutorial_not_advanced')
        self.assertEqual(sum(c == 'tap' for c, _ in self.host.calls), 2)

    def test_unknown_auto_state_is_bounded_without_input(self):
        self.assertEqual(self.tick(self.hud())['step'], 'quest_wait_state')
        self.assertEqual(self.tick(self.hud(), after=121)['error'], 'quest_auto_state_not_recognized')
        self.assertFalse(any(c == 'tap' for c, _ in self.host.calls))

    def test_source_delay_blocks_next_input_until_elapsed(self):
        result = self.tick(['tutorial_drain', 'tutorial_target_corner'])
        self.assertEqual(result['activePoint'], 'quest:110130/task:110130040/tutorial:4002/step:4')
        self.assertEqual(self.tick(['tutorial_drain_menu', 'game_menu'], after=3)['step'], 'quest_wait_action')
        self.assertEqual(sum(c == 'tap' for c, _ in self.host.calls), 1)
        self.assertEqual(self.tick(['tutorial_drain_menu', 'game_menu'], after=2)['step'], 'quest_tutorial_menu')
        self.assertEqual(sum(c == 'tap' for c, _ in self.host.calls), 2)

    def test_source_reference_never_authorizes_input_without_prompt(self):
        self.state['quest'] = dict(last_observed_tutorial=dict(tutorial_id='4002', step=4))
        self.tick(['game_menu', 'tutorial_target_corner'])
        self.assertFalse(any(c == 'tap' for c, _ in self.host.calls))

    def test_hud_clears_last_observed_tutorial(self):
        self.tick(['tutorial_drain', 'tutorial_target_corner'])
        result = self.tick(self.hud('quest_auto_on'), after=5)
        self.assertIsNone(result['activePoint'])

    def test_map_requires_both_anchors_waits_and_only_closes_once(self):
        self.tick(['world_map_header'])
        self.assertFalse(any(c == 'tap' for c, _ in self.host.calls))
        self.assertEqual(self.tick(['world_map_header', 'world_map_exit'])['step'], 'quest_wait_world_map')
        self.assertEqual(self.tick(['world_map_header', 'world_map_exit'], after=9)['step'], 'quest_close_world_map')
        self.tick(['world_map_header', 'world_map_exit'])
        self.assertEqual(sum(c == 'tap' for c, _ in self.host.calls), 1)
        self.assertEqual(self.tick(['world_map_header', 'world_map_exit'], after=21)['error'], 'quest_overlay_not_closed')

    def test_tutorial_has_priority_over_map_closing(self):
        self.tick(['world_map_header', 'world_map_exit'])
        result = self.tick(['world_map_header', 'world_map_exit', 'tutorial_quest', 'quest_anchor'], after=10)
        self.assertEqual(result['step'], 'quest_start_auto')

    def test_phone_lag_does_not_trigger_rapid_second_tap(self):
        visible = ['tutorial_adrenaline', 'tutorial_adrenaline_frame']
        self.tick(visible)
        self.assertEqual(self.tick(visible, after=3)['step'], 'quest_wait_action')
        self.assertEqual(sum(c == 'tap' for c, _ in self.host.calls), 1)
        self.tick(visible, after=6)
        self.assertEqual(sum(c == 'tap' for c, _ in self.host.calls), 2)

    def test_changed_catalog_binding_blocks_input(self):
        self.config['_chain_catalog']['steps']['4002004']['uiKey'] = 'OtherButton'
        result = self.tick(['tutorial_drain', 'tutorial_target_corner'])
        self.assertEqual(result['error'], 'quest_reference_mismatch')
        self.assertFalse(any(c == 'tap' for c, _ in self.host.calls))

    def test_variable_delay_never_shortens_source_minimum(self):
        self.config['interaction']['delay_jitter_sec'] = [.15, .65]
        self.tick(['tutorial_drain', 'tutorial_target_corner'])
        wait = self.state['quest']['settle_until'] - self.now
        self.assertGreaterEqual(wait, 4.65 - 1e-8)
        self.assertLessEqual(wait, 5.15 + 1e-8)

    def test_jitter_stays_inside_safe_target_with_varied_positions(self):
        points = {quests.tap_point(dict(point=[640, 360], rect=[635, 355, 645, 365]),
                                   dict(width=1280, height=720), dict(tap_jitter_px=3)) for _ in range(100)}
        self.assertGreater(len(points), 1)
        self.assertTrue(all(637 <= x <= 643 and 357 <= y <= 363 for x, y in points))

    def test_temporary_missing_target_recovers_without_blind_tap(self):
        self.tick(['tutorial_adrenaline'])
        self.assertFalse(any(c == 'tap' for c, _ in self.host.calls))
        self.tick(['tutorial_adrenaline', 'tutorial_adrenaline_frame'], after=5)
        self.assertEqual(sum(c == 'tap' for c, _ in self.host.calls), 1)

    def test_expected_source_step_is_context_not_an_input_command(self):
        self.tick(['tutorial_drain', 'tutorial_target_corner'])
        result = self.tick(after=1)
        self.assertEqual(result['reason'], 'expected_source_step:4002006')
        self.assertEqual(sum(c == 'tap' for c, _ in self.host.calls), 1)

    def test_reward_claim_requires_text_and_completion_check(self):
        self.tick(['claim_rewards_text'])
        self.assertFalse(any(c == 'tap' for c, _ in self.host.calls))
        visible = ['claim_rewards_text', 'guide_complete_check']
        self.assertEqual(self.tick(visible)['step'], 'claim_guide_reward')
        self.tick(visible, after=3)
        self.assertEqual(sum(c == 'tap' for c, _ in self.host.calls), 1)
        self.tick(visible, after=6)
        self.assertEqual(self.tick(visible, after=9)['error'], 'quest_action_not_advanced')

    def test_reward_overlay_requires_explicit_completion_title(self):
        self.tick(['reward_tap_close'])
        self.assertFalse(any(c == 'tap' for c, _ in self.host.calls))
        visible = ['quest_complete_title', 'reward_tap_close']
        self.assertEqual(self.tick(visible)['step'], 'quest_wait_quest_reward')
        self.assertEqual(self.tick(visible, after=3)['step'], 'quest_close_quest_reward')

    def test_passive_hud_reuses_no_matches_from_previous_frame(self):
        self.assertEqual(self.tick(self.hud('quest_auto_on'))['step'], 'quest_auto_running')
        self.host.calls=[]
        self.assertEqual(self.tick(self.hud('quest_auto_on'), after=1)['step'], 'quest_auto_observing')
        self.assertFalse(any(name=='tap' for name,_ in self.host.calls))
        matched=[args['name'] for name,args in self.host.calls if name=='match']
        self.assertNotIn('tutorial_bag', matched)
        self.assertIn('quest_auto_on', matched)
        self.assertIn('hud_inventory', matched)

    def test_passive_hud_full_discovery_is_periodic(self):
        self.tick(self.hud('quest_auto_on'))
        self.host.calls=[]
        result=self.tick(self.hud('quest_auto_on'), after=12)
        self.assertEqual(result['step'],'quest_auto_running')
        self.assertTrue(any(c=='match' and a['name']=='tutorial_bag' for c,a in self.host.calls))

    def test_tutorial_marker_interrupts_passive_hud(self):
        self.tick(self.hud('quest_auto_on'))
        result=self.tick(self.hud('quest_auto_on','tutorial_skip_left','tutorial_bag'),after=1)
        self.assertEqual(result['step'],'quest_tutorial_bag')

    def test_lost_hud_disables_passive_observation(self):
        self.tick(self.hud('quest_auto_on'))
        result=self.tick(['quest_auto_on'],after=1)
        self.assertNotEqual((result or {}).get('step'),'quest_auto_observing')
