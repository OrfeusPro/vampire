import importlib.util
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).parent/'rfonlinenext'
spec=importlib.util.spec_from_file_location('navigation',ROOT/'navigation.py')
nav=importlib.util.module_from_spec(spec);spec.loader.exec_module(nav)

class Host:
    def __init__(self):self.visible=set();self.calls=[];self.registered=True;self.point=[400,300]
    def call(self,command,**args):
        self.calls.append((command,args))
        if command=='match':
            if args['name']=='map_position':return dict(found=True,registered=self.registered,point=self.point)
            if args['name']=='hud_map_anchor':return dict(found='hud_eye' in self.visible,point=[29,23],rect=[18,10,40,37])
            if args['name']=='auto_off' and 'hud_auto' in self.visible:return dict(found=True,point=[1200,425])
            return dict(found=args['name'] in self.visible,point=[400,300])
        return {}

class Navigation(unittest.TestCase):
    def setUp(self):
        self.host=Host();self.state={};self.now=100
        self.config=json.loads((ROOT/'vision.json').read_text())
        self.settings=dict(farm_enabled=True,active_farm_map_spot_id='test',farm_map_spots=[dict(id='test',map_id='novus_world_101',enabled=True,map_points=[[.31,.56]])])
    def tick(self,visible=(),after=2):
        self.now+=after;self.host.visible=set(visible)
        return nav.tick(self.host,self.settings,self.state,dict(width=1280,height=576),self.config,self.now)
    def map_selection(self):
        self.tick();self.tick(['hud_eye','hud_auto'])
        for _ in range(3):self.assertEqual(self.tick(['map_title'])['step'],'map')
        self.assertEqual(self.tick(['map_title'])['step'],'point_menu')
    def test_full_walk_arrival_and_auto_once(self):
        self.map_selection();self.assertEqual(self.tick(['map_title','map_walk'])['step'],'travelling')
        self.tick(['hud_eye','hud_auto'],after=4)
        self.tick(['map_title','arrival_0']);self.assertEqual(self.tick(['map_title','arrival_0'])['step'],'enable_auto')
        self.tick(['hud_eye','hud_auto','auto_off'])
        self.assertEqual(self.tick(['hud_eye','auto_on'])['step'],'farming')
        actions=len([c for c in self.host.calls if c[0]!='match'])
        for _ in range(10):self.assertEqual(self.tick(['hud_eye','auto_on'])['step'],'farming')
        self.assertEqual(len([c for c in self.host.calls if c[0]!='match']),actions)
        gestures=[a for c,a in self.host.calls if c=='gesture'];self.assertEqual(len(gestures),3)
        self.assertTrue(all(len(a['strokes'])==2 for a in gestures))
    def test_unreachable_point_pauses_without_input(self):
        self.tick();result=self.tick(['point_unreachable']);self.assertEqual(result['error'],'farm_point_unreachable');self.assertFalse(result['retryable'])
        self.assertFalse(any(c!='match' for c,a in self.host.calls))
    def test_failed_fit_does_not_click_and_times_out(self):
        self.tick();self.host.registered=False
        self.assertEqual(self.tick(['map_title'],after=21)['error'],'farm_open_not_recognized')
        self.assertFalse(any(c!='match' for c,a in self.host.calls))
    def test_arrival_requires_two_positive_checks(self):
        self.map_selection();self.tick(['map_title','map_walk']);self.tick(['hud_eye','hud_auto'],after=4)
        self.assertEqual(self.tick(['map_title'])['step'],'travelling')
        self.assertFalse(any(c=='back' and a.get('phase')=='enable_auto' for c,a in self.host.calls))
    def test_no_blind_teleport_confirmation(self):
        self.settings['farm_map_spots'][0]['travel_mode']='teleport';self.map_selection();self.tick(['map_title','map_teleport'])
        before=sum(c=='tap' for c,a in self.host.calls)
        self.tick(['point_confirm_button']);self.assertEqual(sum(c=='tap' for c,a in self.host.calls),before)
        self.tick(['point_confirm_title','point_confirm_button','point_coin'])
        self.assertEqual(sum(c=='tap' for c,a in self.host.calls),before+1)
        self.tick(['point_confirm_title','point_confirm_button','point_coin'])
        self.assertEqual(sum(c=='tap' for c,a in self.host.calls),before+1)
    def test_invalid_target_never_taps(self):
        self.settings['farm_map_spots'][0]['map_points']=[[2,.5]]
        self.assertEqual(self.tick()['error'],'invalid_farm_point');self.assertEqual(self.host.calls,[])

    def test_teleport_requires_title_currency_and_button_on_other_device(self):
        self.settings['farm_map_spots'][0]['travel_mode']='teleport'
        self.map_selection();self.tick(['map_title','map_teleport_vivo'])
        before=sum(c=='tap' for c,a in self.host.calls)
        self.tick(['point_confirm_title_vivo','point_confirm_button_vivo'])
        self.assertEqual(sum(c=='tap' for c,a in self.host.calls),before)
        result=self.tick(['point_confirm_title_vivo','point_confirm_button_vivo','point_coin_vivo'])
        self.assertEqual(result['step'],'travelling')
        self.assertEqual(sum(c=='tap' for c,a in self.host.calls),before+1)

    def test_start_at_target_skips_point_menu_and_teleport(self):
        self.settings['farm_map_spots'][0]['travel_mode']='teleport'
        self.tick();self.tick(['hud_eye','hud_auto'])
        for _ in range(3):self.tick(['map_title'])
        self.assertEqual(self.tick(['map_title','arrival_0'])['step'],'verify_arrival')
        self.assertEqual(self.tick(['map_title','arrival_0'])['step'],'enable_auto')
        self.assertFalse(any(c=='longPress' for c,a in self.host.calls))
        self.assertEqual(self.tick(['hud_eye','auto_on'])['step'],'farming')
    def test_flattened_points_report_configuration_error(self):
        self.settings['farm_map_spots'][0]['map_points']=[.31,.56]
        self.assertEqual(self.tick()['error'],'invalid_farm_point');self.assertEqual(self.host.calls,[])
    def test_launch_screen_returns_to_launch_recognizer(self):
        self.tick();self.assertIsNone(self.tick(['touch_to_start']))
    def test_disabling_farm_clears_route(self):
        self.tick();self.settings['farm_enabled']=False;self.assertIsNone(self.tick());self.assertNotIn('route',self.state)
    def test_offline_result_is_closed_once_only_with_its_title(self):
        self.tick();self.tick(['offline_result_close'])
        self.assertFalse(any(c=='tap' for c,a in self.host.calls))
        self.tick(['offline_result','offline_result_close'])
        self.assertEqual(sum(c=='tap' for c,a in self.host.calls),1)
        self.assertEqual(self.tick(['offline_result','offline_result_close'])['error'],'offline_result_not_closed')

    def test_shifted_scaled_anchor_controls_map_tap(self):
        original=self.host.call
        def shifted(command,**args):
            result=original(command,**args)
            if command=='match' and args['name']=='hud_map_anchor':
                return dict(found=True,point=[51,38],rect=[38,22,64,54])
            return result
        self.host.call=shifted;self.tick();self.tick(['hud_eye','hud_auto'])
        tap=next(a for c,a in self.host.calls if c=='tap')
        self.assertAlmostEqual(tap['x'],51+120*26/22,delta=1)
        self.assertAlmostEqual(tap['y'],38+65*26/22,delta=1)
    def test_missing_anchor_does_not_tap_map_even_with_auto_visible(self):
        self.tick();self.tick(['auto_on'],after=4)
        self.assertFalse(any(c=='tap' for c,a in self.host.calls))
    def test_sleep_text_without_dark_screen_does_not_swipe(self):
        self.tick();self.tick(['sleep_title'])
        self.assertFalse(any(c=='swipe' for c,a in self.host.calls))
    def test_sleep_exit_is_bounded(self):
        self.tick()
        for _ in range(3):self.tick(['sleep_title','sleep_dark'])
        self.assertEqual(self.tick(['sleep_title','sleep_dark'])['error'],'farm_sleep_not_closed')
        self.assertEqual(sum(c=='swipe' for c,a in self.host.calls),3)

if __name__=='__main__':unittest.main()
