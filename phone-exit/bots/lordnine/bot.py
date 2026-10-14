"""Lord Nine local state machine. Every action is bounded by a fresh screen check.

No OCR. Imported coordinates, thresholds, intervals and game Auto Purchase are used.
Travel plans preserve the old entrance, floor and district destinations.
"""
import json
import importlib.util
import random
import re
import time
import base64
import hashlib
import struct
from pathlib import Path

_resources = {}


def resources(directory):
    if directory not in _resources:
        root = Path(directory)
        spec = importlib.util.spec_from_file_location('phoneexit_navigation', root / 'navigation.py')
        navigation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(navigation)
        _resources[directory] = (json.loads((root / 'imported.json').read_text('utf-8')),
                                 json.loads((root / 'maps/index.json').read_text('utf-8')), navigation)
    return _resources[directory]


def active_spot(settings):
    spots = [p for p in settings.get('farm_map_spots', []) if p.get('enabled', True)]
    return next((p for p in spots if p['id'] == settings.get('active_farm_map_spot_id')),
                spots[0] if spots else None)


def tick(host, settings, state, directory):
    class MeasuredHost:
        def __init__(self):
            self.last = 'starting'
            self.slow = []

        def call(self, command, **args):
            self.last = command + ('_' + args['name'] if command == 'match' else '')
            started = time.perf_counter()
            try:
                return host.call(command, **args)
            finally:
                self.slow.append((round((time.perf_counter() - started) * 1000), self.last))
                self.slow = sorted(self.slow, reverse=True)[:5]

    measured = MeasuredHost()
    try:
        result = _tick(measured, settings, state, directory)
        if measured.slow and measured.slow[0][0] > 200 and not result.get('reason'):
            result['reason'] = 'slow_' + measured.slow[0][1] + '_' + str(measured.slow[0][0]) + 'ms'
        return result
    except Exception as error:
        message = str(error)
        if message == 'bot_game_not_foreground' and settings.get('autostart_enabled'):
            # The bridge rejected input after the fresh capture. Do not replay
            # that purchase/tap: the next tick must recognise the screen anew.
            state.clear()
            state['phase'] = 'monitoring'
            return {'status': 'waiting', 'step': 'waiting_game_foreground',
                    'error': None, 'reason': message}
        safe = message if re.fullmatch(r'[a-z0-9_]{1,80}', message) else 'bot_script_error'
        return {'status': 'error', 'step': state.get('phase', 'recognizing_screen'),
                'error': safe, 'reason': measured.last, 'pause': True}


def _tick(host, settings, state, directory):
    # Each tick starts after the previous action completed. An edited route or
    # disabled service must never continue using state from the old settings.
    fingerprint = json.dumps(settings, sort_keys=True, separators=(',', ':'))
    previous = state.get('settings_fingerprint')
    state['settings_fingerprint'] = fingerprint
    if previous is not None and previous != fingerprint:
        interrupted = state.get('phase', 'monitoring') != 'monitoring'
        state.clear()
        state['settings_fingerprint'] = fingerprint
        state['phase'] = 'monitoring'
        return {'status': 'paused' if interrupted else 'running',
                'step': 'settings_changed', 'activePoint': settings.get('active_farm_map_spot_id'),
                'error': 'settings_changed_during_action' if interrupted else None,
                'reason': None, 'pause': interrupted}
    config, catalog, navigation = resources(directory)
    now = time.monotonic()
    waiting = now < state.get('wait_until', 0)
    if waiting and now - state.get('last_wait_check', -100000) < max(.1, config['timeouts'].get('responsive_wait_poll_sec', .75)):
        return {'status': 'running', 'step': state.get('phase', 'waiting'),
                'activePoint': settings.get('active_farm_map_spot_id'), 'error': None, 'reason': None}
    if waiting:
        state['last_wait_check'] = now
    try:
        foreground = host.call('foreground').get('package')
    except Exception as error:
        if str(error) != 'foreground_unavailable':
            raise
        # Android can briefly have no active accessibility window while the
        # game starts or rotates. Wait without launching or sending any input.
        missing_since = state.setdefault('foreground_missing_since', now)
        expired = now - missing_since >= config['game'].get('foreground_check_timeout_sec', 10)
        return {'status': 'paused' if expired else 'waiting',
                'step': 'waiting_foreground', 'reason': 'foreground_unavailable',
                'error': 'foreground_unavailable' if expired else None,
                'pause': expired}
    state.pop('foreground_missing_since', None)
    if foreground != config['game']['package']:
        if not settings.get('autostart_enabled'):
            return {'status': 'waiting', 'step': 'game_not_foreground', 'pause': True,
                    'error': 'game_not_foreground'}
        launch_timeout = config['game'].get('start_timeout_sec', 90)
        elapsed = now - state.get('last_launch', -100000)
        if elapsed < launch_timeout:
            return {'status': 'waiting', 'step': 'waiting_game_launch'}
        if state.get('launch_pending'):
            return {'status':'paused', 'step':'waiting_game_launch',
                    'error':'game_launch_timeout', 'pause':True}
        host.call('launch', package=config['game']['package'])
        # Restart from recognition, never replay an interrupted purchase or
        # continue an old route after returning from another Android screen.
        state.clear()
        state.update(settings_fingerprint=fingerprint, phase='monitoring',
                     last_launch=time.monotonic(), launch_pending=True, entry_autobattle_pending=True)
        return {'status': 'running', 'step': 'launch_game', 'error':None, 'reason':None}
    state.pop('launch_pending', None)
    frame = host.call('capture')
    width, height = frame['width'], frame['height']
    specs = config['vision']['templates']
    matches = {}

    def match(name, spec=None):
        if name.startswith('launch_') and height > width:
            return {'found': False, 'confidence': 0}
        if name not in matches:
            value = dict(spec if spec is not None else specs.get(name, {}))
            value.setdefault('threshold', config['vision'].get('default_threshold', .82))
            matches[name] = host.call('match', name=name, spec=value)
        return matches[name]

    def found(name):
        if name == 'world_map_title':
            return map_open()
        if name == 'power_saving':
            if match(name)['found']:
                return True
            # Same non-OCR fallback as MultiBot.detect_power_saving_screen.
            # Older engines return false for this optional additive detector.
            colors = match('power_saving_colors', {'detector': {
                'type': 'power_saving_colors', 'detector_only': True}})
            return colors['found'] and match('power_saving_emblem')['found']
        return match(name)['found']

    def tap(point):
        if not point or len(point) != 2:
            raise RuntimeError('bot_calibration_required')
        host.call('tap', x=min(width - 1, max(0, round(point[0] * width))),
                  y=min(height - 1, max(0, round(point[1] * height))), width=width, height=height)

    def named(point):
        if point == 'dungeon_map_close':
            exit_button = match('world_map_exit')
            if exit_button['found']:
                host.call('tap', x=exit_button['point'][0], y=exit_button['point'][1], width=width, height=height)
                return
        tap(config['tap_points'].get(point))

    def template(name):
        item = match(name)
        if not item['found']:
            raise RuntimeError('bot_template_required')
        host.call('tap', x=item['point'][0], y=item['point'][1], width=width, height=height)

    def phase(value, delay=0):
        state['phase'] = value
        state['since'] = time.monotonic()
        state['wait_until'] = state['since'] + delay

    def report(step, **extra):
        return {'status': 'running', 'step': step, 'activePoint': settings.get('active_farm_map_spot_id'),
                'error': None, 'reason': None, **extra}

    def pause(error):
        return report(state.get('phase', 'monitoring'), status='error', error=error, pause=True)

    def hud():
        # These are exactly launch_flow's done templates. Broad HUD-bars
        # templates also match the Lord Nine logo and cannot end login.
        if any(found(n) for n in ('game_inventory_icon', 'game_world', 'town_supplies_icon')):
            return True
        # MultiBot also recognises AUTO in its gameplay HUD predicate. Require
        # its actual minimap as corroboration: a login logo is not gameplay.
        return minimap()[0] and (found('auto_battle_on') or found('auto_battle_off'))

    def features(name, region):
        return match(name, {'region': region, 'detector': {'type': 'region_features'}})

    def minimap():
        pin = match('farm_minimap_pin', {'file': 'dungeon_minimap_toggle_icon.png', 'detector': {'type': 'minimap_pin'}})
        if 'panelVisible' in pin:
            return pin['panelVisible'], pin
        vision = config['vision']
        value = features('farm_minimap_features', vision.get('farm_minimap_visible_region', [.065,.145,.225,.335]))
        if 'edgeRatio' not in value:
            return False, pin
        dark = value['darkMapRatio'] >= vision.get('farm_minimap_dark_ratio', .45) and value['edgeRatio'] >= vision.get('farm_minimap_edge_ratio', .035)
        bright = value['brightTownRatio'] >= vision.get('farm_minimap_bright_ratio', .60) and value['meanSaturation'] <= vision.get('farm_minimap_bright_mean_saturation_max', 100) and value['edgeRatio'] >= vision.get('farm_minimap_bright_edge_ratio', .035)
        return dark or bright, pin

    def map_open():
        if match('world_map_title')['found']:
            return True
        if found('power_saving') or found('game_inventory_icon') or found('town_supplies_icon') or found('dungeon_title'):
            return False
        vision = config['vision']
        paths = features('farm_map_paths', vision.get('darkwood_world_map_region', [.22,.16,.78,.84]))
        if paths.get('pathRatio', 0) < vision.get('darkwood_world_map_path_ratio', .055) or minimap()[0]:
            return False
        left = features('farm_map_left', [0,.13,.235,.91])
        right = features('farm_map_right', [.735,.10,.99,.92])
        center = features('farm_map_center', [.24,.16,.76,.84])
        layout = left.get('dark70Ratio', 0) >= vision.get('farm_world_map_layout_left_dark_ratio', .45) and right.get('dark60Ratio', 0) >= vision.get('farm_world_map_layout_right_dark_ratio', .45) and right.get('edgeRatio', 0) >= vision.get('farm_world_map_layout_right_edge_ratio', .010) and center.get('dark80Ratio', 0) >= vision.get('farm_world_map_layout_center_dark_ratio', .45)
        return layout or vision.get('farm_world_map_allow_path_only', False)

    def farm_confirmation():
        vision = config['vision']
        def button(name, regions, hues, area):
            return match(name, {'detector': {'type': 'colored_button',
                'regions': vision.get(name + '_search_regions', regions),
                'hueRanges': hues, 'minArea': vision.get(name + '_min_area', area)}})
        ok = button('farm_ok_button', [[.46,.49,.70,.64],[.45,.58,.72,.74]], [[78,112]], 850)
        cancel = button('farm_cancel_button', [[.30,.49,.52,.64],[.30,.58,.53,.74]], [[0,10],[165,179]], 700)
        y_min, y_max = vision.get('farm_transition_popup_ok_y_range', [.50,.62])
        prompt = ok['found'] and y_min*height <= ok['point'][1] <= y_max*height
        for name in ('farm_fast_travel_ok', 'daily_fast_travel_ok_button', 'daily_renew_ok_button'):
            value = match(name)
            if value['found'] and (cancel['found'] or prompt):
                return value['point']
        return ok['point'] if ok['found'] and (cancel['found'] or prompt) else None

    def current_location():
        candidates = []
        for item in catalog['maps']:
            name = item['id']
            file = 'farm_current_locations/' + name + '.png'
            encoded = settings.get('current_location_templates', {}).get(name)
            if encoded:
                data = base64.b64decode(encoded, validate=True)
                if len(data) > 65536 or data[:8] != b'\x89PNG\r\n\x1a\n' or len(data)<24:
                    raise RuntimeError('editor_invalid_template')
                tw, th = struct.unpack('>II', data[16:24])
                if not (1 <= tw <= 1024 and 1 <= th <= 256):
                    raise RuntimeError('editor_invalid_template')
                file = 'editor/' + hashlib.sha256(data).hexdigest() + '.png'
                dest = Path(directory) / 'templates' / file
                if not dest.exists():
                    dest.parent.mkdir(exist_ok=True)
                    pending = dest.with_suffix('.tmp')
                    pending.write_bytes(data)
                    pending.replace(dest)
            spec = {'file': file,
                    'region': config['vision'].get('farm_current_location_template_region', [.015, .065, .385, .17]),
                    'threshold': config['vision'].get('farm_current_location_template_threshold', .82)}
            value = match('location_' + name, spec)
            candidates.append({'confidence': value['confidence'], 'map_id': name, 'found': value['found'], 'catalog': True})
        # Old fixed Tyriosa templates supplement the captured catalog templates.
        fixed = [('farm_current_location_tyriosa_' + floor.lower(), map_id) for floor, map_id in navigation.TYRIOSA_FLOORS.items()]
        fixed += [('farm_current_location_ulan', 'tab3_row1_ulan'), ('farm_current_location_desert_of_the_screaming', navigation.TYRIOSA_DESERT)]
        for name, map_id in fixed:
            value = match(name)
            candidates.append({'confidence': value['confidence'], 'map_id': map_id, 'found': value['found'], 'catalog': False})
        return navigation.choose_location(candidates, config['vision'])

    # These are identified notice bodies, not a generic OK-button detector.
    # Drop interrupted input before reconnecting; never replay a purchase.
    notice = ('session_timeout' if found('timeout_notification') else
              'network_error' if found('game_server_error_t005') or found('disconnected') else None)
    if notice:
        if not settings.get('autostart_enabled'):
            return pause('game_reconnect_disabled')
        if not state.get('notice_active'):
            attempts, retry_at = state.get('notice_attempts', 0), state.get('notice_retry_at', 0)
            state.clear()
            state.update(settings_fingerprint=fingerprint, phase='monitoring',
                         notice_recovery=True, notice_active=True, entry_autobattle_pending=True,
                         notice_attempts=attempts, notice_retry_at=retry_at)
        if now < state.get('notice_retry_at', 0):
            return report('waiting_game_reconnect', status='waiting', reason=notice)
        button_name = 'timeout_notification_ok' if notice == 'session_timeout' else 'game_notice_ok'
        button = match(button_name)
        if not button['found'] and notice == 'network_error':
            button_name = 'game_notice_ok_large'
            button = match(button_name)
        if not button['found']:
            # Do not guess at a new dialog's coordinates.
            if now - state.setdefault('notice_button_since', now) > 15:
                return pause('game_notice_ok_not_found')
            return report('waiting_game_notice_button', status='waiting', reason=notice)
        state.pop('notice_button_since', None)
        attempts = state.get('notice_attempts', 0)
        template(button_name)
        state.update(notice_attempts=attempts + 1,
                     notice_retry_at=time.monotonic() + min(60, 15 * 2 ** min(attempts, 2)),
                     notice_gone_since=None)
        phase('monitoring', 2)
        return report('dismiss_' + notice, status='waiting', reason=notice)
    if state.get('notice_recovery'):
        state.pop('notice_active', None)
        # Reset the retry budget only after the notice has stayed absent.
        if state.get('notice_gone_since') is None:
            state['notice_gone_since'] = now
        if now - state['notice_gone_since'] >= 60:
            for key in ('notice_recovery', 'notice_gone_since', 'notice_retry_at', 'notice_attempts'):
                state.pop(key, None)

    editor = settings.get('editor_request')
    if editor:
        map_id = editor.get('map_id')
        item = next((item for item in catalog['maps'] if item['id'] == map_id), None)
        if not item:
            return pause('editor_unknown_map')
        if not match('world_map_title')['found']:
            if state.get('editor_map_opened'):
                if now - state['editor_map_opened'] > config['timeouts'].get('service_screen_timeout_sec', 12):
                    return pause('editor_map_not_opened')
                return report('editor_waiting_map')
            if not hud() or not minimap()[0]:
                return pause('editor_open_map_required')
            named('dungeon_map_open')
            state['editor_map_opened'] = time.monotonic()
            state['wait_until'] = time.monotonic() + config['timeouts'].get('dungeon_map_open_sec', 1.2)
            return report('editor_open_map')
        if editor.get('kind') == 'capture':
            return report('editor_capture_ready', status='paused', pause=True, reason='editor_capture_ready')
        if current_location() != map_id:
            return pause('editor_current_location_mismatch')
        options = navigation.marker_options(config, map_id)
        options['search_around'] = False
        # F's current-map-point uses the general marker settings and no target,
        # unlike route arrival checks which use floor-specific angle lists.
        options['angles'] = config['vision'].get('map_navigation_marker_angles', list(range(0,360,45)))
        value = navigation.find_marker(match, options, config['vision'], item, None, width, height)
        if not value.get('found'):
            state['editor_marker_attempts'] = state.get('editor_marker_attempts', 0) + 1
            if state['editor_marker_attempts'] < 3:
                state['wait_until'] = time.monotonic() + 1.2
                return report('editor_waiting_arrow', reason='marker_confidence_%.4f' % value.get('confidence',0))
            return pause('editor_player_arrow_not_found')
        x, y = value['point']
        return report('editor_point_ready', status='paused', pause=True,
                      reason='editor_point_%.8f_%.8f' % (x/width, y/height))

    # Reconcile actual screen after restart: never restore an unconfirmed purchase/tap.
    if found('game_update_notice_title'):
        return pause('game_notice_requires_attention')
    if state.get('phase') == 'revive_wait' and now < state.get('wait_until', 0):
        return report('waiting_after_revive')
    if found('death_popup') or found('revive_button') or found('died_text') or found('power_saving_died_text'):
        if not settings.get('recovery_enabled'):
            return pause('recovery_disabled')
        if found('revive_button'):
            template('revive_button')
            state['serviced'] = False
            state['recovery_dismantle_pending'] = True
            state['at_farm'] = False
            phase('revive_wait', config['timeouts'].get('revive_to_town_sec', 10))
        else:
            return report('waiting_revive_button')
        return report('revive')
    # Original farm.wait uses wait_with_status_checks: preserve its deadline,
    # but inspect death/disconnection while waiting and never replay the action.
    if waiting and now < state.get('wait_until', 0):
        return report(state.get('phase', 'waiting'))
    # Original wake_power_saving_checked closes a quit popup after Back
    # before attempting the fallback swipes. A genuine farm entry keeps priority.
    if found('quit_game_popup') and found('quit_game_cancel') and not (state.get('phase', '').startswith('farm_') and farm_confirmation()):
        template('quit_game_cancel')
        return report('close_quit_popup')
    if found('power_saving'):
        if 'wake_attempts' not in state:
            host.call('back')
            state['wake_attempts'] = 0
        else:
            attempts = config['timeouts'].get('power_saving_wake_swipe_attempts', 2)
            if state['wake_attempts'] >= attempts:
                return pause('power_saving_wake_failed')
            start, end = config['tap_points']['power_saving_wake_start'], config['tap_points']['power_saving_wake_end']
            host.call('swipe', x1=round(start[0]*width), y1=round(start[1]*height), x2=round(end[0]*width), y2=round(end[1]*height), width=width, height=height,
                      durationMs=config['timeouts'].get('power_saving_wake_swipe_duration_ms', 900))
            state['wake_attempts'] += 1
        state['wait_until'] = time.monotonic() + config['timeouts'].get('daily_wake_sec', 2)
        return report('wake_power_saving')
    state.pop('wake_attempts', None)
    if found('loading'):
        if state.get('phase') == 'farm_travel_confirm' and state.get('route'):
            leg = state['route'][state.get('route_index', 0)]
            state['farm_loading_outcome'] = 'farm_transition' if leg.get('transition') else 'farm_arrival'
        if now - state.setdefault('loading_since', now) > config['timeouts'].get('farm_loading_screen_timeout_sec', config['timeouts'].get('farm_transition_popup_timeout_sec', 75)):
            return pause('game_loading_timeout')
        state['wait_until'] = time.monotonic() + config['timeouts'].get('farm_loading_screen_poll_sec', 1)
        return report('loading')
    state.pop('loading_since', None)
    if state.get('farm_loading_outcome'):
        outcome = state.pop('farm_loading_outcome')
        phase(outcome, config['timeouts'].get('farm_after_fast_travel_sec', 5))
        return report('waiting_after_farm_loading')
    if found('party_search_title'):
        if state.get('party_close_started') is not None:
            if now - state['party_close_started'] >= config['timeouts'].get('service_screen_timeout_sec', 12):
                return pause('party_search_not_closed')
            return report('waiting_party_search_closed')
        if found('party_search_close'):
            template('party_search_close')
            state['party_close_started'] = time.monotonic()
            return report('close_party_search')
        return pause('party_search_close_not_found')
    state.pop('party_close_started', None)
    if found('auto_hunt_result_title') and found('auto_hunt_result_ok'):
        template('auto_hunt_result_ok')
        return report('close_auto_hunt_result')

    if (state.get('phase', '').startswith('dismantle_') or state.get('phase', 'monitoring') == 'monitoring') and match('dismantle_rare_warning', {
            'file': 'dismantle_rare_warning.png', 'threshold': .88,
            'region': [.34,.44,.66,.55]})['found']:
        if not settings.get('auto_dismantle_enabled') or settings.get('confirm_rare_dismantle_enabled') is not True:
            return pause('dismantle_rare_items_confirmation_required')
        if state.get('rare_confirm_sent'):
            if now - state['rare_confirm_sent'] >= config['timeouts'].get('service_screen_timeout_sec', 12):
                return pause('dismantle_rare_confirmation_not_closed')
            return report('waiting_dismantle_rare_confirmation')
        if not found('dismantle_rare_ok'):
            if now - state.setdefault('rare_button_since', now) > 12:
                return pause('dismantle_rare_ok_not_found')
            return report('waiting_dismantle_rare_ok')
        template('dismantle_rare_ok')
        state['rare_confirm_sent'] = time.monotonic()
        state.pop('rare_button_since', None)
        phase('dismantle_result', 1)
        return report('confirm_dismantle_rare_items')

    # MultiBot recover_open_mail and fresh-screen reconciliation take priority
    # over login, floor timeouts and restore-icon checks on an obscured HUD.
    current = state.get('phase', 'monitoring')
    mail = next((name for name in ('mail_confirm_popup', 'mail_reward', 'mail_screen') if found(name)), None)
    shop = found('supplies_shop') or found('auto_purchase')
    dismantle = found('dismantle_quick_add_button') or found('dismantle_result')
    inventory = found('inventory_dismantle_button') or found('inventory_auto_sell_button')
    orphan = ('mail' if mail else 'shop' if shop and not current.startswith('shop_') and current != 'farm_map_open' else
              'dismantle' if dismantle and not current.startswith('dismantle_') else
              'inventory' if inventory and not current.startswith('dismantle_') else None)
    if orphan:
        if 'overlay_since' not in state:
            state['overlay_since'] = now
            state['overlay_attempts'] = 0
            # Re-evaluate location after closing; don't replay the old route.
            for key in ('route', 'at_farm', 'destination', 'arrival_started', 'prepare_route',
                        'launch_since', 'launch_actions', 'launch_done_until', 'entry_wait_started', 'unknown_since'):
                state.pop(key, None)
        if state.get('overlay_attempts', 0) >= 3 or now-state['overlay_since'] > config['timeouts'].get('service_screen_timeout_sec', 12):
            return pause('interrupted_' + orphan + '_not_closed')
        if orphan == 'mail':
            named('mail_reward_confirm' if mail == 'mail_confirm_popup' else 'mail_reward_dismiss' if mail == 'mail_reward' else 'mail_close')
        elif orphan == 'shop':
            if found('auto_purchase_ok'):
                host.call('back')  # Cancel an interrupted purchase, not replay OK.
            else:
                named('shop_exit')
        elif orphan == 'dismantle':
            named('dismantle_result_close' if found('dismantle_result') else 'dismantle_window_close')
        else:
            host.call('back')
        state['overlay_attempts'] += 1
        phase('overlay_close', config['timeouts'].get('shop_close_sec', 4) if orphan == 'shop' else config['timeouts'].get('popup_close_sec', 1.5))
        return report('close_interrupted_' + orphan)
    if current == 'overlay_close':
        if hud() or match('world_map_title')['found']:
            state.pop('overlay_since', None)
            state.pop('overlay_attempts', None)
            phase('monitoring')
            return report('interrupted_window_closed')
        if now-state.get('overlay_since', now) > config['timeouts'].get('service_screen_timeout_sec', 12):
            return pause('interrupted_window_hud_not_verified')
        return report('waiting_interrupted_window_closed')

    # A dark launch background can satisfy the map layout fallback. Only the
    # actual title template may bypass login before gameplay is recognized.
    launch_screen = next((screen for screen in config['game'].get('launch_flow', {}).get('screens', [])
                          if not screen.get('done') and screen.get('template') and found(screen['template'])), None)
    if (launch_screen or state.get('launch_since') is not None or state.get('launch_pending')
            or state.get('entry_wait_started') is not None) and not hud() and not match('world_map_title')['found']:
        flow = config['game'].get('launch_flow', {})
        if launch_screen and not state.get('entry_autobattle_pending'):
            # MultiBot handles login before farm/service. Clear interrupted
            # action state, but retain the reconnect backoff and settings.
            if not settings.get('autostart_enabled'):
                return pause('autostart_disabled')
            preserved = {key: value for key, value in state.items()
                         if key.startswith('notice_') or key == 'settings_fingerprint'}
            state.clear()
            state.update(preserved, phase='monitoring', launch_since=now,
                         entry_autobattle_pending=True)
        if state.get('launch_done_until'):
            if now >= state['launch_done_until']:
                # Original start_game_and_wait verifies the screen again,
                # then gives handle_launch_screen_if_needed a bounded rescue.
                state.pop('launch_done_until', None)
                state['launch_fallback_until'] = now + flow.get('fallback_timeout_sec', 30)
                state['launch_fallback_actions'] = 0
            else:
                return report('waiting_game_launch_done')
        if state.get('launch_fallback_until') and now >= state['launch_fallback_until']:
            return pause('game_launch_done_timeout')
        if state.get('launch_since') is not None and now - state['launch_since'] > flow.get('max_seconds', 210):
            return pause('game_launch_timeout')
        for screen in flow.get('screens', []):
            name = screen.get('template')
            if name and not screen.get('done') and found(name):
                if screen.get('only_during_start') and state.get('launch_fallback_until'):
                    continue
                if not settings.get('autostart_enabled'):
                    return pause('autostart_disabled')
                state.setdefault('launch_since', now)
                state['entry_autobattle_pending'] = True
                counts = state.setdefault('launch_actions', {})
                if sum(counts.values()) >= flow.get('max_steps', 35):
                    return pause('game_launch_action_limit')
                count = counts.get(screen['name'], 0)
                if count >= screen.get('max_actions', 9999):
                    state['wait_until'] = now + flow.get('poll_sec', 1)
                    return report('waiting_launch_' + screen['name'])
                if not screen.get('point_name'):
                    return report('waiting_launch_' + screen['name'])
                if state.get('launch_fallback_until'):
                    if state.get('launch_fallback_actions', 0) >= flow.get('fallback_action_attempts', 3):
                        return report('waiting_game_launch_done')
                    state['launch_fallback_actions'] = state.get('launch_fallback_actions', 0) + 1
                named(screen['point_name'])
                counts[screen['name']] = count + 1
                phase('monitoring', screen.get('wait_sec', 1))
                if screen.get('wait_for_done_after_action') and not state.get('launch_fallback_until'):
                    state['launch_done_until'] = state['wait_until'] + screen.get('done_timeout_sec', 120)
                return report('launch_' + screen['name'], reason='connect_' + str(round(match('launch_connect')['confidence'], 3)) + '_tap_' + str(round(match('launch_tap_to_start')['confidence'], 3)))
        if state.get('launch_fallback_until'):
            return report('waiting_game_launch_done')
        if settings.get('autostart_enabled') and not state.get('gameplay_seen'):
            # A restarted bot may attach while login is already loading, so no
            # launch command or first button has armed a bounded entry budget.
            # Known buttons above still act immediately; no blind loading taps.
            started = state.setdefault('entry_wait_started', now)
            if now - started < config['game'].get('initial_recognition_timeout_sec', 20):
                return report('waiting_game_launch')
            return pause('game_launch_timeout')
        if now - state.get('last_launch', -100000) < config['game'].get('start_timeout_sec', 90):
            return report('waiting_game_launch')
        state.setdefault('unknown_since', now)
        if now - state['unknown_since'] > 12:
            return report('recognizing_screen', status='error', error='unrecognized_game_screen', pause=True,
                          reason='connect_' + str(round(match('launch_connect')['confidence'], 3)) + '_tap_' + str(round(match('launch_tap_to_start')['confidence'], 3)))
        return report('recognizing_screen')
    if state.get('entry_autobattle_pending') and hud() and found('launch_offer_close'):
        # MultiBot Actions.close_launch_offer: real close template, max 3.
        count = state.get('launch_offer_close_count', 0)
        if count >= 3:
            return pause('launch_offer_not_closed')
        template('launch_offer_close')
        state['launch_offer_close_count'] = count + 1
        state['wait_until'] = time.monotonic() + config['game'].get('launch_flow', {}).get('poll_sec', 1)
        return report('close_launch_offer')
    if hud() or match('world_map_title')['found']:
        state.pop('unknown_since', None)
        state['gameplay_seen'] = True
        state.pop('entry_wait_started', None)
        for key in ('launch_since', 'launch_actions', 'launch_done_until', 'launch_fallback_until', 'launch_fallback_actions', 'launch_offer_close_count'):
            state.pop(key, None)


    current = state.get('phase', 'monitoring')
    timeout = config['timeouts'].get('service_screen_timeout_sec', 12)
    if not current.startswith('farm_') and current not in ('monitoring', 'revive_wait') and now - state.get('since', now) > timeout:
        # MultiBot wait_for_service_condition checks the latest predicate
        # before declaring timeout. Slow vision must not reject a ready screen.
        predicates = {
            'restore_open': lambda: found('stat_restore_window'),
            'restore_close': lambda: True,
            'shop_open': lambda: found('supplies_shop') or found('auto_purchase'),
            'shop_confirm': lambda: found('auto_purchase_ok') or found('supplies_shop'),
            'shop_exit': lambda: found('supplies_shop') and not found('auto_purchase_ok'),
            'shop_closed': lambda: not found('supplies_shop') and hud(),
            'dismantle_inventory': lambda: found('dismantle_quick_add_button') or found('inventory_dismantle_button'),
            'dismantle_add': lambda: found('dismantle_quick_add_button'),
            'dismantle_selection': lambda: True,
            'dismantle_confirm': lambda: found('dismantle_quick_add_button'),
            'dismantle_result': lambda: found('dismantle_result'),
            'dismantle_result_closed': lambda: not found('dismantle_result') and found('dismantle_quick_add_button'),
            'dismantle_closed': lambda: found('inventory_dismantle_button') or hud(),
        }
        ready = predicates.get(current, lambda: False)()
        if not ready:
            return pause('game_step_timeout_' + current)

    if current == 'monitoring' and state.get('at_farm') and settings.get('farm_enabled'):
        blocking = 'map' if found('world_map_title') else 'inventory' if any(found(n) for n in ('inventory_auto_sell_button', 'inventory_dismantle_button')) else 'shop' if found('supplies_shop') or found('auto_purchase') else 'menu' if found('main_menu_open') or (found('supplies_button') and found('town_supplies_icon')) else None
        if blocking:
            if state.get('autobattle_overlay_attempts', 0) >= max(1, config['vision'].get('dungeon_autobattle_retry_attempts', 3)):
                return pause('farm_autobattle_overlay_not_closed')
            state['autobattle_overlay_attempts'] = state.get('autobattle_overlay_attempts', 0) + 1
            if blocking == 'shop':
                named('shop_exit')
                state['wait_until'] = time.monotonic() + config['timeouts'].get('shop_close_sec', 4)
            elif blocking == 'map':
                state['map_close_next'] = 'monitoring'
                state['map_close_attempts'] = 1
                named('dungeon_map_close')
                phase('farm_close_map', config['timeouts'].get('dungeon_map_close_sec', .8))
            elif blocking == 'menu':
                named('daily_burger_menu')
                state['wait_until'] = time.monotonic() + config['timeouts'].get('daily_menu_open_sec', config['timeouts'].get('popup_close_sec', .8))
            else:
                host.call('back')
            return report('close_autobattle_' + blocking)
        state.pop('autobattle_overlay_attempts', None)

    if current == 'revive_wait':
        if hud():
            phase('monitoring')
        return report('waiting_after_revive')

    # Death recovery precedes shop service, as in the old town state machine.
    if current != 'restore_close' and settings.get('recovery_enabled') and found('stat_restore_window'):
        if found('restore_button'):
            template('restore_button')
            state['recovery_dismantle_pending'] = True
            phase('restore_close', config['timeouts'].get('restore_sec', 3))
        return report('restore_stats')
    if current == 'restore_close':
        if found('stat_restore_window'):
            named('close_stat_window')
        phase('monitoring', 1)
        return report('close_restore_window')
    if current == 'monitoring' and hud() and settings.get('recovery_enabled') and found('restore_icon') and match('restore_icon')['confidence'] >= config['vision'].get('restore_icon_strict_threshold', .85) and found('town_supplies_icon'):
        template('restore_icon')
        phase('restore_open', config['timeouts'].get('restore_sec', 3))
        return report('open_restore')
    if current == 'restore_open':
        return report('waiting_restore_window')

    # Resume from visible dismantle UI without replaying confirmation.
    if current == 'monitoring' and found('dismantle_result'):
        if not settings.get('auto_dismantle_enabled'):
            return pause('dismantle_ui_requires_attention')
        phase('dismantle_result')
        current = 'dismantle_result'
    if current == 'dismantle_inventory':
        if found('dismantle_quick_add_button'):
            phase('dismantle_add')
        elif found('inventory_dismantle_button'):
            template('inventory_dismantle_button')
            phase('dismantle_add', 1)
        return report('open_dismantle')
    if current == 'dismantle_add':
        if found('dismantle_quick_add_button'):
            state.pop('rare_confirm_sent', None)
            state.pop('rare_button_since', None)
            template('dismantle_quick_add_button')
            phase('dismantle_selection', 1)
        return report('dismantle_quick_add')
    if current == 'dismantle_selection':
        if found('dismantle_selection_options'):
            if found('dismantle_selection_quick_add'):
                template('dismantle_selection_quick_add')
                phase('dismantle_confirm', 1)
            return report('dismantle_apply_selection')
        phase('dismantle_confirm')
        current = 'dismantle_confirm'
    if current == 'dismantle_confirm':
        region = config['vision'].get('dismantle_confirm_active_region', [.30, .76, .50, .88])
        active = match('confirm_teal', {'region': region, 'detector': {'type': 'hsv_ratio',
            'low': [75, 25, 35], 'high': [105, 255, 190],
            'minRatio': config['vision'].get('dismantle_confirm_active_teal_ratio', .08)}})['found']
        if active:
            named('dismantle_confirm')
            phase('dismantle_result', 1)
            return report('dismantle_confirm')
        if found('dismantle_quick_add_button'):
            named('dismantle_window_close')
            state['empty_until'] = now + config['auto_dismantle'].get('empty_retry_interval_sec', 600)
            phase('dismantle_closed', 1)
            return report('dismantle_empty')
        return report('waiting_dismantle_selection')
    if current == 'dismantle_result':
        if found('dismantle_result'):
            named('dismantle_result_close')
            phase('dismantle_result_closed', 1)
        return report('waiting_dismantle_result')
    if current == 'dismantle_result_closed':
        if not found('dismantle_result') and found('dismantle_quick_add_button'):
            named('dismantle_window_close')
            phase('dismantle_closed', 1)
        return report('close_dismantle')
    if current == 'dismantle_closed':
        if not found('dismantle_quick_add_button') and not found('inventory_dismantle_button') and hud():
            phase('monitoring')
        elif found('inventory_dismantle_button'):
            host.call('back')
        return report('verify_dismantle_closed')

    if current == 'shop_open':
        if found('supplies_shop') or found('auto_purchase'):
            named('auto_purchase')
            phase('shop_confirm', 1)
        return report('open_supplies')
    if current == 'shop_confirm':
        if found('auto_purchase_ok'):
            named('auto_purchase_ok')
            phase('shop_exit', 1)
        elif found('supplies_shop') and now - state['since'] >= timeout / 2:
            # The game can legitimately offer no purchase. Do not buy again.
            phase('shop_exit')
        return report('auto_purchase')
    if current == 'shop_exit':
        if found('supplies_shop') and not found('auto_purchase_ok'):
            named('shop_exit')
            phase('shop_closed', 1)
        return report('close_shop')
    if current == 'shop_closed':
        if not found('supplies_shop') and hud():
            state['serviced'] = True
            phase('monitoring')
        return report('verify_shop_closed')

    spot = active_spot(settings)
    if current.startswith('farm_'):
        # Navigation is never marked complete solely because a timer elapsed.
        return farm_tick(host, config, catalog, settings, state, match, found, tap, named, phase, report, pause, hud, now, width, height, current_location, navigation, farm_confirmation, minimap)

    if not hud() and not match('world_map_title')['found']:
        if settings.get('autostart_enabled') and not state.get('gameplay_seen'):
            started = state.setdefault('entry_wait_started', now)
            if now - started < config['game'].get('initial_recognition_timeout_sec', 20):
                return report('waiting_game_launch')
            return pause('game_launch_timeout')
        state.setdefault('unknown_since', now)
        if now - state['unknown_since'] > 12:
            return report('recognizing_screen', status='error', error='unrecognized_game_screen', pause=True,
                          reason='connect_' + str(round(match('launch_connect')['confidence'], 3)) + '_tap_' + str(round(match('launch_tap_to_start')['confidence'], 3)))
        return report('recognizing_screen')

    # Only a recognized game login/launch arms this one-shot check. Starting
    # the bot on an already open character or beginning a new route does not.
    if state.get('entry_autobattle_pending') and hud() and settings.get('autobattle_enabled', True) and not found('town_supplies_icon'):
        off, on = match('auto_battle_off'), match('auto_battle_on')
        button_off = off['found'] and (not on['found'] or off['confidence'] > on['confidence'])
        if not on['found'] and not button_off and not state.get('preflight_autobattle_attempts'):
            # ensure_autobattle_after_launch waits for a recognizable button
            # five times. Unknown is never treated as an enabled AUTO button.
            checks = state.get('launch_autobattle_checks', 0) + 1
            state['launch_autobattle_checks'] = checks
            if checks < max(1, config['vision'].get('launch_autobattle_retry_attempts', 5)):
                state['wait_until'] = time.monotonic() + config['timeouts'].get('launch_autobattle_retry_sec', config['timeouts'].get('auto_battle_sec', 2))
                return report('waiting_launch_autobattle')
        if button_off:
            attempts = state.get('preflight_autobattle_attempts', 0)
            if attempts >= max(1, config['vision'].get('dungeon_autobattle_retry_attempts', 3)):
                return pause('farm_preroute_autobattle_not_enabled')
            template('auto_battle_off')
            state['preflight_autobattle_attempts'] = attempts + 1
            state['wait_until'] = time.monotonic() + config['timeouts'].get('autobattle_toggle_settle_sec', 2.5)
            return report('enable_autobattle_before_map')
        if state.get('preflight_autobattle_attempts') and not on['found']:
            return pause('farm_preroute_autobattle_state_unknown')
        state.pop('preflight_autobattle_attempts', None)
        state.pop('entry_autobattle_pending', None)
        state.pop('launch_autobattle_checks', None)
    elif state.get('entry_autobattle_pending') and hud():
        state.pop('entry_autobattle_pending', None)

    due = now - state.get('last_dismantle', -100000) >= config['auto_dismantle'].get('check_interval_sec', 60)
    if (settings.get('recovery_enabled') and settings.get('auto_dismantle_enabled')
            and state.get('recovery_dismantle_pending') and found('town_supplies_icon')
            and not state.get('serviced')):
        # MultiBot death_recovery_before_buy_supplies / town_recovery:
        # require_weight_red=False. Complete/close dismantle before shopping.
        state.pop('recovery_dismantle_pending', None)
        state['last_dismantle'] = now
        template('game_inventory_icon') if found('game_inventory_icon') else named('inventory')
        phase('dismantle_inventory', 1)
        return report('recovery_dismantle_before_supplies')
    if settings.get('auto_dismantle_enabled') and due and now >= state.get('empty_until', 0):
        state['last_dismantle'] = now
        if found('inventory_weight_red'):
            template('game_inventory_icon') if found('game_inventory_icon') else named('inventory')
            phase('dismantle_inventory', 1)
            return report('red_weight_dismantle')
    if settings.get('recovery_enabled') and found('town_supplies_icon') and not state.get('serviced'):
        if found('supplies_button'):
            template('supplies_button')
        else:
            named('supplies')
        phase('shop_open', 1)
        return report('buy_supplies')
    if not settings.get('farm_enabled'):
        return report('monitoring')
    if not spot:
        return pause('farm_point_required')
    if state.get('active_spot') != spot['id']:
        state['active_spot'] = spot['id']
        state['at_farm'] = False
    if not state.get('at_farm'):
        state['destination'] = random.choice(spot['map_points']) if spot.get('map_points') else None
        plan = navigation.travel_plan(spot)
        chain_only = plan and plan.get('type') in ('tyriosa_floor_chain', 'deadmans_district_chain')
        if state['destination'] is None and not chain_only and (not spot.get('teleport_point') or spot.get('run_after_teleport', True)):
            return pause('farm_point_required')
        # Original preflight refreshes Current Location from World Map before
        # choosing an entrance or resuming from an already reached floor.
        state['route'] = [navigation.leg(spot['map_id'], state['destination'], False, spot['map_id'])]
        state['prepare_route'] = True
        state['route_index'] = 0
        phase('farm_map_open', config['timeouts'].get('dungeon_map_open_sec', 1.2))
        return report('open_farm_map')
    if not settings.get('autobattle_enabled', True):
        return report('farm_autobattle_disabled', status='paused', pause=True)
    off, on = match('auto_battle_off'), match('auto_battle_on')
    button_state = ('off' if off['confidence'] >= on['confidence'] else 'on') if off['found'] and on['found'] else 'off' if off['found'] else 'on' if on['found'] else None
    if button_state != 'on':
        wait = config['timeouts'].get('dungeon_after_autobattle_sec', .8)
        if now < state.get('autobattle_settle_until', 0):
            state['wait_until'] = time.monotonic() + min(.4, max(0, state['autobattle_settle_until'] - time.monotonic()))
            return report('verify_autobattle')
        attempts = max(1, config['vision'].get('dungeon_autobattle_retry_attempts', 3))
        if state.get('autobattle_attempts', 0) >= attempts:
            return pause('farm_autobattle_state_unknown' if button_state is None else 'farm_autobattle_not_enabled')
        state['autobattle_attempts'] = state.get('autobattle_attempts', 0) + 1
        if button_state == 'off':
            if off.get('point'):
                template('auto_battle_off')
            else:
                named('dungeon_auto_battle')
            completed = time.monotonic()
            state['autobattle_settle_until'] = completed + config['timeouts'].get('autobattle_toggle_settle_sec', max(2.5, wait) if wait > 0 else 0)
        state['wait_until'] = time.monotonic() + wait
        return report('enable_autobattle' if button_state == 'off' else 'waiting_autobattle_state')
    state.pop('autobattle_attempts', None)
    state.pop('autobattle_settle_until', None)
    return report('farming')


def farm_tick(host, config, catalog, settings, state, match, found, tap, named, phase, report, pause, hud, now, width, height, current_location, navigation, farm_confirmation, minimap):
    spot = active_spot(settings)
    if not spot:
        return pause('farm_point_required')
    def close_map(next_phase='monitoring', delay=0):
        named('dungeon_map_close')
        state['map_close_next'] = next_phase
        state['map_close_delay'] = delay
        state['map_close_attempts'] = 1
        phase('farm_close_map', config['timeouts'].get('dungeon_map_close_sec', .8))

    if state['phase'] == 'farm_close_map':
        if not found('world_map_title'):
            next_phase = state.pop('map_close_next', 'monitoring')
            if next_phase == 'monitoring':
                state['at_farm'] = True
            state.pop('map_close_attempts', None)
            phase(next_phase, state.pop('map_close_delay', 0))
            return report('farm_map_closed')
        if now - state['since'] < config['timeouts'].get('dungeon_map_close_sec', .8) + config['timeouts'].get('dungeon_map_close_verify_sec', 3):
            return report('waiting_farm_map_closed')
        if state.get('map_close_attempts', 0) >= max(1, config['vision'].get('dungeon_map_close_attempts', 3)):
            return pause('farm_map_not_closed_autobattle_skipped')
        named('dungeon_map_close')
        state['map_close_attempts'] = state.get('map_close_attempts', 0) + 1
        phase('farm_close_map', config['timeouts'].get('dungeon_map_close_sec', .8))
        return report('retry_close_farm_map')
    if not state.get('route') or state.get('route_index', 0) >= len(state['route']):
        return pause('farm_route_missing')
    leg = state['route'][state['route_index']]
    item = next((m for m in catalog['maps'] if m['id'] == leg['map_id']), None)
    if not item:
        return pause('farm_map_missing')
    current = state['phase']
    if current in ('farm_travel_confirm', 'farm_transition', 'farm_map_open'):
        confirmation = farm_confirmation()
        if confirmation:
            host.call('tap', x=confirmation[0], y=confirmation[1], width=width, height=height)
            confirmed_at = time.monotonic()
            delay = config['timeouts'].get('farm_transition_ok_sec', config['timeouts'].get('daily_fast_travel_confirm_sec', 1))
            if current == 'farm_map_open':
                state['wait_until'] = confirmed_at + delay + config['timeouts'].get('farm_after_stale_popup_sec', config['timeouts'].get('farm_after_fast_travel_sec', 5))
            elif current == 'farm_transition':
                state['wait_until'] = confirmed_at + delay + config['timeouts'].get('farm_tyriosa_floor_load_sec', 5)
            else:
                phase('farm_transition' if leg.get('transition') else 'farm_arrival', delay + config['timeouts'].get('farm_after_fast_travel_sec', 5))
            return report('confirm_farm_entry' if leg.get('transition') else 'confirm_farm_travel')
    if current not in ('farm_arrival', 'farm_verify_marker', 'farm_transition') and now - state.get('since', now) > config['timeouts'].get('farm_navigation_no_progress_timeout_sec', 60):
        return pause('farm_navigation_no_progress')

    def advance():
        state['route_index'] += 1
        state['arrival_checks'] = 0
        state.pop('previous_marker', None)
        state.pop('nudged', None)
        state.pop('map_open_retries', None)
        state.pop('map_open_started', None)
        state.pop('minimap_toggle_used', None)
        if state['route_index'] >= len(state['route']):
            if found('world_map_title'):
                close_map()
            else:
                state['at_farm'] = True
                phase('monitoring')
        else:
            phase('farm_map_open', config['timeouts'].get('dungeon_map_open_sec', 1.2))

    def continent():
        for name, region in [('el_sera', [.008, .155, .103, .209]),
                             ('kransia', [.113, .155, .208, .209])]:
            spec = {'region': region, 'detector': {'type': 'hsv_ratio',
                    'low': [15,100,70], 'high': [40,255,255], 'minRatio': .10}}
            if match('continent_' + name, spec)['found']:
                return name
        return None

    if current == 'farm_map_open':
        if found('supplies_shop') or found('auto_purchase'):
            if state.get('preflight_shop_close_attempts', 0) >= 2:
                return pause('farm_supplies_shop_not_closed')
            named('shop_exit')
            state['preflight_shop_close_attempts'] = state.get('preflight_shop_close_attempts', 0) + 1
            state['wait_until'] = time.monotonic() + config['timeouts'].get('shop_close_sec', 4)
            return report('close_supplies_before_farm')
        state.pop('preflight_shop_close_attempts', None)
        blocker = next((name for name in ('party_search_title', 'main_menu_open', 'inventory_dismantle_button', 'inventory_auto_sell_button', 'dungeon_title') if found(name)), None)
        if blocker is None and not found('world_map_title') and not any(found(name) for name in ('auto_battle_off', 'auto_battle_on', 'game_inventory_icon')):
            value = match('farm_map_blocker_features', {'region':config['vision'].get('farm_map_open_blocker_region', [.24,.08,.76,.88]), 'detector':{'type':'region_features'}})
            if value.get('dark55Ratio', 0) >= config['vision'].get('farm_map_open_blocker_dark_ratio', .32) and value.get('edgeRatio', 0) >= config['vision'].get('farm_map_open_blocker_edge_ratio', .012):
                blocker = 'map_open_blocker'
        if state.get('preflight_overlay'):
            if blocker:
                if now - state['preflight_overlay_started'] < config['timeouts'].get('service_screen_timeout_sec', 12):
                    return report('waiting_map_overlay_closed')
                attempts = max(1, config['vision'].get('farm_map_open_attempts', config['vision'].get('dungeon_map_open_attempts', 3)))
                if state.get('preflight_overlay_attempts', 0) >= attempts:
                    return pause('farm_map_overlay_not_closed')
            state.pop('preflight_overlay', None)
        if not blocker:
            state.pop('preflight_overlay_attempts', None)
        if blocker:
            if blocker == 'party_search_title':
                close_button = match('party_search_close')
                if not close_button['found']:
                    return pause('farm_party_search_close_not_found')
                host.call('tap', x=close_button['point'][0], y=close_button['point'][1], width=width, height=height)
            else:
                host.call('back')
            state['preflight_overlay'] = blocker
            state['preflight_overlay_attempts'] = state.get('preflight_overlay_attempts', 0) + 1
            state['preflight_overlay_started'] = time.monotonic()
            state['wait_until'] = time.monotonic() + config['timeouts'].get('farm_map_open_blocker_back_sec', config['timeouts'].get('popup_close_sec', 1))
            return report('close_map_overlay')
        if found('world_map_title'):
            state.pop('map_open_retries', None)
            state.pop('map_open_started', None)
            state.pop('minimap_toggle_used', None)
            if state.pop('prepare_route', False):
                try:
                    state['route'] = navigation.route(spot, state['destination'], current_location())
                except RuntimeError as error:
                    return pause(str(error))
                state['route_index'] = 0
                if not state['route']:
                    close_map()
                    return report('farm_location_verified')
                return report('farm_route_prepared')
            if state.get('map_return_phase'):
                phase(state.pop('map_return_phase'))
                return report('farm_map_reopened')
            target = item.get('continent', 'el_sera')
            if target not in ('el_sera', 'kransia'):
                return pause('farm_unknown_continent')
            detected = continent()
            if detected != target and not (detected is None and target == 'el_sera'):
                tap([.159, .174] if target == 'kransia' else [.055, .174])
                phase('farm_continent', config['timeouts'].get('farm_map_select_sec', 1.2))
                return report('select_continent')
            tabs = config['tap_points'].get('farm_map_side_tabs') or [[.021, .250], [.021, .337], [.021, .423], [.021, .507], [.021, .590]]
            index = item.get('tab_index', 1) - 1
            if index < 0 or index >= len(tabs):
                return pause('farm_tab_missing')
            tap(item.get('tab_point') or tabs[index])
            state['tab_attempts'] = state.get('tab_attempts', 0) + 1
            phase('farm_tab', config['timeouts'].get('farm_map_select_sec', 1.2))
            return report('select_map_tab')
        # Original open_world_map waits for confirmation, then retries at most
        # dungeon_map_open_attempts. Only retry on a fresh confirmed HUD pin.
        if not state.get('map_open_started') or now - state.get('since', now) >= config['timeouts'].get('service_screen_timeout_sec', 12):
            retries = state.get('map_open_retries', 0)
            attempts = max(1, config['vision'].get('farm_map_open_attempts', config['vision'].get('dungeon_map_open_attempts', 3)))
            if retries >= attempts:
                return pause('farm_map_not_opened')
            visible, pin = minimap()
            if not visible and pin.get('found') and not state.get('minimap_toggle_used'):
                host.call('tap', x=pin['point'][0], y=pin['point'][1], width=width, height=height)
                state['minimap_toggle_used'] = True
                phase('farm_map_open', config['timeouts'].get('dungeon_map_open_sec', 1.2))
                return report('open_hidden_minimap')
            if not visible:
                # Original open_world_map continues its bounded attempts when
                # a fresh frame cannot confirm the minimap; never tap blindly.
                state['map_open_retries'] = retries + 1
                if state['map_open_retries'] >= attempts:
                    return pause('farm_minimap_not_confirmed')
                phase('farm_map_open', config['timeouts'].get('dungeon_map_open_sec', 1.2))
                return report('waiting_minimap_confirmation')
            state['map_open_retries'] = retries + 1
            state['map_open_started'] = True
            named('dungeon_map_open')
            phase('farm_map_open', config['timeouts'].get('dungeon_map_open_sec', 1.2))
            return report('retry_open_farm_map')
        return report('waiting_farm_map', reason='map_' + str(round(match('world_map_title')['confidence'], 3)))
    if current == 'farm_continent':
        if item.get('continent', 'el_sera') == 'kransia' and found('farm_kransia_entry'):
            if not found('farm_kransia_enter'):
                return pause('farm_kransia_enter_unavailable')
            tap([.500, .905])
            phase('farm_continent_reopen', config['timeouts'].get('farm_continent_load_sec', 8))
        elif continent() == item.get('continent', 'el_sera'):
            phase('farm_map_open')
        elif now - state['since'] > config['timeouts'].get('farm_continent_confirm_timeout_sec', 6):
            return pause('farm_continent_not_confirmed')
        return report('verify_continent')
    if current == 'farm_continent_reopen':
        if not found('world_map_title'):
            named('dungeon_map_open')
        phase('farm_continent', config['timeouts'].get('dungeon_map_open_sec', 1.2))
        return report('reopen_continent_map')
    if current == 'farm_tab':
        if found('world_map_title'):
            state.pop('tab_attempts', None)
            tap(item.get('select_point'))
            phase('farm_selected', config['timeouts'].get('farm_map_select_sec', 1.2))
        else:
            if state.get('tab_attempts', 0) >= max(1, config['vision'].get('farm_select_tab_retry_attempts', 2)):
                return pause('farm_tab_did_not_stay_open')
            phase('farm_map_open')
            return report('reopen_map_after_tab_closed')
        return report('select_map')
    if current == 'farm_selected':
        if not found('world_map_title'):
            return pause('farm_map_closed_after_selection')
        row_y = item['select_point'][1]
        spec = {'file': 'farm_map_names/' + item['id'] + '.png',
                'region': [.035, max(0, row_y-.052), .225, min(1, row_y+.052)],
                'threshold': config['vision'].get('farm_map_name_template_threshold', .93),
                'method': item.get('selected_template_method', '')}
        selected = match('selected_map_name', spec)
        # Original select_catalog_map records an unconfirmed name as a warning;
        # map closure is fatal, but a low name confidence does not add a retry.
        if found('world_map_title'):
            if leg.get('marker'):
                region = config['vision'].get('map_navigation_target_region', config['vision'].get('map_navigation_marker_search_region', [.22,.16,.78,.84]))
                region = item.get('navigation_region') or region
                inset = config['vision'].get('map_navigation_target_inset', .015)
                if not (region[0]+inset <= leg['point'][0] <= region[2]-inset and region[1]+inset <= leg['point'][1] <= region[3]-inset):
                    named('dungeon_map_close')
                    return pause('farm_target_outside_map_region')
            tap(leg['point'])
            delay = config['timeouts'].get('map_navigation_after_point_sec', .5) if leg.get('marker') else config['timeouts'].get('farm_map_select_sec', 1.2) if leg.get('transition') else config['timeouts'].get('farm_fast_travel_select_sec', .8)
            phase('farm_target', delay)
        return report('verify_selected_map', reason=None if selected['found'] else 'selected_map_name_unconfirmed')
    if current == 'farm_target':
        if found('world_map_title'):
            if leg['teleport']:
                retry_points = config['tap_points'].get('farm_fast_travel_button_retry_points') or [config['tap_points']['farm_fast_travel_button'], [.865,.948], [.900,.948], [.835,.948], [.865,.932]]
                state['travel_retry_points'] = list(dict.fromkeys(tuple(p) for p in retry_points))
                state['travel_attempt'] = 0
                tap(state['travel_retry_points'][0])
                state['travel_attempt_started'] = time.monotonic()
            else:
                named('farm_walk_button')
            state['arrival_started'] = time.monotonic()
            state['last_progress_at'] = state['arrival_started']
            state['arrival_checks'] = 0
            phase('farm_travel_confirm', config['timeouts'].get('map_navigation_after_confirm_sec', .5) if leg.get('marker') else config['timeouts'].get('farm_fast_travel_popup_sec', .8) if leg['teleport'] else config['timeouts'].get('farm_after_walk_tap_sec', .8))
        return report('farm_travel')
    if current == 'farm_travel_confirm':
        if leg['teleport'] and found('world_map_title'):
            retry_timeout = config['timeouts'].get('farm_fast_travel_button_retry_timeout_sec', config['timeouts'].get('farm_fast_travel_popup_sec', 4))
            if now - state.get('travel_attempt_started', now) >= retry_timeout:
                index = state.get('travel_attempt', 0) + 1
                points = state.get('travel_retry_points', [])
                if index >= len(points):
                    return pause('farm_fast_travel_not_confirmed')
                tap(points[index])
                state['travel_attempt'] = index
                state['travel_attempt_started'] = time.monotonic()
            state['wait_until'] = time.monotonic() + config['timeouts'].get('farm_fast_travel_button_retry_poll_sec', config['timeouts'].get('farm_transition_popup_poll_sec', 1))
            return report('waiting_fast_travel_popup')
        if found('world_map_title') and not leg['teleport']:
            if leg.get('marker'):
                phase('farm_verify_marker')
            elif not state.get('walk_retried'):
                named('farm_walk_button')
                state['walk_retried'] = True
                state['wait_until'] = time.monotonic() + config['timeouts'].get('farm_after_walk_retry_sec', 1)
            else:
                state.pop('walk_retried', None)
                close_map('farm_transition', config['timeouts'].get('farm_after_walk_close_map_sec', .8))
        elif not found('world_map_title') and hud():
            phase('farm_transition' if leg.get('transition') else 'farm_arrival')
        return report('verify_travel_confirmation')
    if current == 'farm_arrival':
        if now - state['since'] > config['timeouts'].get('map_navigation_arrival_timeout_sec', 45):
            return pause('farm_arrival_not_verified')
        if not found('world_map_title') and hud():
            # Imported location labels are from World Map, not the minimap.
            # Obtain matching evidence instead of inferring arrival from time.
            state['map_return_phase'] = 'farm_arrival'
            phase('farm_map_open')
            return report('open_arrival_map')
        if (hud() or found('world_map_title')) and current_location() == leg['arrival_map']:
            advance()
        return report('verify_arrival')
    if current == 'farm_transition':
        elapsed = now - state.get('arrival_started', now)
        limit = config['timeouts'].get('farm_tyriosa_floor_route_timeout_sec', 45)
        if elapsed > limit:
            return pause('farm_floor_not_verified')
        if current_location() == leg['arrival_map']:
            advance()
            return report('floor_verified')
        if leg.get('nudge') and not state.get('nudged') and elapsed >= config['timeouts'].get('farm_deadmans_entry_before_nudge_sec', 5):
            host.call('swipe', x1=round(.147*width), y1=round(.804*height),
                      x2=round(.100*width), y2=round(.720*height),
                      width=width, height=height, durationMs=2500)
            state['nudged'] = True
            state['wait_until'] = time.monotonic() + config['timeouts'].get('farm_deadmans_entry_after_nudge_sec', 1)
            return report('deadmans_entry_nudge')
        map_interval = config['timeouts'].get('farm_tyriosa_floor_map_check_sec', 15)
        if elapsed >= map_interval and now-state.get('last_floor_map_check', 0) >= map_interval:
            if found('world_map_title'):
                close_map('farm_transition')
            else:
                state['map_return_phase'] = 'farm_transition'
                phase('farm_map_open')
            state['last_floor_map_check'] = time.monotonic()
        else:
            state['wait_until'] = time.monotonic() + max(.5, config['timeouts'].get('farm_tyriosa_floor_route_poll_sec', 2))
        return report('verify_floor_transition')
    if current == 'farm_verify_marker':
        options = navigation.marker_options(config, leg['map_id'])
        if not found('world_map_title'):
            state['map_return_phase'] = 'farm_verify_marker'
            phase('farm_map_open')
            return report('reopen_marker_map')
        best = navigation.find_marker(match, options, config['vision'], item, leg['point'], width, height)
        if best['found']:
            target = [leg['point'][0] * width, leg['point'][1] * height]
            distance = sum((best['point'][i]-target[i])**2 for i in range(2))**.5
            previous = state.get('previous_marker')
            stable = previous is not None and sum((previous[i]-best['point'][i])**2 for i in range(2))**.5 <= 3 * width / 1280
            state['previous_marker'] = best['point']
            state['arrival_checks'] = (state.get('arrival_checks', 0)+1 if stable else 1) if distance <= min(options['radius'], 20 * width / 1280) else 0
            anchor = state.get('progress_anchor')
            if anchor is None:
                state['progress_anchor'] = best['point']
            elif sum((anchor[i]-best['point'][i])**2 for i in range(2))**.5 >= 6 * width / 1280:
                state['progress_anchor'] = best['point']
                state['last_progress_at'] = time.monotonic()
            if state['arrival_checks'] >= options['checks']:
                advance()
                return report('farm_arrival_verified')
        else:
            state['previous_marker'] = None
            state['arrival_checks'] = 0
        elapsed = time.monotonic() - state.get('arrival_started', now)
        no_progress = time.monotonic() - state.get('last_progress_at', state.get('arrival_started', now))
        timed_out = elapsed >= options['timeout']
        if options['progress_timeout'] > 0:
            timed_out = elapsed >= max(options['timeout'], options['max_route']) or (timed_out and no_progress >= options['progress_timeout'])
        if timed_out:
            named('dungeon_map_close')
            return pause('farm_route_time_limit' if elapsed >= max(options['timeout'], options['max_route']) else 'farm_marker_not_moving')
        state['wait_until'] = time.monotonic() + options['poll']
        return report('verify_map_marker')
    return pause('farm_unknown_step')
