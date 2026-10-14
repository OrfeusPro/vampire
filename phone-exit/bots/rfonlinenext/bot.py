"""RF Online Next launch module. Fresh local screenshots, no OCR or blind taps."""
import json
import importlib.util
import time
from pathlib import Path

PACKAGE = 'com.netmarble.rfnext'
_configs = {}
_navigators = {}


def tick(host, settings, state, directory):
    if directory not in _configs:
        _configs[directory] = json.loads((Path(directory) / 'vision.json').read_text('utf-8'))
    config = _configs[directory]
    now = time.monotonic()

    def report(step, status='waiting', error=None):
        result = {'status': status, 'step': step, 'error': error}
        if error:
            result['pause'] = True
        return result

    if not settings.get('autostart_enabled', False) and not settings.get('farm_enabled', False):
        state.clear()
        return report('autostart_disabled', 'paused') | {'pause': True}
    try:
        foreground = host.call('foreground').get('package')
    except RuntimeError as error:
        if str(error) != 'foreground_unavailable':
            raise
        state.setdefault('foreground_since', now)
        if now-state['foreground_since'] >= config['button_timeout_sec']:
            return report('waiting_game_foreground', error='foreground_unavailable')
        return report('waiting_game_foreground')
    state.pop('foreground_since', None)
    if foreground != PACKAGE:
        if not settings.get('autostart_enabled', False):
            return report('game_not_foreground', 'paused') | {'pause': True}
        if 'launch_at' not in state:
            state.clear()
            host.call('launch', package=PACKAGE)
            state['launch_at'] = now
            return report('launch_game')
        if now - state['launch_at'] >= config['launch_timeout_sec']:
            return report('waiting_game_foreground', error='game_launch_timeout')
        return report('waiting_game_foreground')

    # Being in the game's package alone doesn't mean the character is loaded.
    state.setdefault('launch_at', now)
    frame = host.call('capture')
    def match(name):
        return host.call('match', name=name, spec=config['templates'][name])

    if settings.get('farm_enabled'):
        if directory not in _navigators:
            spec = importlib.util.spec_from_file_location('rf_navigation', Path(directory) / 'navigation.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            _navigators[directory] = module
        result = _navigators[directory].tick(host, settings, state, frame, config, now)
        if result is not None:
            return result

    hud = match('hud_eye')
    if hud.get('found') and (match('hud_auto').get('found') or match('auto_on').get('found')):
        if settings.get('farm_enabled'):
            route=state.get('route',{})
            if now-route.get('since',now)>config['button_timeout_sec']:
                return report('waiting_map_anchor', error='farm_map_anchor_not_recognized') | {'retryable': False}
            return report('waiting_map_anchor')
        state.clear()
        return report('game_ready', 'running')
    for name in config['launch_buttons']:
        button = match(name)
        if not button.get('found'):
            continue
        required = config.get('requires', {}).get(name)
        if required and not match(required).get('found'):
            continue
        if state.get('clicked') == name:
            if now - state['clicked_at'] >= config['button_timeout_sec']:
                return report('waiting_' + name, error='game_launch_button_not_closed')
            return report('waiting_' + name)
        # One action per recognised screen. Never repeat on a stuck screen.
        if state.get('actions', 0) >= config['max_actions']:
            return report('waiting_game_entry', error='game_launch_action_limit')
        host.call('tap', x=button['point'][0], y=button['point'][1], width=frame['width'], height=frame['height'])
        state.update(clicked=name, clicked_at=now, actions=state.get('actions', 0) + 1)
        return report('press_' + name)
    if now - state['launch_at'] >= config['launch_timeout_sec']:
        return report('waiting_game_entry', error='game_entry_not_recognized')
    return report('waiting_game_entry')
