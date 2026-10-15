"""Vampir phone-only launch. Recognised screens only; never accept unknown dialogs."""
# Development entry guide: README.md (sources, dependencies, generators, validation).
import json
import importlib.util
import time
from pathlib import Path

PACKAGE = 'com.netmarble.thered'
_configs = {}
_quests = {}
_shops = {}


def prepare_templates(config, frame):
    reference = config.get('reference_size', [1280, 720])
    scale = min(frame['width'] / reference[0], frame['height'] / reference[1])
    if config.get('_prepared_frame') == (frame['width'], frame['height']):
        return
    original = config.setdefault('_reference_templates', config['templates'])
    config['templates'] = {name: dict(spec, scales=[round(value * min(
        frame['width'] / spec.get('reference_size', reference)[0],
        frame['height'] / spec.get('reference_size', reference)[1]), 6) for value in spec.get('scales', [1])])
        for name, spec in original.items()}
    config['_prepared_scale'] = scale
    config['_prepared_frame'] = (frame['width'], frame['height'])


def tick(host, settings, state, directory):
    if directory not in _configs:
        _configs[directory] = json.loads((Path(directory) / 'vision.json').read_text('utf-8'))
        if _configs[directory].get('chain_catalog') == 'quest-runtime.json':
            catalog = json.loads((Path(directory) / 'quest-runtime.json').read_text('utf-8'))
            if catalog.get('schemaVersion') != 1:
                raise ValueError('quest_catalog_incompatible')
            _configs[directory]['_chain_catalog'] = catalog
        if _configs[directory].get('shop_flow'):
            _configs[directory]['_shop_reference'] = json.loads((Path(directory) / 'shop-reference.json').read_text('utf-8'))
    config = _configs[directory]
    now = time.monotonic()

    def report(step, error=None):
        result = dict(status='waiting', step=step, error=error)
        if error:
            result.update(status='error', pause=True, retryable=False)
        return result

    if not settings.get('autostart_enabled') and not settings.get('quest_enabled', False):
        state.clear()
        return dict(status='paused', step='autostart_disabled', pause=True, error=None)
    try:
        foreground = host.call('foreground').get('package')
    except RuntimeError as error:
        if str(error) != 'foreground_unavailable':
            raise
        since = state.setdefault('foreground_since', now)
        return report('waiting_game_foreground', 'foreground_unavailable' if now - since >= 10 else None)
    state.pop('foreground_since', None)
    if foreground != PACKAGE:
        if not settings.get('autostart_enabled'):
            return dict(status='paused', step='game_not_foreground', pause=True, error=None)
        if 'launch_at' not in state:
            state.clear()
            host.call('launch', package=PACKAGE)
            state['launch_at'] = now
            return report('launch_game')
        return report('waiting_game_foreground', 'game_launch_timeout' if now - state['launch_at'] >= config['launch_timeout_sec'] else None)
    frame = host.call('capture')
    prepare_templates(config, frame)

    def match(name):
        result = host.call('match', name=name, spec=config['templates'][name])
        if result.get('found'):
            return result
        for alternative in config.get('match_alternatives', {}).get(name, []):
            candidate = host.call('match', name=alternative, spec=config['templates'][alternative])
            if candidate.get('found'):
                return candidate
            if candidate.get('confidence', 0) > result.get('confidence', 0):
                result = candidate
        return result

    config['_match'] = match

    # Asset download may take much longer than login. Never restart or click it.
    if any(match(name).get('found') for name in config.get('download_screens', ['patch_download'])):
        state['entry_since'] = now
        return report('waiting_game_download')
    for name in config.get('manual_screens', []):
        if match(name).get('found'):
            source = config.get('manual_screen_sources', {}).get(name, {})
            return dict(status='paused', step='waiting_' + name, pause=True, error=None,
                        reason=('source_text:' + source['localization_key']) if source.get('localization_key') else None)
    if settings.get('quest_enabled', False):
        if config.get('shop_flow'):
            if directory not in _shops:
                spec = importlib.util.spec_from_file_location('vampir_shop', Path(directory) / 'shop.py')
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                _shops[directory] = module
            result = _shops[directory].tick(host, state, frame, config, now, directory, config['_shop_reference'])
            if result is not None:
                state.pop('entry_since', None)
                return result
        if directory not in _quests:
            spec = importlib.util.spec_from_file_location('vampir_quests', Path(directory) / 'quests.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            _quests[directory] = module
        result = _quests[directory].tick(host, settings, state, frame, config, now)
        if result is not None:
            state.pop('entry_since', None)
            return result
    anchors = config['ready_anchors']
    if anchors and all(match(name).get('found') for name in anchors):
        state.clear()
        return dict(status='running', step='game_ready', error=None)
    state.setdefault('entry_since', now)
    for name in config['launch_buttons']:
        button = match(name)
        if not button.get('found'):
            continue
        if state.get('clicked') == name:
            return report('waiting_' + name, 'game_launch_button_not_closed' if now - state['clicked_at'] >= config['button_timeout_sec'] else None)
        if state.get('actions', 0) >= config['max_actions']:
            return report('waiting_game_entry', 'game_launch_action_limit')
        host.call('tap', x=button['point'][0], y=button['point'][1], width=frame['width'], height=frame['height'])
        state.update(clicked=name, clicked_at=now, actions=state.get('actions', 0) + 1)
        return report('press_' + name)
    return report('waiting_game_entry', 'game_entry_not_recognized' if now - state['entry_since'] >= config['entry_timeout_sec'] else None)
