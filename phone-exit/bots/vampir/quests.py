"""Quest mode: game auto-progression plus identified tutorial and scene controls."""
import random


def tap_point(button, frame, interaction):
    """Small variation strictly inside a known target; no rectangle, no jitter."""
    x, y = button['point']
    rect = button.get('rect')
    radius = max(0, min(4, interaction.get('tap_jitter_px', 0))) * min(frame['width'] / 1280, frame['height'] / 720)
    if rect and len(rect) == 4 and rect[0] < x < rect[2] and rect[1] < y < rect[3]:
        margin = 2
        left, right = max(rect[0] + margin, x - radius, 1), min(rect[2] - margin, x + radius, frame['width'] - 2)
        top, bottom = max(rect[1] + margin, y - radius, 1), min(rect[3] - margin, y + radius, frame['height'] - 2)
        if left <= right and top <= bottom:
            x, y = random.uniform(left, right), random.uniform(top, bottom)
    return round(x), round(y)


def source_observation(source, config):
    catalog = config.get('_chain_catalog')
    if not catalog:
        raise ValueError('quest_catalog_missing')
    step = catalog['steps'].get(source['step_id'])
    if not step or step['tutorial'] != source['tutorial_id'] or step['uiKey'] != source['ui_key']:
        raise ValueError('quest_reference_mismatch')
    candidates = catalog['tutorials'][step['tutorial']]['taskCandidates']
    observed = dict(source, task_candidates=candidates, expected_step=step['nextInTable'])
    cursor = step['nextInTable']
    while cursor and catalog['steps'][cursor]['type'] == '4':
        cursor = catalog['steps'][cursor]['nextInTable']
    observed['expected_next_observation'] = cursor
    if len(candidates) == 1:
        observed['task_id'] = candidates[0]
        observed['quest_id'] = catalog['tasks'][candidates[0]]['quest']
    return observed


def tick(host, settings, state, frame, config, now):
    if not settings.get('quest_enabled', False):
        state.pop('quest', None)
        return None
    quest = state.setdefault('quest', {})
    interaction = config.get('interaction', {})

    def match(name):
        if callable(config.get('_match')):
            return config['_match'](name)
        return host.call('match', name=name, spec=config['templates'][name])

    def found(name):
        return match(name).get('found', False)

    def report(step, error=None):
        result = dict(status='running', step=step, error=error)
        source = quest.get('last_observed_tutorial')
        if source and source.get('quest_id'):
            result['activePoint'] = 'quest:%s/task:%s/tutorial:%s/step:%s' % (source['quest_id'], source['task_id'], source['tutorial_id'], source['step'])
        else:
            result['activePoint'] = ('last_tutorial:%s:step:%s' % (source['tutorial_id'], source['step'])) if source else None
        if source and source.get('expected_next_observation') and ('wait' in step or error):
            result['reason'] = 'expected_source_step:' + source['expected_next_observation']
        else:
            result['reason'] = None
        if error:
            result.update(status='error', pause=True, retryable=False)
        return result

    def tap(button, step, source=None):
        try:
            observed = source_observation(source, config) if source else None
        except (KeyError, ValueError) as error:
            return report('quest_reference_error', str(error))
        x, y = tap_point(button, frame, interaction)
        host.call('tap', x=x, y=y, width=frame['width'], height=frame['height'])
        lo, hi = interaction.get('delay_jitter_sec', [0, 0])
        jitter = random.uniform(lo, hi) if 0 <= lo <= hi <= 1 else 0
        quest['settle_until'] = now + max(2, source.get('minimum_delay_sec', 0) if source else 0) + jitter
        if source:
            quest['last_observed_tutorial'] = observed
        quest.pop('unknown_since', None)
        return report(step)

    if now < quest.get('settle_until', 0):
        return report('quest_wait_action')
    hud = all(found(name) for name in config['ready_anchors']) if config['ready_anchors'] else False
    skip = match('scene_skip')
    # Tutorial panels also contain SKIP. Only the observed dialog header
    # authorizes this control; a missing HUD alone is not a cinematic signal.
    if settings.get('skip_cutscenes_enabled', True) and skip.get('found') and found('dialog_auto_header'):
        if quest.get('skip_attempts', 0) >= 3:
            return report('quest_skip_scene', 'quest_scene_skip_not_closed')
        quest['skip_attempts'] = quest.get('skip_attempts', 0) + 1
        return tap(skip, 'quest_skip_scene')
    if not skip.get('found'):
        quest.pop('skip_attempts', None)
    for action in config['tutorial_actions']:
        prompt, target, step = action['prompt'], action['target'], action['step']
        if not found(prompt):
            quest.pop(prompt + '_attempts', None)
            quest.pop(prompt + '_attempt_at', None)
            quest.pop(prompt + '_target_since', None)
            continue
        button = match(target)
        if not button.get('found'):
            since = quest.setdefault(prompt + '_target_since', now)
            return report(step, 'quest_tutorial_target_not_found' if now - since > 20 else None)
        quest.pop(prompt + '_target_since', None)
        attempts = quest.get(prompt + '_attempts', 0)
        if attempts and now - quest.get(prompt + '_attempt_at', now) < interaction.get('retry_wait_sec', 8):
            return report('quest_wait_action')
        if attempts >= 2:
            return report(step, 'quest_tutorial_not_advanced')
        if target == 'tutorial_target_corner' or 'offset' in action:
            rect = button.get('rect')
            if not rect or len(rect) != 4:
                return report(step, 'quest_tutorial_target_geometry')
            geometry = action if 'offset' in action else config['tutorial_corner']
            scale = (rect[2] - rect[0]) / geometry['width']
            dx, dy = geometry['offset']
            point = [button['point'][0] + dx * scale, button['point'][1] + dy * scale]
            left, top, right, bottom = geometry.get('point_region', [.2, .2, .8, .65])
            if not (frame['width'] * left < point[0] < frame['width'] * right and frame['height'] * top < point[1] < frame['height'] * bottom):
                return report(step, 'quest_tutorial_target_geometry')
            safe_radius = 6 * scale
            button = dict(point=point, rect=[point[0] - safe_radius, point[1] - safe_radius, point[0] + safe_radius, point[1] + safe_radius])
        quest[prompt + '_attempts'] = attempts + 1
        quest[prompt + '_attempt_at'] = now
        return tap(button, step, action.get('source_tutorial'))
    for action in config.get('quest_actions', []):
        key = 'action_' + action['id']
        if not all(found(name) for name in action['anchors']):
            quest.pop(key, None)
            continue
        button = match(action['target'])
        if not button.get('found'):
            continue
        pending = quest.setdefault(key, dict(attempts=0))
        if pending['attempts'] and now - pending['at'] < action['retry_wait_sec']:
            return report('quest_wait_action')
        if pending['attempts'] >= action['max_attempts']:
            return report(action['id'], 'quest_action_not_advanced')
        pending.update(attempts=pending['attempts'] + 1, at=now)
        quest.pop('last_observed_tutorial', None)
        return tap(button, action['id'])
    visible_overlay = None
    for overlay in config.get('known_overlays', []):
        if not found(overlay['header']):
            continue
        close = match(overlay['close'])
        if not close.get('found'):
            continue
        visible_overlay = overlay['id']
        window = quest.setdefault('overlay', dict(id=visible_overlay, since=now))
        if window['id'] != visible_overlay:
            window = dict(id=visible_overlay, since=now)
            quest['overlay'] = window
        if 'clicked_at' in window:
            return report('quest_close_' + visible_overlay, 'quest_overlay_not_closed' if now - window['clicked_at'] > overlay['timeout_sec'] else None)
        if now - window['since'] < overlay['wait_sec']:
            return report('quest_wait_' + visible_overlay)
        window['clicked_at'] = now
        return tap(close, 'quest_close_' + visible_overlay)
    if visible_overlay is None:
        quest.pop('overlay', None)
    if hud:
        quest.pop('last_observed_tutorial', None)
        quest.pop('unknown_since', None)
        if found('quest_auto_on'):
            quest.pop('hud_unknown_since', None)
            quest.pop('activation_since', None)
            return report('quest_auto_running')
        if 'activation_since' in quest:
            return report('quest_wait_auto', 'quest_auto_not_enabled' if now - quest['activation_since'] > 20 else None)
        if found('quest_auto_off'):
            button = match('quest_anchor')
            if button.get('found'):
                quest['activation_since'] = now
                return tap(button, 'quest_start_auto')
        since = quest.setdefault('hud_unknown_since', now)
        return report('quest_wait_state', 'quest_auto_state_not_recognized' if now - since > 120 else None)
    quest.pop('hud_unknown_since', None)
    since = quest.setdefault('unknown_since', now)
    if now - since > 120:
        return report('quest_recognizing_screen', 'quest_screen_not_recognized')
    # Known launch screens are still handled by the launch module.
    return None
