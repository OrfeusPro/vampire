"""Source-linked title attempt using the current in-game account/server selection."""


def tick(host, settings, state, frame, config, match, now):
    for name in ('title', 'character'):
        profile = config.get('entry_' + name)
        if profile:
            result = screen_tick(host, state, frame, profile, match, now, name)
            if result is not None:
                return result
    return None


def screen_tick(host, state, frame, profile, match, now, name):
    entry = state.setdefault(name + '_entry', {})
    prompt = match(profile['prompt'])
    control = profile.get('control', 'WBP_TitlePanelUI/ButtonStart')
    if 'at' in entry:
        if not prompt.get('found') and not any(match(anchor).get('found') for anchor in profile['anchors']):
            entry['left_title'] = True
            return None
        if entry.get('left_title'):
            return dict(status='paused', pause=True, retryable=False, error=None,
                        step=name + '_reappeared', reason='manual_entry_check_required')
        if now - entry['at'] >= profile['timeout_sec']:
            return dict(status='paused', pause=True, retryable=False,
                        step=name + '_not_advanced', error=name + '_not_advanced',
                        reason='source_control:' + control)
        return dict(status='waiting', step=name + '_wait_transition', error=None)
    if not prompt.get('found'):
        return None
    if not all(match(anchor).get('found') for anchor in profile['anchors']):
        return dict(status='paused', pause=True, retryable=False, error=None,
                    step=name + '_identity_unverified', reason='verify_' + name + '_screen')
    entry['at'] = now
    try:
        host.call('tap', x=prompt['point'][0], y=prompt['point'][1],
                  width=frame['width'], height=frame['height'])
    except RuntimeError:
        return dict(status='paused', pause=True, retryable=False,
                    error=name + '_tap_outcome_unknown', step=name + '_wait_transition')
    return dict(status='waiting', step=name + '_wait_transition', error=None,
                reason='source_control:' + control)
