"""Source-guided search order. Predictions never authorize input without a match."""


def tutorial_candidates(config, quest):
    actions = config['tutorial_actions']
    previous = quest.get('last_observed_tutorial', {})
    expected = previous.get('expected_next_observation')
    steps = config.get('_chain_catalog', {}).get('steps', {})
    visited = set()
    # Some source steps prepare/highlight a control rather than show a prompt.
    while expected and expected not in visited:
        visited.add(expected)
        row = steps.get(expected)
        if not row or row.get('type') not in ('4', '18'):
            break
        expected = row.get('nextInTable')

    def priority(action):
        source = action.get('source_tutorial', {})
        if expected and source.get('step_id') == expected:
            return 0
        if action['prompt'] == quest.get('recognized_prompt'):
            return 1
        if previous.get('tutorial_id') and source.get('tutorial_id') == previous['tutorial_id']:
            return 2
        return 3

    return sorted(actions, key=priority)


def screen_kind(source):
    """Names describe the matched source control's owner, not the whole UI stack."""
    wbp, widget = source.get('wbp', ''), source.get('widget', '')
    if 'Enchant' in wbp or 'Enchant' in source.get('ui_key', ''):
        return 'enhancement_tutorial'
    if 'ItemInfo' in wbp:
        return 'item_info_tutorial'
    if 'Inventory' in widget:
        return 'inventory_tutorial'
    return 'tutorial'


def overlay_route(config, state, match, now):
    """A positive screen identity only; unmatched screens retain full discovery."""
    for overlay in config.get('fast_overlays', []):
        key = 'fast_overlay_' + overlay['id']
        if not all(match(name).get('found') for name in overlay['anchors']):
            state.pop(key, None)
            continue
        if any(match(name).get('found') for name in overlay.get('blocked_by', [])):
            state.pop(key, None)
            continue
        window = state.setdefault(key, {'since': now})
        if 'clicked_at' in window:
            if now - window['clicked_at'] >= overlay['timeout_sec']:
                return dict(status='error', step='screen_exit_' + overlay['id'],
                            error='screen_exit_not_confirmed', pause=True, retryable=False)
            return dict(status='waiting', step='screen_wait_exit_' + overlay['id'], error=None)
        button = match(overlay['close'])
        if not button.get('found'):
            return dict(status='paused', step='screen_exit_' + overlay['id'],
                        error='screen_exit_target_missing', pause=True, retryable=False)
        if now - window['since'] < overlay['wait_sec']:
            return dict(status='waiting', step='screen_settle_' + overlay['id'], error=None)
        # Reserve before IPC. An unconfirmed tap is never repeated.
        window['clicked_at'] = now
        return dict(button=button, step='screen_exit_' + overlay['id'])
    return None
