"""Explicit source-keyed acknowledgements; no generic Confirm or reconnect loop."""


def tick(host, state, frame, config, match, now):
    rules = {rule['id']: rule for rule in config['message_acknowledgements']}

    def report(step, rule, pause=False, error=None):
        result = dict(status='paused' if pause else 'waiting', step=step,
                      error=error, reason='source_text:' + rule['localization_key'])
        if pause:
            result.update(pause=True, retryable=False)
        return result

    pending = state.get('message_ack_pending')
    if pending:
        rule = rules[pending['id']]
        if now - pending['at'] < 2:
            return report('message_confirm_wait', rule)
        if not match(rule['message']).get('found'):
            del state['message_ack_pending']
            state.pop('entry_since', None)
            return report('message_confirm_dismissed', rule)
        if now - pending['at'] >= rule.get('timeout_sec', 10):
            return report('message_confirm_outcome_unknown', rule, True,
                          'message_confirm_outcome_unknown')
        return report('message_confirm_wait', rule)

    for rule in rules.values():
        message = match(rule['message'])
        if not message.get('found'):
            continue
        if rule['id'] in state.get('message_ack_done', []):
            return report('message_confirm_reappeared', rule, True)
        button = match(rule['button'])
        if not button.get('found'):
            return report('message_confirm_button_missing', rule, True)
        scale = config['_prepared_scale']
        dx = abs(button['point'][0] - message['point'][0]) / scale
        dy = (button['point'][1] - message['point'][1]) / scale
        if dx > rule['dx_max'] or not rule['dy_min'] <= dy <= rule['dy_max']:
            return report('message_confirm_geometry_unknown', rule, True)
        # Reserve before IPC. Never retry an input with an uncertain outcome.
        state.setdefault('message_ack_done', []).append(rule['id'])
        state['message_ack_pending'] = dict(id=rule['id'], at=now,
                                           key=rule['localization_key'])
        try:
            host.call('tap', x=button['point'][0], y=button['point'][1],
                      width=frame['width'], height=frame['height'])
        except RuntimeError:
            return report('message_confirm_outcome_unknown', rule, True,
                          'message_confirm_outcome_unknown')
        return report('message_confirm_wait', rule)
    return None
