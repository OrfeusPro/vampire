"""Shared input transaction for source-bound quest controls; no screen guessing."""
import math


def forget(records, key):
    """Only call after a fresh observation proves this rule is no longer visible."""
    records.pop(key, None)


def execute(host, records, button, frame, now, point, policy=None, source=None):
    """Input requires a fresh resolved control. Reserve before crossing Android IPC.

    Records survive ticks in this process, not Android restarts. Purchases retain
    their separate durable journal and must never be routed through this helper.
    """
    policy = policy or {}
    key = policy.get('id')
    record = records.get(key, {}) if key else {}
    if record.get('outcome') == 'unknown':
        return dict(phase='error', error='quest_input_outcome_unknown')
    if record.get('attempts', 0):
        if now - record['at'] < policy['retry_wait_sec']:
            return dict(phase='wait')
        if record['attempts'] >= policy['max_attempts']:
            return dict(phase='exhausted')
    rect = button.get('rect')
    if (not rect or len(rect) != 4 or len(point) != 2
            or not all(isinstance(v, (int, float)) and math.isfinite(v) for v in [*rect, *point])
            or not (0 <= rect[0] < point[0] < rect[2] <= frame['width']
                    and 0 <= rect[1] < point[1] < rect[3] <= frame['height'])):
        return dict(phase='error', error='quest_target_geometry')
    pending = dict(attempts=record.get('attempts', 0) + 1, at=now, outcome='unknown',
                   target_rect=list(rect), point=list(point))
    if source:
        pending['source_step'] = source['step_id']
        pending['expected_source_step'] = source.get('expected_next_observation')
    if key:
        records[key] = pending
    try:
        result = host.call('tap', x=point[0], y=point[1], width=frame['width'], height=frame['height'])
    except RuntimeError:
        return dict(phase='error', error='quest_input_outcome_unknown')
    if isinstance(result, dict) and result.get('performed') is False:
        pending['outcome'] = 'rejected'
        return dict(phase='error', error='quest_input_rejected')
    # Android accepted input; this is NOT proof that the quest completed.
    pending['outcome'] = 'input_acknowledged'
    return dict(phase='sent')
