"""Editable example: return derived data; no game commands or credentials."""


def analyze(batch):
    state=batch['state'];person=state.get('character') or {}
    hp,maximum=person.get('hp'),person.get('max_hp')
    return dict(hp_percent=round(100*hp/maximum,1) if type(hp) is int and type(maximum) is int and maximum>0 else None,
        stats=len(person.get('stats',[])),packets=state.get('packets',{}),
        sample_gap=batch['samples']['gap'],event_gap=batch['events']['gap'])
