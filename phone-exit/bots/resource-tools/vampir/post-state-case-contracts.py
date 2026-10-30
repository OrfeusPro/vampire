"""Exact independent oracle for the 44 fixture-bound post-state scenarios."""
import hashlib
import itertools
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULTS = dict(present=True, class_count=3, class_index=2, class_match=True, active=True, busy=False,
    occupied=False, mode=0, predicate=False, fallback=False, list_match=True, eligible=False,
    object_index=0, object_count=1, flag=1)
SERVICE = 0x28001000
TYPE_INFO = 0x28003030


def case_count(): return 44


def tools():
    names = ('post-state-case-contracts.py', 'verify-post-state-context.py')
    return {str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in names}


def matrix():
    cases = [(False, dict(zip(('mode', 'predicate', 'fallback', 'list_match', 'eligible'), values)))
        for values in itertools.product((0, 3), (False, True), (False, True), (False, True), (False, True))]
    cases.extend((False, settings) for settings in (dict(present=False), dict(class_count=1), dict(class_match=False),
        dict(active=False), dict(busy=True), dict(occupied=True), dict(list_match=False, eligible=True, object_count=0),
        dict(list_match=False, eligible=True, object_index=0x10005, object_count=0x10006)))
    cases.extend((True, settings) for settings in (dict(flag=0), dict(present=False), dict(active=False), dict(occupied=True)))
    return [(direct, dict(DEFAULTS, **settings)) for direct, settings in cases]


def expected_case(direct, settings, c):
    """Instruction-derived contract, not an interpretation of backend semantics.

    Wrapper offsets36/58/68 are actor/class exits. The target's stores211/338/
    356 and AL-only exits363 follow the exact 103-instruction transfer shape.
    """
    s = settings;events = [] if direct else ['class', 'lookup'] + (['class'] if s['present'] else [])
    wrapper_gate = s['present'] and s['class_count'] >= s['class_index'] and s['class_match']
    reaches = direct or wrapper_gate
    operates = reaches and s['active'] and not s['busy'] and s['present'] and not s['occupied']
    entry = [dict(service=True, actor=s['present'], flag=s['flag'] if direct else 1, stack=0x38000)] if reaches else []
    writes = []
    if not reaches:
        returned = TYPE_INFO if s['present'] else 0
    elif not s['active'] or s['busy'] or not s['present']:
        # Wrapper's singleton getter leaves the raw service pointer in RAX.
        # Direct calls seed RAX=0; xor AL,AL preserves the remaining bits.
        returned = 0 if direct else SERVICE
    else:
        events.append('occupied')
        if s['occupied']: returned = 0
        else:
            events += ['assign', 'mode']
            if s['mode'] != 3:
                events.append('predicate')
                if not s['predicate']: events.append('fallback')
                if s['predicate'] or s['fallback']: events.append('hide')
            flag = s['flag'] if direct else 1
            if flag: events.append('list_match')
            list_path = bool(flag and s['list_match'])
            if list_path:
                events += ['virtual_0x2e8', 'virtual_0x540'];offset = 211
            else:
                events += ['settle', 'eligible'];offset = 356
                if s['eligible']:
                    events += ['virtual_0x4c8', 'virtual_0x540', 'virtual_0x2e8', 'mark']
                    offset = 338 if s['object_index'] < s['object_count'] else 356
            writes = [dict(offset='0x250', size=8, value=0, instruction=hex(int(c['functions']['target'], 16) + offset))]
            returned = 1
    return dict(direct=direct, settings=s, returned=returned, events=events, writes=writes,
        target_entry=entry, slot=0 if operates else 0xaabbccdd, guards=True, abi=True, arguments_checked=True, initial_rax=0)


def expected_rows(c): return [expected_case(direct, settings, c) for direct, settings in matrix()]


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def validate_report(r, c):
    if (not isinstance(r, dict) or type(r.get('schema')) is not int or r['schema'] != 1 or r.get('method') != 'bounded_native'):
        raise ValueError('Post-state report schema/method differs')
    for name in ('network_used', 'profile_activated', 'runtime_activated', 'backend_used', 'full_handler_executed'):
        if r.get(name) is not False: raise ValueError('Post-state fixture/native activation scope differs')
    if r.get('native_post_state_used') is not True: raise ValueError('Post-state native scope differs')
    if r.get('source_sha256') != c.get('source_sha256') or canonical(r.get('tail_calls')) != canonical(c['tail_calls']):
        raise ValueError('Post-state source/tail report provenance differs')
    expected = expected_rows(c)
    if len(expected) != case_count() or canonical(r.get('cases')) != canonical(expected):
        raise ValueError('Post-state matrix, raw return, events or writes differ')
