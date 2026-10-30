"""Exact synthetic current LoginResult handler service/writes contract.

The old service matrix and new trailing branches share whole native handler
execution. This oracle defines observable outcomes independently of its fixtures.
"""
import hashlib
import itertools
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAMILY = 'login-full-handler'
BASE = 0x1234000000000000
TOOLS = ('login-full-handler-case-contracts.py', 'verify-login-full-handler-context.py',
         'update-native-harness.py', 'result-gate-transfer-rules.py', 'audit-launcher-shape-11318.py')
DEFAULTS = dict(peer_flag=0, selected_server=42, previous_server=7, gate_state=0, optional_object=True,
    sdk_enabled=False, manager_present=True, sdk_callbacks=False, auth_present=False,
    post_predicate=False, flag138=1, message='', trailing_predicate=False, temp_allocated=False,
    trailing_text='', field150=0, field154=0, poison=0)


def tools():
    return {str(HERE/name): hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in TOOLS}


def case_count(): return 48
def verifier(): return 'verify-login-full-handler-context'


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def scenarios():
    result = [dict(field48=field, peer_flag=peer) for field, peer in itertools.product((0, 1, 32767, 32768, 65535), (0, 1))]
    result += [dict(code=code) for code in (1, 14, 22, 37, 54, 9400, 9818, 9819, 90021, 0xffffffff)]
    result += [dict(gate_state=1), dict(previous_server=42), dict(post_predicate=True),
        dict(sdk_enabled=True, manager_present=False), dict(sdk_enabled=True),
        dict(sdk_enabled=True, sdk_callbacks=True, auth_present=True), dict(sdk_enabled=True, sdk_callbacks=True),
        dict(sdk_enabled=True, auth_present=True)]
    result += [dict(code=code, optional_object=False, message='error') for code in (1, 9818, 9819, 90021)]
    result += [dict(code=1, gate_state=1), dict(field48=1, optional_object=False), dict(flag138=0)]
    result += [dict(raw16=value) for value in (0, 1, 65535)]
    result += [dict(code=0x1197, gate_state=flag) for flag in (0, 1)]
    result += [dict(trailing_predicate=predicate, temp_allocated=allocated, poison=poison,
                    trailing_text='новая🙂', field150=0x89abcdef, field154=0x12345678)
               for predicate, allocated, poison in itertools.product((False, True), (False, True), (0x55, 0xaa))]
    return result


def _event(action, site, owner='handler', **extra):
    return dict(action=action, owner=owner, call_offset=site, arguments_checked=True, **extra)


def _write(region, offset, size, value, site):
    return dict(region=region, offset=offset, size=size, value=value & ((1 << (8*size))-1), instruction_offset=site)


def expected_case(scenario):
    scenario = dict(scenario)
    code, field, raw = (scenario.pop(k, default) for k, default in (('code', 0), ('field48', 0), ('raw16', 0x8000)))
    settings = scenario
    p = dict(DEFAULTS, **settings)
    events, writes = [], []
    skipped_gate = code in (54, 9818, 9819, 90021)
    allowed = code == 0 or code == 0x1197 and p['gate_state'] == 0
    early = allowed and p['peer_flag'] != 0 and 0 < field < 32768
    success = allowed and not early
    if not skipped_gate:
        events.append(dict(action='native_gate', code=code, packet_id=4))
        if code not in (0, 42, 9400) and p['gate_state'] == 0:
            events.append(_event('gate_error', 961 if code == 0x1197 else 1001, owner='gate'))
        events.append(dict(action='native_gate_return', value=int(allowed)))
    if early:
        events += [_event('early', 472), _event('virtual_exit', 490)]
    elif success:
        callbacks = p['sdk_enabled'] and p['manager_present'] and p['sdk_callbacks']
        if callbacks: events.append(_event('virtual_sdk', 711))
        events.append(_event('time_pair', 790))
        events.append(_event('trailing_predicate', 820, text=p['trailing_text'], time=BASE,
            field150=p['field150'], field154=p['field154'], returned=int(p['trailing_predicate'])))
        allocated = not p['trailing_predicate'] and p['temp_allocated']
        events.append(_event('trailing_apply', 836 if p['trailing_predicate'] else 855,
            source='packet' if p['trailing_predicate'] else 'empty_temporary',
            text=p['trailing_text'] if p['trailing_predicate'] else '', temporary_allocated=allocated))
        if allocated: events.append(_event('trailing_free', 869))
        events.append(_event('toggle', 899))
        if 0 < field < 32768:
            if p['optional_object']: events += [_event('optional_prepare', 927), _event('positive', 939)]
            events.append(_event('toggle', 953))
        events += [_event('post_state', 958), _event('virtual_view', 974)]
        if callbacks: events.append(_event('sdk_a0', 1042))
        if p['flag138'] == 1: events.append(_event('flag138', 1067))
        events.append(_event('server_store', 1137))
        events.append(_event('predicate_action', 1164) if p['post_predicate'] else _event('other_action', 1184))
        if p['sdk_enabled'] and p['manager_present'] and p['auth_present']: events.append(_event('sdk_final', 1311))
    elif code == 54:
        events.append(_event('popup54', 1491))
    elif code in (9818, 9819):
        if p['optional_object']: events += [_event('optional_prepare', 1367), _event('error_9818', 1377)]
        events.append(_event('error_finish', 1384))
    elif code == 90021:
        if p['optional_object']: events.append(_event('error_90021', 1334))
        events.append(_event('error_finish', 1341 if p['optional_object'] else 1384))
    elif code in (14, 22, 37):
        if code == 22: writes.append(_write('global', 'special22', 1, 1, 417))
        events.append(_event('dedicated_error', 430))
    elif code == 9400:
        events.append(_event('error9400', 407))
    else:
        events.append(_event('disconnect', 274))
        events.append(_event('popup', 364) if p['message'] else _event('virtual_exit', 490))
    signed = raw if raw < 32768 else raw - 65536
    derived = math.floor(signed * 600000000.0 + 0.5) if success else 0xabcdef
    if success:
        for offset, size, value, at in ((0x38, 8, BASE+1, 557), (0xa0, 1, 1, 573), (0xb0, 8, BASE+4, 586),
            (0xc0, 8, BASE+5, 600), (0xd0, 8, BASE+6, 614), (0xe0, 8, BASE+7, 628), (0xe8, 1, 1, 642)):
            writes.append(_write('state', hex(offset), size, value, at))
        writes += [_write('global', 'derived', 8, derived, 766), _write('state', '0x88', 8, BASE+1, 885)]
        if p['previous_server'] != p['selected_server']:
            writes += [_write('controller', '0x30c', 4, p['selected_server'], 1101), _write('controller', '0x308', 4, p['selected_server'], 1107)]
    qwords = dict(zip(('0x38', '0x88', '0xb0', '0xc0', '0xd0', '0xe0'),
        (BASE+1, BASE+1, BASE+4, BASE+5, BASE+6, BASE+7) if success else (0xabcdef, 0, 0, 0, 0, 0)))
    return dict(code=code, field48=field, raw16=raw, settings=settings, handler_invoked=True, events=events, writes=writes,
        state=dict(text='fixture' if success else 'before', qwords=qwords, flags={'0xa0': int(success), '0xe8': int(success)}),
        controller_server=[p['selected_server']]*2 if success else [p['previous_server']]*2,
        special22=int(code == 22), derived=derived, guards=True, abi=True, packet_guards=True, string_guards=True,
        trailing_temporary_allocated=bool(success and not p['trailing_predicate'] and p['temp_allocated']),
        trailing_temporary_freed=bool(success and not p['trailing_predicate'] and p['temp_allocated']))


def expected_rows(): return [expected_case(scenario) for scenario in scenarios()]


def validate_report(report, context):
    if (not isinstance(report, dict) or type(report.get('schema')) is not int or report['schema'] != 1
            or report.get('method') != 'bounded_native' or type(report.get('packet_bytes')) is not int or report['packet_bytes'] != 352):
        raise ValueError('Full Login handler report schema/method/packet layout differs')
    for flag in ('network_used', 'profile_activated', 'runtime_activated', 'same_packet_reader_used', 'native_post_state_used',
                 'native_continuation_used', 'session_executed'):
        if report.get(flag) is not False: raise ValueError('Full Login handler report boundary differs: '+flag)
    if report.get('native_handler_used') is not True or report.get('native_gate_used') is not True:
        raise ValueError('Full Login handler native roots differ')
    if context.get('packet_bytes') != 352 or context.get('format') != 'login-full-handler-v1':
        raise ValueError('Full Login handler checked context layout differs')
    expected = expected_rows()
    if len(expected) != case_count() or canonical(report.get('cases')) != canonical(expected):
        raise ValueError('Full Login handler matrix/outcome differs')
