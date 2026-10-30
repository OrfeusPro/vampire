"""Exact result-gate return/dispatch reports with explicit fixture boundaries."""
import hashlib
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
FAMILIES = ('result-gate',)
IMAGE_BASE = 0x140000000
CODES = (0, 1, 42, 58, 708, 1304, 0xffffffff, 0x1197)
TOOLS = ('result-gate-case-contracts.py', 'verify-result-gate-context.py', 'update-native-harness.py')


def tools():
    return {str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in TOOLS}


def case_count(family='result-gate'):
    if not isinstance(family, str) or family not in FAMILIES:
        raise ValueError('Unreviewed result gate family')
    return 243


def verifier(family='result-gate'):
    case_count(family)
    return 'verify-result-gate-context'


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _state_event():
    return dict(action='gate_state', call_offset=36, arguments_checked=True)


def expected_rows(context):
    cases = []
    for code in CODES:
        for flag in (0, 1):
            events = [_state_event()]
            if code != 0 and flag == 0 and code != 42:
                # The 0x1197 branch invokes the same error service from +961
                # and then returns true. Ordinary failures use +1001/false.
                events.append(dict(action='gate_error', call_offset=961 if code == 0x1197 else 1001, arguments_checked=True))
            cases.append(dict(code=code, state_flag=flag, returned=int(code == 0 or (code == 0x1197 and flag == 0)),
                events=events, guards=True, abi=True, state_guards=True, temporary_guards=True))
    switch = context['switch']
    index = bytes.fromhex(switch['index_bytes'])
    table = bytes.fromhex(switch['table_bytes'])
    if (len(index) != 227 or len(table) != 16 or max(index) > 3
            or type(switch['input_first']) is not int or switch['input_first'] != 1305
            or type(switch['input_count']) is not int or switch['input_count'] != 227):
        raise ValueError('Result gate indexed input layout differs')
    targets = [IMAGE_BASE + value for value in struct.unpack('<4I', table)]
    switch_cases = [dict(code=1305+number, index=slot, target=hex(targets[slot]), events=[_state_event()],
        stopped_before_target=True, abi_return_checked=False, external_branch_services_executed=False,
        state_guards=True, temporary_guards=True, guards=True) for number, slot in enumerate(index)]
    return dict(cases=cases, switch_cases=switch_cases)


def validate_report(report, context=None):
    if not isinstance(context, dict):
        raise ValueError('Result gate report requires its checked source context')
    if (not isinstance(report, dict) or type(report.get('schema')) is not int or report['schema'] != 1
            or report.get('method') != 'bounded_native' or type(report.get('code_instructions')) is not int
            or report['code_instructions'] != 251):
        raise ValueError('Result gate report schema/method/code coverage differs')
    for flag in ('network_used', 'profile_activated', 'runtime_activated', 'handler_executed', 'login_handoff_executed', 'session_executed'):
        if report.get(flag) is not False:
            raise ValueError('Result gate report scope/activation differs')
    if report.get('function') != context['function']:
        raise ValueError('Result gate report root differs')
    expected = expected_rows(context)
    if len(expected['cases']) + len(expected['switch_cases']) != 243:
        raise ValueError('Reviewed result gate coverage changed')
    for group, rows in expected.items():
        if canonical(report.get(group)) != canonical(rows):
            raise ValueError('Result gate matrix/outcome differs: ' + group)
