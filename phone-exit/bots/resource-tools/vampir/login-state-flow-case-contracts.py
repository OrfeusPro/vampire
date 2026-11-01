"""Exact native dispatch/post-state/continuation integration matrix.

Frozen child contracts supply fixture expectations. Their old native suites are
not invoked; each new row is one actual source-bound delivery through dispatch.
"""
import copy
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
FAMILY = 'login-state-flow'
FORMAT = 'login-state-flow-v1'
SCOPE = 'bounded_native_login_state_flow'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


DISPATCH = load('login-dispatch-case-contracts')
POST_STATE = load('post-state-case-contracts')
CONTINUATION = load('login-handler-case-contracts')
TRUE_FLAGS = tuple(flag for flag in DISPATCH.TRUE_FLAGS if flag != 'native_lookup_used') + (
    'native_post_state_used', 'native_post_state_getter_used',
    'native_continuation_used', 'native_continuation_constructor_used',
    'native_continuation_getter_used', 'native_continuation_reset_used')
FALSE_FLAGS = tuple(flag for flag in DISPATCH.FALSE_FLAGS
    if flag not in ('native_post_state_used', 'native_continuation_used')) + (
    'native_lookup_used', 'native_post_state_backend_used',
    'native_continuation_helpers_used', 'native_nonempty_destructor_used')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def tools():
    names = ('login-state-flow-case-contracts.py', 'login-state-flow-oracle.py',
        'login-state-flow-handler-fixtures.py', 'login-state-flow-native-providers.py',
        'login-state-flow-diagnostics.py',
        'verify-login-state-flow-context.py', 'verify-login-state-flow-harness.py',
        'post-state-case-contracts.py', 'login-handler-case-contracts.py')
    return {**DISPATCH.tools(), **{str(HERE / n): hashlib.sha256((HERE / n).read_bytes()).hexdigest() for n in names}}


def case_count(): return 325

def verifier(): return 'verify-login-state-flow-context'


def post_settings():
    return [copy.deepcopy(settings) for direct, settings in POST_STATE.matrix() if not direct]


def continuation_settings():
    return [dict(level=level, capacity=capacity) for level, capacity in itertools.product((0, 1, 2, 5), (128, 256))]


def _delivery(label, composition, post, continuation, *, group, index, before=()):
    return dict(kind='delivery', group=group, label=label, composition=copy.deepcopy(composition),
        post_settings=copy.deepcopy(post), continuation_settings=copy.deepcopy(continuation),
        before_keys=list(before), after_keys=[], tls_index=index % 2, poison=0x55 if index % 2 == 0 else 0xaa)


def scenarios():
    rows = []
    for i, post in enumerate(post_settings()):
        for j, continuation in enumerate(continuation_settings()):
            index = len(rows)
            rows.append(_delivery('post-%02d-cont-%02d' % (i, j), dict(kind='full', scenario={}),
                post, continuation, group='state-flow', index=index,
                before=(0, 1, 2, 3, 5, 6, 7, 8) if index == 0 else ()))
    negatives = [('peer-early', dict(field48=1, peer_flag=1)), ('denied-code1', dict(code=1)),
                 ('skipped-gate54', dict(code=54)), ('dedicated22', dict(code=22))]
    for name, scenario in negatives:
        rows.append(_delivery(name, dict(kind='full', scenario=scenario), dict(POST_STATE.DEFAULTS),
            dict(level=5, capacity=256), group='negative-handler', index=len(rows)))
    rows.append(_delivery('empty-reader-body', dict(kind='truncated', scenario={}, fail_at=0, cut=0),
        dict(POST_STATE.DEFAULTS), dict(level=5, capacity=256), group='negative-reader', index=len(rows)))
    return rows


def frame_body(spec): return DISPATCH.frame_body(spec)

def expected_setup(spec): return DISPATCH.expected_setup(spec)

def expected_case(spec): return load('login-state-flow-oracle').expected_case(spec)


def validate_report(report, context):
    if (not isinstance(report, dict) or type(report.get('schema')) is not int or report['schema'] != 1
            or report.get('method') != 'bounded_native' or report.get('source_sha256') != context.get('source_sha256')
            or not isinstance(context.get('source_sha256'), str) or not re.fullmatch('[0-9a-f]{64}', context['source_sha256'])
            or context.get('family') != FAMILY or context.get('format') != FORMAT):
        raise ValueError('State-flow source/schema/method differs')
    if report.get('scope') != SCOPE:
        raise ValueError('State-flow report scope differs')
    extents = (('packet_bytes', 352), ('packet_allocation_bytes', 344), ('owner_bytes', 80), ('node_bytes', 40),
        ('framing_minimum', 5), ('continuation_bytes', 1024), ('post_state_service_bytes', 768),
        ('post_state_actor_bytes', 832), ('post_state_class_bytes', 64))
    for key, value in extents:
        if type(context.get(key)) is not int or context[key] != value:
            raise ValueError('State-flow ' + key + ' differs')
    for flag in TRUE_FLAGS:
        if report.get(flag) is not True:
            raise ValueError('State-flow native scope differs: ' + flag)
    for flag in FALSE_FLAGS:
        if report.get(flag) is not False:
            raise ValueError('State-flow fixture boundary differs: ' + flag)
    if (report.get('framing_precondition') != 'frame_size_at_least_5'
            or report.get('initial_context_precondition') != 'active_packet_and_tls_zero'):
        raise ValueError('State-flow framing/context precondition differs')
    wanted = scenarios(); rows = report.get('cases')
    if (len(wanted) != case_count() or len({canonical(s) for s in wanted}) != case_count()
            or not isinstance(rows, list) or len(rows) != case_count()):
        raise ValueError('State-flow exact matrix differs')
    oracle = load('login-state-flow-oracle')
    for row, spec in zip(rows, wanted):
        oracle.validate_case(row, spec)
