"""Exact prepare-to-synthetic-service handoff matrix; no wire or online proof."""
import copy
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
FAMILY = 'login-send-handoff'
FORMAT = 'login-send-handoff-v1'
SCOPE = 'bounded_native_login_send_handoff'
SPEC_FIELDS = ('scenario', 'selector', 'empty', 'poison', 'cache_case', 'metadata_case', 'pending_case')
TRUE_FLAGS = ('native_prepare_used', 'native_sdk_used', 'native_metadata_used',
    'native_sender_used', 'native_service_getter_used', 'synthetic_service_vtable')
FALSE_FLAGS = ('native_wire_used', 'native_writer_used', 'native_pending_insert_used',
    'native_delegate_used', 'native_service_backend_used', 'native_os_effects_used',
    'network_used', 'profile_activated', 'runtime_activated', 'session_executed')
PENDING_CASES = ('empty-count-equal', 'inline-bucket-miss', 'heap-chain-miss', 'heap-chain-hit')
PENDING_TIMEOUT_BITS = dict(zip(PENDING_CASES, (0x3fa00000, 0x40200000, 0x40700000, 0x40900000)))


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


PARENT = load('login-metadata-case-contracts')
PREPARE = load('verify-login-prepare-context')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def tools():
    names = ('login-send-handoff-case-contracts.py', 'login-send-handoff-oracle.py',
        'verify-login-send-handoff-context.py', 'verify-login-send-handoff-harness.py',
        'login-send-handoff-runtime.py', 'login-sdk-fixtures.py')
    return {**PARENT.tools(), **{str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                               for name in names}}


def case_count(): return 896


def verifier(): return 'verify-login-send-handoff-context'


def pending_settings(name):
    if not isinstance(name, str) or name not in PENDING_CASES:
        raise ValueError('Send handoff pending case differs')
    index = PENDING_CASES.index(name)
    return dict(forwarded=index != 3, timeout_bits=PENDING_TIMEOUT_BITS[name],
        bucket_storage=('not-read', 'inline', 'heap', 'heap')[index],
        lookup_keys=copy.deepcopy(([], [], [8], [8, 4])[index]))


def scenarios():
    return [dict(scenario=scenario[0], selector=3, empty=empty, poison=0x55,
                 cache_case='warm', metadata_case=list(metadata), pending_case=pending)
        for scenario, empty, metadata, pending in itertools.product(
            PREPARE.SCENARIOS, (False, True), PARENT.INTEGRATION_CASES, PENDING_CASES)]


def validate_spec(spec):
    if not isinstance(spec, dict) or set(spec) != set(SPEC_FIELDS):
        raise ValueError('Send handoff case dimensions differ')
    try:
        valid = (isinstance(spec['scenario'], str) and spec['scenario'] in {row[0] for row in PREPARE.SCENARIOS}
            and type(spec['selector']) is int and spec['selector'] == 3
            and type(spec['empty']) is bool and type(spec['poison']) is int and spec['poison'] == 0x55
            and spec['cache_case'] == 'warm'
            and canonical(spec['metadata_case']) in {canonical(list(row)) for row in PARENT.INTEGRATION_CASES}
            and isinstance(spec['pending_case'], str) and spec['pending_case'] in PENDING_CASES)
    except (TypeError, ValueError):
        valid = False
    if not valid:
        raise ValueError('Send handoff exact case dimensions differ')
    return spec


def expected_case(spec, prepare_report):
    oracle = load('login-send-handoff-oracle')
    return oracle.expected_case(spec, oracle.prepared_rows(prepare_report))


def validate_report(report, context, prepare_report):
    if (not isinstance(report, dict) or not isinstance(context, dict)
            or type(report.get('schema')) is not int or report['schema'] != 1
            or report.get('method') != 'bounded_native'
            or context.get('family') != FAMILY or context.get('format') != FORMAT
            or not isinstance(context.get('source_sha256'), str)
            or not re.fullmatch('[0-9a-f]{64}', context['source_sha256'])
            or report.get('source_sha256') != context['source_sha256']
            or not isinstance(prepare_report, dict)
            or prepare_report.get('source_sha256') != context['source_sha256']):
        raise ValueError('Send handoff source/schema/method differs')
    if report.get('scope') != SCOPE:
        raise ValueError('Send handoff report scope differs')
    for name, value in (('packet_bytes', 320), ('session_bytes', 160)):
        if (type(context.get(name)) is not int or context[name] != value
                or type(report.get(name)) is not int or report[name] != value):
            raise ValueError('Send handoff ' + name + ' differs')
    for flag in TRUE_FLAGS:
        if report.get(flag) is not True:
            raise ValueError('Send handoff native scope differs: ' + flag)
    for flag in FALSE_FLAGS:
        if report.get(flag) is not False:
            raise ValueError('Send handoff fixture boundary differs: ' + flag)
    if canonical(report.get('metadata_fields')) != canonical(prepare_report.get('metadata_fields')):
        raise ValueError('Send handoff metadata provenance differs')
    wanted = scenarios(); rows = report.get('cases')
    if (len(wanted) != case_count() or len({canonical(row) for row in wanted}) != case_count()
            or not isinstance(rows, list) or len(rows) != case_count()):
        raise ValueError('Send handoff exact matrix differs')
    oracle = load('login-send-handoff-oracle')
    prepared = oracle.prepared_rows(prepare_report)
    for row, spec in zip(rows, wanted):
        oracle.validate_case(row, spec, prepared)
