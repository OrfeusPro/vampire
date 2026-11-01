"""Admission of actual bounded Login backend observations, not planned cases.

The frozen input contract and byte oracle remain independent dependencies. This
module validates a report; source/proof/tool pointer integrity is checked by the
adapter and proof-bound harness before any native experiment.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
FAMILY = 'login-backend-wire'
FORMAT = 'login-backend-wire-v1'
SCOPE = 'bounded_native_login_backend_wire'
KEY_BITS = 0x1122334455667788
EXTENTS = dict(packet_bytes=320, session_bytes=160, service_bytes=240,
    backend_bytes=784, archive_bytes=64)
TRUE_FLAGS = ('native_prepare_used', 'native_sdk_used', 'native_metadata_used',
    'native_sender_used', 'native_service_getter_used', 'native_publisher_used',
    'native_service_thunk_used', 'native_backend_used', 'native_writer_used',
    'native_wire_used', 'native_archive_used', 'native_packet_id_used',
    'native_archive_append_used', 'native_archive_cleanup_used',
    'ambient_backend_provider_used')
FALSE_FLAGS = ('synthetic_service_vtable', 'native_checksum_used',
    'native_transform_used', 'native_transport_used', 'native_pending_insert_used',
    'native_delegate_used', 'native_backend_assignment_used', 'native_os_effects_used',
    'network_used', 'profile_activated', 'runtime_activated', 'session_executed')


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


INPUT = load('login-backend-wire-case-contracts')
BYTES = load('login-backend-wire-oracle')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def tools():
    names = ('login-backend-wire-native-contracts.py', 'login-backend-wire-native-oracle.py',
        'verify-login-backend-wire-context.py', 'verify-login-backend-wire-harness.py',
        'login-backend-wire-runtime.py', 'login-backend-wire-codec.py',
        'login-backend-wire-source.py', 'portable-native-family.py', 'research-workflow.py')
    return {**INPUT.tools(), **{str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                               for name in names}}


def case_count(): return INPUT.case_count()


def verifier(): return 'verify-login-backend-wire-context'


def scenarios(): return INPUT.scenarios()


def expected_flow(spec): return INPUT.expected_flow(spec)


def validate_spec(spec): return INPUT.validate_spec(spec)


def matrix_sha256():
    return hashlib.sha256(canonical(scenarios()).encode('utf-8')).hexdigest()


def observed_summary(rows):
    """Aggregate actual observations; never use expected flow to fill a report."""
    try:
        return dict(cases=len(rows), prepared_inputs=len({row['prepared_ordinal'] for row in rows}),
            core=sum(row['group'] == 'core' for row in rows),
            focused_negative=sum(row['group'] == 'focused-negative' for row in rows),
            pending_suppressed=sum(not row['handoff']['forwarded'] for row in rows),
            sequence_wraps=sum(row['wire']['writer_calls'] and row['backend']['sequence_after'] == 0 for row in rows),
            transport_result0=sum(row['wire']['transport_calls'] and row['wire']['transport_return_al'] == 0 for row in rows),
            transport_result1=sum(row['wire']['transport_calls'] and row['wire']['transport_return_al'] == 1 for row in rows),
            backend_calls=sum(row['backend']['entry_calls'] for row in rows),
            state_getter_calls=sum(row['backend']['state_getter_calls'] for row in rows),
            fallback_calls=sum(row['backend']['action_calls'] for row in rows),
            **{key: sum(row['wire'][key] for row in rows) for key in (
                'writer_calls', 'transport_calls', 'archive_constructor_calls',
                'archive_cleanup_calls', 'initial_growth_calls')})
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError('Backend native actual summary differs') from error


def validate_report(report, context, prepare_report):
    if (not isinstance(report, dict) or not isinstance(context, dict)
            or type(report.get('schema')) is not int or report['schema'] != 1
            or report.get('method') != 'bounded_native'
            or report.get('scope') != SCOPE
            or context.get('family') != FAMILY or context.get('format') != FORMAT
            or not isinstance(context.get('source_sha256'), str)
            or not re.fullmatch('[0-9a-f]{64}', context['source_sha256'])
            or report.get('source_sha256') != context['source_sha256']
            or not isinstance(prepare_report, dict)
            or prepare_report.get('source_sha256') != context['source_sha256']):
        raise ValueError('Backend native source/schema/scope/method differs')
    for key, wanted in EXTENTS.items():
        if (type(context.get(key)) is not int or context[key] != wanted
                or type(report.get(key)) is not int or report[key] != wanted):
            raise ValueError('Backend native ' + key + ' differs')
    for flag in TRUE_FLAGS:
        if report.get(flag) is not True:
            raise ValueError('Backend native scope differs: ' + flag)
    for flag in FALSE_FLAGS:
        if report.get(flag) is not False:
            raise ValueError('Backend native fixture boundary differs: ' + flag)
    if canonical(report.get('metadata_fields')) != canonical(prepare_report.get('metadata_fields')):
        raise ValueError('Backend native metadata provenance differs')
    specs = scenarios(); rows = report.get('cases')
    if (len(specs) != case_count() or len({canonical(spec) for spec in specs}) != case_count()
            or not isinstance(rows, list) or len(rows) != case_count()
            or report.get('matrix_sha256') != matrix_sha256()):
        raise ValueError('Backend native exact matrix differs')
    oracle = load('login-backend-wire-native-oracle')
    prepared = oracle.prepared_rows(prepare_report)
    for row, spec in zip(rows, specs):
        oracle.validate_case(row, spec, prepared)
    actual = observed_summary(rows)
    if (canonical(actual) != canonical(INPUT.summary())
            or canonical(report.get('summary')) != canonical(actual)):
        raise ValueError('Backend native observed summary differs')
