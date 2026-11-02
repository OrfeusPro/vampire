"""Точная offline-матрица владения service/backend; без исполнения клиента."""
import copy
from functools import lru_cache
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
FAMILY = 'service-lifecycle'
FORMAT = 'service-lifecycle-v1'
SCOPE = 'bounded_native_service_lifecycle'
EXTENTS = dict(service_bytes=240, backend_bytes=800, control_bytes=24, callback_fixture_bytes=48)
CALL_KEYS = ('service.publisher', 'service.assign', 'control.move_release', 'control.deleting',
    'backend.constructor', 'backend.base_constructor', 'service.deleting', 'backend.deleting',
    'backend.destructor', 'backend.base_destructor', 'backend.reset',
    'backend.string_ring_clear', 'control.dispatch')
POISONS = (dict(allocator_poison=0x5a, stack_poison=0x6d),
           dict(allocator_poison=0xa5, stack_poison=0xb7))
TRUE_FLAGS = ('native_service_publisher_used', 'native_service_assignment_used',
    'native_backend_constructor_used', 'native_backend_base_constructor_used',
    'native_control_move_release_used', 'native_control_dispatch_used',
    'native_control_deleting_used', 'native_service_deleting_used',
    'native_backend_deleting_used', 'native_backend_destructor_used',
    'native_backend_base_destructor_used', 'native_backend_reset_used',
    'native_string_ring_clear_used', 'native_atomic_counter_transitions_used',
    'ambient_service_provider_used', 'ambient_control_provider_used',
    'ambient_registration_provider_used', 'synthetic_callback_storage_used')
FALSE_FLAGS = ('native_allocator_used', 'native_vector_storage_helpers_used',
    'native_engine_effects_used', 'native_registration_helpers_used',
    'native_callback_allocator_used', 'native_callback_destructor_used',
    'native_callback_execution_used', 'native_writer_used', 'native_checksum_used',
    'native_unregistration_used',
    'native_transform_used', 'native_prepare_used', 'native_sdk_used',
    'native_sender_used', 'native_transport_used', 'native_socket_used',
    'native_drain_used', 'native_process_initializer_used',
    'native_process_cleanup_used', 'native_concurrent_lifetime_used',
    'native_os_effects_used', 'network_used', 'profile_activated',
    'runtime_activated', 'session_executed')
ROUND_CHECKS = ('guards', 'abi', 'source_aliases_checked', 'ownership_checked',
                'source_defined_fields_checked')


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def scenarios():
    rows = []
    def add(**fields):
        rows.append(dict(**fields, cleanup_find='end', rounds=copy.deepcopy(list(POISONS))))
    for old in ('none', 'last_reference', 'shared_reference'):
        for callback in ('absent', 'source_table_synthetic_storage'):
            for flags in (0, 1):
                add(case_id='lifecycle-' + str(len(rows)).zfill(2), group='assignment_lifecycle',
                    old_backend=old, callback_model=callback, service_delete_flags=flags)
    axes = (('null_null', None, None, 0, 0),
        ('equal_control_values', 'A', 'A', 1, 1),
        ('same_pointer_slot', 'A', 'same_slot', 1, 1),
        ('null_to_new', None, 'B', 0, 0),
        ('replace_shared', 'A', 'B', 2, 1),
        ('replace_last_weak_held', 'A', 'B', 1, 2),
        ('replace_last_both', 'A', 'B', 1, 1),
        ('clear_shared', 'A', None, 2, 3),
        ('clear_last_weak_held', 'A', None, 1, 3),
        ('clear_last_null_backend', 'A_null', None, 1, 1))
    for i, (name, destination, source, strong, weak) in enumerate(axes):
        add(case_id='move-' + str(i).zfill(2), group='control_move_release', name=name,
            destination=destination, source=source, old_strong=strong, old_weak=weak)
    for flags in (0, 1, 2, 3):
        add(case_id='backend-delete-' + str(flags), group='deleting_flags',
            entry='backend.deleting', flags=flags)
    for flags in (0, 1):
        add(case_id='control-delete-' + str(flags), group='deleting_flags',
            entry='control.deleting', flags=flags)
    i = 0
    for queues in ('all_empty', 'first_nonempty', 'all_three_nonempty'):
        for ring in ('empty', 'wrapped_two_sso_and_small_heap'):
            add(case_id='reset-' + str(i).zfill(2), group='reset_and_ring_ownership',
                queues=queues, string_ring=ring, socket_id=0)
            i += 1
    # Native base constructor leaves local capacity zero. A local insertion
    # therefore must reserve; global spare storage is an input before entry.
    profiles = (('both_found', 'found', 'found', []),
        ('local_insert_reserve', 'end', 'found', ['local']),
        ('global_insert_reserve', 'found', 'end', ['global']),
        ('both_insert_mixed', 'end', 'end', ['local']))
    i = 0
    for name, local, global_, reserve in profiles:
        for observer in ('null', 'synthetic_weak_control'):
            add(case_id='constructor-' + str(i).zfill(2), group='constructor_registration_branches',
                iterator_fixture=dict(name=name, local=local, global_=global_, reserve=list(reserve)),
                observer_control=observer)
            i += 1
    return rows


def case_count():
    return 42


@lru_cache(maxsize=1)
def _recipes():
    return {spec['case_id']: canonical(spec) for spec in scenarios()}


def validate_spec(spec):
    try:
        if (not isinstance(spec, dict) or not isinstance(spec.get('case_id'), str)
                or canonical(spec) != _recipes().get(spec['case_id'])):
            raise ValueError('Service lifecycle exact input recipe differs')
    except (TypeError, ValueError) as error:
        raise ValueError('Service lifecycle exact input recipe differs') from error
    return spec


def matrix_sha256():
    return hashlib.sha256(canonical(scenarios()).encode('utf-8')).hexdigest()


def tools():
    names = ('service-lifecycle-case-contracts.py', 'service-lifecycle-oracle.py',
        'verify-service-lifecycle-context.py', 'service-lifecycle-harness.py',
        'service-lifecycle-runtime.py', 'service-lifecycle-memory.py',
        'service-lifecycle-providers.py', 'portable-native-family.py',
        'research-workflow.py', 'build-native-entry-code.py', 'extract-native-enums.py')
    return {str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in names}


def verifier():
    return 'verify-service-lifecycle-context'


def observed_summary(rows):
    try:
        result = dict(cases=len(rows), rounds=0, native_entries=0, native_calls=0,
            native_allocations=0, native_frees=0, atomic_transitions=0,
            assignment_lifecycle_cases=0, control_move_release_cases=0, deleting_flags_cases=0,
            reset_and_ring_ownership_cases=0, constructor_registration_branches_cases=0,
            callback_copies=0, callback_unknown_nonzero=0,
            retained_owner_observations=0,
            retained_fixture_owner_observations=0,
            **{role + '_calls': 0 for role in CALL_KEYS})
        for row in rows:
            result[row['spec']['group'] + '_cases'] += 1
            for round_ in row['observation']['rounds']:
                result['rounds'] += 1
                result['native_entries'] += len(round_['entries'])
                result['native_allocations'] += len(round_['native_allocations'])
                result['native_frees'] += len(round_['native_frees'])
                result['atomic_transitions'] += len(round_['atomic_transitions'])
                result['retained_owner_observations'] += len(round_['retained_owners'])
                result['retained_fixture_owner_observations'] += len(round_['retained_fixture_owners'])
                for role in CALL_KEYS:
                    result[role + '_calls'] += round_['calls'][role]
                    result['native_calls'] += round_['calls'][role]
                for assignment in round_['effects'].get('assignments', []):
                    if assignment['callback'] is not None:
                        result['callback_copies'] += 1
                        result['callback_unknown_nonzero'] += int(assignment['callback']['unknown_dword'] != 0)
        return result
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError('Service lifecycle actual summary differs') from error


def validate_report(report, context):
    if (not isinstance(report, dict) or type(report.get('schema')) is not int or report['schema'] != 1
            or report.get('method') != 'bounded_native' or report.get('scope') != SCOPE
            or context.get('family') != FAMILY or context.get('format') != FORMAT
            or not isinstance(context.get('source_sha256'), str)
            or not re.fullmatch('[0-9a-f]{64}', context['source_sha256'])
            or report.get('source_sha256') != context['source_sha256']
            or report.get('backend_context') != context.get('backend_context')
            or report.get('backend_check') != context.get('backend_check')):
        raise ValueError('Service lifecycle report source/scope/dependencies differ')
    for key, value in EXTENTS.items():
        if (type(report.get(key)) is not int or report[key] != value
                or type(context.get(key)) is not int or context[key] != value):
            raise ValueError('Service lifecycle extent differs: ' + key)
    for key in TRUE_FLAGS:
        if report.get(key) is not True:
            raise ValueError('Service lifecycle native scope differs: ' + key)
    for key in FALSE_FLAGS:
        if report.get(key) is not False:
            raise ValueError('Service lifecycle fixture boundary differs: ' + key)
    rows = report.get('cases')
    if not isinstance(rows, list) or len(rows) != case_count() or report.get('matrix_sha256') != matrix_sha256():
        raise ValueError('Service lifecycle exact matrix differs')
    oracle = load('service-lifecycle-oracle')
    for row, spec in zip(rows, scenarios()):
        oracle.validate_case(row, spec)
    actual = observed_summary(rows)
    expected = observed_summary([oracle.expected_case(spec) for spec in scenarios()])
    if canonical(actual) != canonical(expected) or canonical(report.get('summary')) != canonical(actual):
        raise ValueError('Service lifecycle actual summary differs')
