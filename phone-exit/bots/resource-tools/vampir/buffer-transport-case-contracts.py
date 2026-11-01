"""Frozen bounded buffer/queue inputs; no execution or runtime admission."""
from functools import lru_cache
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
FAMILY = 'buffer-transport'
FORMAT = 'buffer-transport-v1'
SCOPE = 'bounded_native_buffer_transport'
EXTENTS = dict(vector_bytes=24, queue_bytes=32, archive_bytes=64, transport_bytes=400)
TRUE_FLAGS = ('native_resize_used', 'native_growth_used', 'native_queue_append_used',
    'native_transport_used', 'native_archive_raw_used', 'native_set_count_used',
    'ambient_vector_provider_used', 'ambient_queue_provider_used',
    'ambient_archive_provider_used', 'ambient_transport_provider_used',
    'synthetic_wake_table_used')
FALSE_FLAGS = ('native_writer_used', 'native_checksum_used', 'native_transform_used',
    'native_prepare_used', 'native_sender_used', 'native_backend_used',
    'native_archive_constructor_used', 'native_backend_constructor_used',
    'native_cleanup_used', 'native_socket_used', 'native_drain_used',
    'native_transport_failure_used', 'native_backend_lifetime_used',
    'native_os_effects_used', 'network_used', 'profile_activated',
    'runtime_activated', 'session_executed')
CALL_KEYS = ('resize', 'grow', 'append', 'transport', 'archive_raw', 'set_count')


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def pattern(size):
    return bytes((i * 37 + 11) & 255 for i in range(size))


def _initial(payload=b'', capacity=0, sentinel=False, **extra):
    return dict(payload_hex=payload.hex(), capacity=capacity, sentinel=sentinel, **extra)


def _payload(payload, offset=0, high32=0, **extra):
    return dict(payload_hex=payload.hex(), source_offset=offset, r8_high32=high32, **extra)


def resize_specs():
    triples = [(4, 8, 0), (4, 8, 1), (4, 8, 3), (0, 0, 0), (0, 8, 0),
        (4, 8, 4), (8, 8, 8), (0, 8, 1), (0, 8, 8), (4, 8, 5),
        (4, 8, 7), (4, 8, 8), (0, 0, 1), (0, 0, 1024), (0, 0, 4095),
        (0, 0, 4096), (4, 10, 11), (4, 10, 14), (4, 10, 15), (4, 10, 16),
        (4, 9, 10), (4, 9, 13), (4, 9, 14), (4, 2730, 2731),
        (4, 2731, 2732), (4, 4095, 4096), (4, 4096, 4097),
        (1, 1, 2), (2, 2, 3), (3, 3, 4), (3, 3, 5)]
    rows = [dict(case_id='resize-' + str(i).zfill(2), mode='resize',
        initial=_initial(pattern(size), capacity), steps=[dict(requested_size=n)])
        for i, (size, capacity, n) in enumerate(triples)]
    for size, capacity, requests in ((4, 8, (0, 0, 3, 8, 9)),
            (4, 10, (11, 15, 16, 4, 16, 17)),
            (4, 2730, (2731, 2730, 4095, 4096))):
        rows.append(dict(case_id='resize-' + str(len(rows)).zfill(2), mode='resize',
            initial=_initial(pattern(size), capacity),
            steps=[dict(requested_size=n) for n in requests]))
    return rows


def append_specs():
    axes = [(0, 0, False, 0), (0, 0, False, 1), (0, 8, False, 0),
        (0, 8, False, 7), (0, 8, False, 8), (0, 8, True, 0),
        (3, 8, True, 0), (3, 8, True, 1), (3, 8, True, 4), (3, 8, True, 5)]
    rows = [dict(case_id='append-' + str(i).zfill(2), mode='append',
        initial=_initial(pattern(size), capacity, sentinel),
        steps=[_payload(pattern(n), (i % 3), 0xfeedbeef if i == 9 else 0)])
        for i, (size, capacity, sentinel, n) in enumerate(axes)]
    for initial, payloads in ((_initial(), (b'', b'a', b'\0b', b'', b'c\0def')),
            (_initial(b'abc', 8, True), (b'\0', b'', b'def')),
            (_initial(b'abc', 8, True), (b'12345', b'', b'6\0abcdefg'))):
        rows.append(dict(case_id='append-' + str(len(rows)).zfill(2), mode='append',
            initial=initial, steps=[_payload(p, 3, 0xfeedbeef) for p in payloads]))
    return rows


def transport_specs():
    rows = []
    for state, busy, payload in ((1, 0, b'a\0b'), (0, 0, b'a'), (2, 0, b''),
            (1, 1, b'ab'), (1, 0xffffffff, b'\0'), (0xffffffff, 0, b'abc')):
        rows.append(dict(case_id='transport-' + str(len(rows)).zfill(2), mode='transport',
            initial=_initial(), steps=[_payload(payload, state=state, busy=busy)]))
    rows.append(dict(case_id='transport-06', mode='transport', initial=_initial(),
        steps=[_payload(p, 1, 0xfeedbeef, state=s, busy=b) for s, b, p in (
            (0, 0, b'a'), (1, 1, b'b\0'), (1, 0, b'c'), (2, 0, b''), (1, 0, b''))]))
    rows.append(dict(case_id='transport-07', mode='transport',
        initial=_initial(b'ab\0c', 8, True),
        steps=[_payload(b'\xff\0Z', 3, 0xfeedbeef, state=1, busy=0)]))
    return rows


def archive_specs():
    axes = [(_initial(flags_bits=1), (b'',)),
        (_initial(flags_bits=0), (b'A',)),
        (_initial(flags_bits=0xffffffff), (b'abc\0def', b'')),
        (_initial(b'abc', 1024, flags_bits=1), (pattern(1021),)),
        (_initial(b'abc', 1024, flags_bits=0xffffffff), (pattern(1022),)),
        (_initial(pattern(1023), 1024, flags_bits=0), (b'Z',)),
        (_initial(pattern(1024), 1024, flags_bits=1), (b'\0',)),
        (_initial(pattern(2048), 2048, flags_bits=0xffffffff), (b'Z',)),
        (_initial(pattern(4094), 4096, flags_bits=1), (b'\0Z',)),
        (_initial(flags_bits=0xffffffff), (b'', pattern(1023), b'Z', b'\0', b'\0\xff', b''))]
    return [dict(case_id='archive-' + str(i).zfill(2), mode='archive', initial=initial,
        steps=[_payload(p, 3 if j & 1 else 1, 0xfeedbeef if j & 1 else 0)
               for j, p in enumerate(payloads)]) for i, (initial, payloads) in enumerate(axes)]


def scenarios():
    return resize_specs() + append_specs() + transport_specs() + archive_specs()


def case_count():
    return 65


@lru_cache(maxsize=1)
def _recipes():
    return {s['case_id']: canonical(s) for s in scenarios()}


def validate_spec(spec):
    try:
        if (not isinstance(spec, dict) or not isinstance(spec.get('case_id'), str)
                or canonical(spec) != _recipes().get(spec['case_id'])):
            raise ValueError('Buffer transport exact input recipe differs')
    except (TypeError, ValueError) as error:
        raise ValueError('Buffer transport exact input recipe differs') from error
    return spec


def matrix_sha256():
    return hashlib.sha256(canonical(scenarios()).encode('utf-8')).hexdigest()


def tools():
    names = ('buffer-transport-case-contracts.py', 'buffer-transport-oracle.py',
        'verify-buffer-transport-context.py', 'buffer-transport-harness.py',
        'buffer-transport-runtime.py', 'buffer-transport-memory.py',
        'portable-native-family.py', 'research-workflow.py', 'build-native-entry-code.py',
        'extract-native-enums.py', 'build-object-zero-init-code.py')
    return {str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in names}


def verifier():
    return 'verify-buffer-transport-context'


def source_layout(context):
    """Version-bound source contract; verifier also checks the parent profile."""
    leaves = context.get('leaves', {})
    if len(leaves) != 1:
        raise ValueError('Buffer transport set-count leaf differs')
    address, raw = next(iter(leaves.items()))
    return dict(archive_table=copy.deepcopy(context['source_inputs']['archive_table']),
        archive_raw=context['functions']['archive.raw'], archive_raw_slot=136,
        set_count_leaf=dict(address=address, bytes=raw),
        archive_offsets=dict(last_count=8, flags=12, ready=16, vector=24,
                             capacity=48, cursor=52, count=56),
        transport_gate=dict(state_offset=264, required_state=1,
            busy_offset=192, required_busy=0, wake_receiver_offset=80,
            wake_argument_offset=272, wake_slot=32, queue_offset=368))


def observed_summary(rows):
    try:
        result = dict(cases=len(rows), steps=0, resize_cases=0, append_cases=0,
            transport_cases=0, archive_cases=0, cumulative_cases=0,
            **{key + '_calls': 0 for key in CALL_KEYS},
            allocate_calls=0, free_calls=0, memset_calls=0, memmove_calls=0,
            memcpy_calls=0, wake_calls=0, aligned_allocations=0, maximum_allocation_bytes=0)
        for row in rows:
            mode = row['spec']['mode']
            result[mode + '_cases'] += 1
            steps = row['observation']['steps']
            result['steps'] += len(steps)
            result['cumulative_cases'] += int(len(steps) > 1)
            for step in steps:
                for key in CALL_KEYS:
                    result[key + '_calls'] += step['calls'][key]
                for event in step['events']:
                    result[event['kind'] + '_calls'] += 1
                    if event['kind'] == 'allocate':
                        result['aligned_allocations'] += int(event['size'] >= 4096 + 39)
                        result['maximum_allocation_bytes'] = max(result['maximum_allocation_bytes'], event['size'])
        return result
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError('Buffer transport observed summary differs') from error


def validate_report(report, context):
    if (not isinstance(report, dict) or type(report.get('schema')) is not int or report['schema'] != 1
            or report.get('method') != 'bounded_native' or report.get('scope') != SCOPE
            or context.get('family') != FAMILY or context.get('format') != FORMAT
            or not isinstance(context.get('source_sha256'), str)
            or not re.fullmatch('[0-9a-f]{64}', context['source_sha256'])
            or report.get('source_sha256') != context['source_sha256']
            or report.get('wire_context') != context.get('wire_context')
            or report.get('wire_check') != context.get('wire_check')
            or canonical(report.get('source_layout')) != canonical(source_layout(context))):
        raise ValueError('Buffer transport report source/scope/dependencies differ')
    for key, value in EXTENTS.items():
        if (type(report.get(key)) is not int or report[key] != value
                or type(context.get(key)) is not int or context[key] != value):
            raise ValueError('Buffer transport extent differs: ' + key)
    for key in TRUE_FLAGS:
        if report.get(key) is not True:
            raise ValueError('Buffer transport native scope differs: ' + key)
    for key in FALSE_FLAGS:
        if report.get(key) is not False:
            raise ValueError('Buffer transport fixture boundary differs: ' + key)
    rows = report.get('cases')
    if not isinstance(rows, list) or len(rows) != case_count() or report.get('matrix_sha256') != matrix_sha256():
        raise ValueError('Buffer transport exact matrix differs')
    oracle = load('buffer-transport-oracle')
    for row, spec in zip(rows, scenarios()):
        oracle.validate_case(row, spec)
    actual = observed_summary(rows)
    expected = observed_summary([oracle.expected_case(spec) for spec in scenarios()])
    if canonical(actual) != canonical(expected) or canonical(report.get('summary')) != canonical(actual):
        raise ValueError('Buffer transport summary differs')
