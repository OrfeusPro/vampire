"""Exact bounded frame-integrity inputs; no native execution or admission."""
from functools import lru_cache
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
FAMILY = 'frame-integrity'
FORMAT = 'frame-integrity-v1'
SCOPE = 'bounded_native_frame_integrity'
FALLBACK_KEY = 0x9ab378c9d02084a7
ASYMMETRIC_KEY = 0x0102030405060708
MASK32 = 0xffffffff
EXTENTS = dict(packet_bytes=320, backend_bytes=784, archive_bytes=64)
TRUE_FLAGS = ('native_backend_used', 'native_writer_used', 'native_wire_used',
    'native_archive_used', 'native_packet_id_used', 'native_archive_append_used',
    'native_archive_cleanup_used', 'native_checksum_used', 'native_transform_used',
    'ambient_packet_provider_used', 'ambient_backend_provider_used')
FALSE_FLAGS = ('native_prepare_used', 'native_sdk_used', 'native_metadata_used',
    'native_sender_used', 'native_publisher_used', 'native_service_getter_used',
    'native_service_thunk_used', 'native_backend_assignment_used',
    'native_transport_used', 'native_os_effects_used', 'network_used',
    'profile_activated', 'runtime_activated', 'session_executed')
# Four distinct prepared inputs, not mutable observations from this replay.
PREPARED_INPUTS = (
    (8, 91, '06bd82162d1b4f56e54b33d9b8aa29d73ed9e12cb93db97a6c9f8966e9ecb42d'),
    (5, 807, 'fb24014dcefeb8dae118aa4303fd7692aeb8aaa2791400668173a43f2f5ead94'),
    (0, 173, 'dc7c88de7a60ca492d9e4f6bb9722a48ebd50f6a191795eb299e0e3fef1c3d70'),
    (16, 173, '706e557df30ab6fd34e6c6ad60973803957f3e4affece6fa0d54e435dd394b20'),
)


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def pattern(length):
    return bytes((index * 37 + 11) & 255 for index in range(length))


def primitive_specs():
    rows = []
    def add(operation, group, **fields):
        rows.append(dict(case_id='primitive-' + str(len(rows)).zfill(3),
            entry_mode='primitive', operation=operation, group=group, **fields))
    for offset, seed in ((0, 0), (1, 0x12345678), (3, MASK32)):
        add('init', 'init', state_offset=offset, raw_state_seed=seed)
    payloads = [b'', b'123456789', bytes(range(256))]
    payloads += [pattern(n) for n in (1, 2, 3, 4, 7, 8, 9, 15, 16, 17,
                                     31, 32, 33, 255, 256, 257, 511, 512, 811)]
    def crc(group, payload, chunks=None, initialize=True, seed=MASK32,
            state_offset=0, source_offset=0, high32=0, unmapped=False):
        add('crc', group, payload_hex=payload.hex(),
            chunks=[len(payload)] if chunks is None else list(chunks),
            initialize=initialize, raw_state_seed=seed, state_offset=state_offset,
            source_offset=source_offset, r8_high32=high32, unmapped_source=unmapped)
    for payload in payloads:
        crc('one-shot', payload)
    for payload, chunks, state, source in (
            (b'123456789', (0, 1, 7, 0, 1, 0), 0, 1),
            (pattern(257), (0, 7, 1, 1, 248, 0), 1, 3),
            (pattern(811), (3, 4, 1, 247, 1, 1, 554), 3, 1)):
        crc('incremental', payload, chunks, state_offset=state, source_offset=source)
    for seed, payload in ((0, b''), (0, b'123456789'), (0x12345678, bytes(range(256)))):
        crc('raw-seed', payload, initialize=False, seed=seed)
    crc('width', b'', high32=0xfeedbeef, unmapped=True)
    crc('width', b'Z', high32=0xfeedbeef)
    def xor(group, payload, key, in_place=False, source=0, destination=0,
            length_bits=None, high32=0, unmapped=False):
        add('xor', group, payload_hex=payload.hex(), key_bits=key, in_place=in_place,
            source_offset=source, destination_offset=source if in_place else destination,
            length_bits=len(payload) if length_bits is None else length_bits,
            rdx_high32=high32, unmapped_data=unmapped)
    for n in (0, 1, 7, 8, 9, 15, 16, 17, 255, 256, 257, 815):
        for key in (0, ASYMMETRIC_KEY):
            for in_place in (False, True):
                xor('core', pattern(n), key, in_place)
    for key in (1, (1 << 64) - 1, FALLBACK_KEY):
        for in_place in (False, True):
            xor('key-edge', pattern(257), key, in_place)
    for source, destination, n, key, alias in (
            (1, 3, 9, ASYMMETRIC_KEY, False), (3, 1, 257, 0, False),
            (1, 1, 9, 0, True), (3, 3, 257, ASYMMETRIC_KEY, True)):
        xor('unaligned', pattern(n), key, alias, source, destination)
    for bits in (MASK32, 0x80000000):
        for key in (0, ASYMMETRIC_KEY):
            xor('signed', b'', key, length_bits=bits, unmapped=True)
    for i, bits in enumerate((0, 1, MASK32, 0x80000000)):
        xor('width', b'Z' if bits == 1 else b'', (0, ASYMMETRIC_KEY)[i & 1],
            length_bits=bits, high32=0xfeedbeef, unmapped=bits != 1)
    for key in (0, ASYMMETRIC_KEY):
        xor('empty-unmapped', b'', key, unmapped=True)
        xor('known-order', bytes(8), key)
    return rows


def integration_specs():
    rows = []
    keys = ((0, ASYMMETRIC_KEY), (1, (1 << 64) - 1),
            (ASYMMETRIC_KEY, 0), ((1 << 64) - 1, 1))
    sequences = (0, 0xfffe, 0xffff, 0)
    debug = ('off', 'firsttrue', 'secondtrue', 'off')
    def add(ordinal, key, sequence, diagnostic, result, group, reuse_step):
        rows.append(dict(case_id='backend-' + str(len(rows)).zfill(2),
            entry_mode='backend', operation='backend', group=group,
            prepared_ordinal=ordinal, key_bits=key, sequence_seed=sequence,
            debug_case=diagnostic, transport_result_byte=result,
            archive_flags_bits=0 if ordinal == 8 else MASK32, reuse_step=reuse_step))
    for index, (ordinal, _, _) in enumerate(PREPARED_INPUTS):
        for result in (0, 1):
            add(ordinal, keys[index][result], sequences[index], debug[index], result, 'independent', None)
    add(5, 0, 0xffff, 'firsttrue', 0, 'paired', 0)
    add(5, ASYMMETRIC_KEY, 0, 'secondtrue', 1, 'paired', 1)
    return rows


def scenarios():
    return primitive_specs() + integration_specs()


def case_count():
    return 113


@lru_cache(maxsize=1)
def _spec_recipes():
    return {row['case_id']: canonical(row) for row in scenarios()}


def validate_spec(spec):
    if not isinstance(spec, dict) or not isinstance(spec.get('case_id'), str):
        raise ValueError('Frame integrity input fields differ')
    try:
        if canonical(spec) != _spec_recipes().get(spec['case_id']):
            raise ValueError('Frame integrity exact input recipe differs')
    except (TypeError, ValueError) as error:
        raise ValueError('Frame integrity exact input recipe differs') from error
    return spec


def matrix_sha256():
    return hashlib.sha256(canonical(scenarios()).encode('utf-8')).hexdigest()


def tools():
    names = ('frame-integrity-case-contracts.py', 'frame-integrity-oracle.py',
        'verify-frame-integrity-context.py', 'frame-integrity-harness.py',
        'frame-integrity-runtime.py', 'frame-integrity-codec.py',
        'portable-native-family.py', 'research-workflow.py')
    paths = [HERE / name for name in names]
    shared = HERE.parents[1] / 'vampir-shared/vampir_core'
    paths += [shared / 'frame_primitives.py', shared / 'ping.py']
    return {**load('login-backend-wire-native-contracts').tools(),
            **{str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}}


def verifier():
    return 'verify-frame-integrity-context'


def observed_summary(rows):
    try:
        primitives = [row for row in rows if row['spec']['entry_mode'] == 'primitive']
        backends = [row for row in rows if row['spec']['entry_mode'] == 'backend']
        crcs = [row for row in primitives if row['spec']['operation'] == 'crc']
        xors = [row for row in primitives if row['spec']['operation'] == 'xor']
        inits = [row for row in primitives if row['spec']['operation'] == 'init']
        return dict(cases=len(rows), primitive_cases=len(primitives), init_cases=len(inits),
            crc_cases=len(crcs), xor_cases=len(xors), backend_entries=len(backends),
            prepared_inputs=len({row['spec']['prepared_ordinal'] for row in backends}),
            checksum_init_calls=len(inits) + sum(row['observation']['init_calls'] for row in crcs)
                + sum(row['observation']['wire']['checksum_init_calls'] for row in backends),
            checksum_update_calls=sum(row['observation']['update_calls'] for row in crcs)
                + sum(row['observation']['wire']['checksum_calls'] for row in backends),
            transform_calls=len(xors) + sum(row['observation']['wire']['transform_calls'] for row in backends),
            writer_calls=sum(row['observation']['wire']['writer_calls'] for row in backends),
            transport_captures=sum(row['observation']['wire']['transport_calls'] for row in backends),
            archive_constructor_calls=sum(row['observation']['wire']['archive_constructor_calls'] for row in backends),
            archive_cleanup_calls=sum(row['observation']['wire']['archive_cleanup_calls'] for row in backends),
            initial_growth_calls=sum(row['observation']['wire']['initial_growth_calls'] for row in backends),
            sequence_wraps=sum(row['observation']['backend']['sequence_before'] == 0xffff
                and row['observation']['backend']['sequence_after'] == 0 for row in backends),
            transport_result0=sum(row['observation']['wire']['transport_return_al'] == 0 for row in backends),
            transport_result1=sum(row['observation']['wire']['transport_return_al'] == 1 for row in backends),
            paired_reuses=sum(row['observation']['same_backend_as_previous'] for row in backends))
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError('Frame integrity observed summary differs') from error


def validate_report(report, context, prepare_report, backend_report=None):
    if (not isinstance(report, dict) or report.get('schema') != 1 or type(report['schema']) is not int
            or report.get('method') != 'bounded_native' or report.get('scope') != SCOPE
            or context.get('family') != FAMILY or context.get('format') != FORMAT
            or not isinstance(context.get('source_sha256'), str)
            or not re.fullmatch('[0-9a-f]{64}', context['source_sha256'])
            or report.get('source_sha256') != context.get('source_sha256')
            or report.get('source_sha256') != prepare_report.get('source_sha256')):
        raise ValueError('Frame integrity native source/schema/scope differs')
    for key, value in EXTENTS.items():
        if type(report.get(key)) is not int or report[key] != value or context.get(key) != value:
            raise ValueError('Frame integrity extent differs: ' + key)
    for flag in TRUE_FLAGS:
        if report.get(flag) is not True:
            raise ValueError('Frame integrity native scope differs: ' + flag)
    for flag in FALSE_FLAGS:
        if report.get(flag) is not False:
            raise ValueError('Frame integrity fixture boundary differs: ' + flag)
    if canonical(report.get('metadata_fields')) != canonical(prepare_report.get('metadata_fields')):
        raise ValueError('Frame integrity prepared metadata provenance differs')
    rows = report.get('cases')
    if (not isinstance(rows, list) or len(rows) != case_count()
            or report.get('matrix_sha256') != matrix_sha256()):
        raise ValueError('Frame integrity exact matrix differs')
    oracle = load('frame-integrity-oracle')
    prepared = oracle.prepared_rows(prepare_report, backend_report)
    for actual, spec in zip(rows, scenarios()):
        oracle.validate_case(actual, spec, prepared)
    actual_summary = observed_summary(rows)
    expected_summary = observed_summary([oracle.expected_case(spec, prepared) for spec in scenarios()])
    if canonical(actual_summary) != canonical(expected_summary) or canonical(report.get('summary')) != canonical(actual_summary):
        raise ValueError('Frame integrity actual summary differs')
