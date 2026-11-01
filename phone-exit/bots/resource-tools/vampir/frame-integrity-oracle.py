"""Pure expectations from immutable prepared inputs and existing frame primitives.

No expected bytes are copied into native archives. A synthetic packet is seeded
from the separately proved parent; the admitted Login writer must produce bytes.
"""
import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import zlib

HERE = Path(__file__).resolve().parent
SHARED = HERE.parents[1] / 'vampir-shared'
if str(SHARED) not in sys.path:
    sys.path.insert(0, str(SHARED))
from vampir_core import frame_primitives as PRIMITIVES
from vampir_core import ping as PING

if (Path(PRIMITIVES.__file__).resolve() != (SHARED / 'vampir_core/frame_primitives.py').resolve()
        or Path(PING.__file__).resolve() != (SHARED / 'vampir_core/ping.py').resolve()):
    raise ValueError('Frame integrity oracle primitive import origin differs')
payload_crc32, xor_transform = PRIMITIVES.payload_crc32, PRIMITIVES.xor_transform


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONTRACT = load('frame-integrity-case-contracts')
HANDOFF = load('login-send-handoff-oracle')
PARENT_INPUT = load('login-backend-wire-case-contracts')
BODY = load('login-backend-wire-oracle')


def prepared_rows(prepare_report, backend_report=None):
    """Select four exact parent projections; callers check pointer/proof lineage."""
    prepared = HANDOFF.prepared_rows(prepare_report)
    specs = PARENT_INPUT.prepared_specs()
    result = {}
    for ordinal, size, digest in CONTRACT.PREPARED_INPUTS:
        key = HANDOFF.parent_key(specs[ordinal])
        if key not in prepared:
            raise ValueError('Frame integrity prepared ordinal missing')
        row = copy.deepcopy(prepared[key])
        body = BODY.login_body(row)
        if len(body) != size or hashlib.sha256(body).hexdigest() != digest:
            raise ValueError('Frame integrity immutable prepared body differs')
        if backend_report is not None:
            if (backend_report.get('source_sha256') != prepare_report.get('source_sha256')
                    or backend_report.get('method') != 'bounded_native'
                    or backend_report.get('scope') != 'bounded_native_login_backend_wire'):
                raise ValueError('Frame integrity backend parent scope/source differs')
            matches = [item for item in backend_report.get('cases', [])
                if item.get('prepared_ordinal') == ordinal and item.get('group') == 'core'
                and item.get('pending_case') == 'empty-count-equal'
                and item.get('transport_result_byte') == 0]
            if len(matches) != 1:
                raise ValueError('Frame integrity accepted parent row missing or ambiguous')
            actual = matches[0]
            if (actual.get('strings') != row['strings'] or actual.get('integers') != row['integers']
                    or actual.get('wire', {}).get('writer_calls') != 1
                    or actual['wire'].get('writer_delta_hex') != body.hex()):
                raise ValueError('Frame integrity accepted parent writer bytes differ')
        result[ordinal] = row
    return result


def expected_primitive(spec):
    operation = spec['operation']
    if operation == 'init':
        return dict(state_after=CONTRACT.MASK32, returned_state_alias=True,
                    state_write_bytes=4, guards=True, abi=True)
    payload = bytes.fromhex(spec['payload_hex'])
    if operation == 'crc':
        raw = CONTRACT.MASK32 if spec['initialize'] else spec['raw_state_seed']
        values, states, cursor = [], [], 0
        for length in spec['chunks']:
            chunk = payload[cursor:cursor + length]
            cursor += length
            # Standard one-shot primitive is authoritative for every initialized
            # prefix. Only explicitly arbitrary raw seeds need the zlib adapter.
            value = payload_crc32(payload[:cursor]) if spec['initialize'] else (
                zlib.crc32(chunk, raw ^ CONTRACT.MASK32) & CONTRACT.MASK32)
            raw = value ^ CONTRACT.MASK32
            values.append(value)
            states.append(raw)
        return dict(values=values, states=states, init_calls=int(spec['initialize']),
                    update_calls=len(spec['chunks']), source_immutable=True, guards=True, abi=True)
    if operation == 'xor':
        bits = spec['length_bits']
        source = payload if bits < 0x80000000 else b''
        return dict(output_hex=xor_transform(source, spec['key_bits']).hex(), returned=bits,
            effective_key_bits=spec['key_bits'] or CONTRACT.FALLBACK_KEY,
            disjoint_source_immutable=None if spec['in_place'] else True, guards=True, abi=True)
    raise ValueError('Frame integrity primitive operation differs')


def expected_backend(spec, prepared):
    debug = spec['debug_case']
    sequence = spec['sequence_seed']
    body = BODY.login_body(prepared)
    if prepared['integers']['0x120'] != spec['archive_flags_bits']:
        raise ValueError('Frame integrity prepared flags provider differs')
    prefix = struct.pack('<HH', 3, sequence)
    inner = prefix + body
    crc = payload_crc32(inner)
    plain = (len(inner) + 7).to_bytes(3, 'little') + struct.pack('<I', crc) + inner
    frame = plain[:3] + xor_transform(plain[3:], spec['key_bits'])
    backend = dict(entry_calls=1, return_byte=spec['transport_result_byte'],
        state_getter_calls=1, state_return=1, action_calls=0, action_arguments_checked=None,
        arguments_checked=True, sequence_before=sequence, sequence_after=(sequence + 1) & 0xffff,
        id_getter_calls=1 + int(debug != 'off'), request_id=3, platform_first_calls=1,
        platform_second_calls=int(debug != 'firsttrue'),
        diagnostic_selector_offset=4 if debug == 'off' else 0)
    wire = dict(writer_calls=1, request_id_calls=1 + int(debug != 'off'),
        archive_constructor_calls=2, archive_cleanup_calls=2, initial_growth_calls=2,
        checksum_calls=1, transform_calls=1, transport_calls=1, append_calls=1,
        writer_prefix_hex=prefix.hex(), writer_delta_hex=body.hex(), inner_hex=inner.hex(),
        plaintext_frame_hex=plain.hex(), frame_hex=frame.hex(), transport_hex=frame.hex(),
        checksum_input_hex=inner.hex(), writer_entry_count=len(prefix), writer_return_count=len(inner),
        inner_bytes=len(inner), frame_bytes=len(frame), checksum_value=crc,
        checksum_init_calls=1, checksum_initial_state=CONTRACT.MASK32,
        checksum_final_state=crc ^ CONTRACT.MASK32,
        transform_offset=3, transform_size=len(frame) - 3, transform_key_bits=spec['key_bits'],
        transform_return_value=len(frame) - 3,
        transform_effective_key_bits=spec['key_bits'] or CONTRACT.FALLBACK_KEY,
        transport_return_al=spec['transport_result_byte'], request_id=3,
        archive_flags_bits=spec['archive_flags_bits'], initial_growth_sizes=[1024, 1024],
        cleanup_order=['outer', 'inner'], transform_identity=False,
        **dict.fromkeys(('same_packet', 'writer_source_edge', 'packet_immutable',
            'strings_immutable', 'prefix_immutable', 'transform_in_place',
            'transport_before_cleanup', 'guards', 'wire_temporaries_released',
            'archive_buffers_released', 'ownership_checked'), True))
    reused = spec['reuse_step'] == 1
    return dict(backend=backend, wire=wire,
        ownership=dict(packet_immutable=True, strings_immutable=True, input_buffers_live=True,
                       archive_buffers_released=True, guards=True, abi=True),
        same_backend_as_previous=reused, same_packet_as_previous=reused)


def expected_case(spec, prepared=None):
    CONTRACT.validate_spec(spec)
    if spec['entry_mode'] == 'primitive':
        observation = expected_primitive(spec)
    else:
        if not isinstance(prepared, dict) or spec['prepared_ordinal'] not in prepared:
            raise ValueError('Frame integrity prepared input missing')
        observation = expected_backend(spec, prepared[spec['prepared_ordinal']])
    return dict(spec=copy.deepcopy(spec), observation=observation)


def validate_case(actual, spec, prepared=None):
    wanted = expected_case(spec, prepared)
    try:
        if CONTRACT.canonical(actual) != CONTRACT.canonical(wanted):
            raise ValueError('Frame integrity actual case differs')
    except (TypeError, ValueError) as error:
        raise ValueError('Frame integrity actual case differs') from error
    return actual
