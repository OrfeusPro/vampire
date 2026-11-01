"""Independent expected projections for actual Login backend native delivery.

Prepared values come from the guarded parent report; bytes come from the frozen
field oracle. Runtime observations must never be used to seed their own expected
packet, archive or transport frame.
"""
import copy
import importlib.util
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


CONTRACT = load('login-backend-wire-native-contracts')
HANDOFF = load('login-send-handoff-oracle')


def prepared_rows(prepare_report): return HANDOFF.prepared_rows(prepare_report)


def expected_handoff(spec, prepared):
    parent_spec = {key: spec[key] for key in CONTRACT.INPUT.PARENT.SPEC_FIELDS}
    child = HANDOFF.expected_case(parent_spec, prepared)['handoff']
    for key in ('sink_calls', 'sink_same_packet', 'sink_arguments',
            'sink_arguments_checked', 'synthetic_service_vtable'):
        del child[key]
    forwarded = child['forwarded']; checked = True if forwarded else None
    child.update(service_calls=int(forwarded), service_same_packet=checked,
        service_arguments=dict(receiver='source_service', packet='same_prepared_packet') if forwarded else None,
        service_arguments_checked=checked, source_service_vtable=True,
        thunk_calls=int(forwarded), thunk_arguments_checked=checked, thunk_same_packet=checked)
    return child


def expected_publisher():
    return dict(calls=1, published_singleton=True,
        vptrs=['initial_primary', 'primary', 'secondary'],
        backend_zeroed_before_ambient=True, ambient_backend_bound=True,
        returned_service=True, guards=True, abi=True)


def expected_backend(spec):
    flow = CONTRACT.expected_flow(spec)
    entered = bool(flow['backend_calls']); ready = bool(flow['writer_calls'])
    return dict(entry_calls=flow['backend_calls'], return_byte=flow['backend_return_al'],
        state_getter_calls=flow['state_getter_calls'],
        state_return=spec['backend_state'] if flow['state_getter_calls'] else None,
        action_calls=flow['fallback_calls'],
        action_arguments_checked=True if flow['fallback_calls'] else None,
        arguments_checked=True if entered else None,
        sequence_before=flow['sequence_before'], sequence_after=flow['sequence_after'],
        id_getter_calls=flow['request_id_calls'], request_id=3 if ready else None,
        platform_first_calls=flow['debug_first_calls'],
        platform_second_calls=flow['debug_second_calls'],
        diagnostic_selector_offset=flow['selected_diagnostic_offset'])


def expected_wire(spec, prepared):
    flow = CONTRACT.expected_flow(spec); ready = bool(flow['writer_calls'])
    body = CONTRACT.BYTES.login_body(prepared)
    prefix = struct.pack('<HH', 3, spec['sequence_seed'])
    inner = prefix + body
    frame = CONTRACT.BYTES.frame(body, spec['sequence_seed'], CONTRACT.INPUT.CHECKSUM_FIXTURE)
    checked = True if ready else None
    result = {key: flow[key] for key in ('writer_calls', 'request_id_calls',
        'archive_constructor_calls', 'archive_cleanup_calls', 'initial_growth_calls',
        'checksum_calls', 'transform_calls', 'transport_calls')}
    result.update(append_calls=int(ready),
        writer_prefix_hex=prefix.hex() if ready else None,
        writer_delta_hex=body.hex() if ready else None,
        inner_hex=inner.hex() if ready else None,
        plaintext_frame_hex=frame.hex() if ready else None,
        frame_hex=frame.hex() if ready else None,
        transport_hex=frame.hex() if ready else None,
        checksum_input_hex=inner.hex() if ready else None,
        writer_entry_count=len(prefix) if ready else None,
        writer_return_count=len(inner) if ready else None,
        inner_bytes=len(inner) if ready else None,
        frame_bytes=len(frame) if ready else None,
        checksum_value=CONTRACT.INPUT.CHECKSUM_FIXTURE if ready else None,
        transform_offset=3 if ready else None,
        transform_size=len(frame)-3 if ready else None,
        transform_key_bits=CONTRACT.KEY_BITS if ready else None,
        transport_return_al=spec['transport_result_byte'] if ready else None,
        request_id=3 if ready else None,
        archive_flags_bits=(0 if spec['empty'] else 0xffffffff) if ready else None,
        **{key: checked for key in ('same_packet', 'writer_source_edge', 'packet_immutable',
            'strings_immutable', 'prefix_immutable', 'transform_in_place',
            'transform_identity', 'transport_before_cleanup')},
        initial_growth_sizes=[1024, 1024] if ready else [],
        cleanup_order=['outer', 'inner'] if ready else [], guards=True,
        wire_temporaries_released=True, archive_buffers_released=True, ownership_checked=True)
    return result


def expected_case(spec, prepared):
    CONTRACT.validate_spec(spec)
    key = HANDOFF.parent_key(spec)
    if not isinstance(prepared, dict) or key not in prepared:
        raise ValueError('Backend native prepared expectation missing')
    expected = copy.deepcopy(prepared[key])
    expected['lifecycle'][0] = 'sender_entry'
    return dict(copy.deepcopy(spec), **expected,
        handoff=expected_handoff(spec, prepared), publisher=expected_publisher(),
        backend=expected_backend(spec), wire=expected_wire(spec, expected),
        ownership=dict(inputs_unchanged=True, retained_sdk_live=True,
            preparation_temporaries_released=True, packet_strings_released=True,
            guards=True, abi=True))


def validate_case(actual, spec, prepared):
    if not isinstance(actual, dict):
        raise ValueError('Backend native actual row differs')
    wanted = expected_case(spec, prepared)
    try:
        same = CONTRACT.canonical(actual) == CONTRACT.canonical(wanted)
    except (TypeError, ValueError) as error:
        raise ValueError('Backend native actual value/type differs') from error
    if not same:
        if set(actual) != set(wanted):
            raise ValueError('Backend native case fields differ')
        for key in wanted:
            if CONTRACT.canonical(actual[key]) != CONTRACT.canonical(wanted[key]):
                raise ValueError('Backend native case ' + key + ' differs')
        raise ValueError('Backend native case differs')
    return actual
