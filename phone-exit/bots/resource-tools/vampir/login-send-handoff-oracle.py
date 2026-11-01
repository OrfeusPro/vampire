"""Pure expectations from a separately guarded native prepare report.

The parent report is an immutable, source-bound dependency checked by the caller.
Its old send-return pairs collapse to one prepared expectation. No old native
suite, writer, sink or other native entry is invoked by this module.
"""
import copy
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
STRING_OFFSETS = (0x10, 0x20, 0x30, 0x40, 0x58, 0x68, 0x78, 0x88,
    0xa0, 0xb8, 0xc8, 0xd8, 0xe8, 0x100, 0x110)
SCALAR_WIDTHS = {0x50: 4, 0x98: 1, 0x99: 1, 0xb0: 4, 0xf8: 4,
    0x120: 4, 0x124: 1, 0x128: 8, 0x130: 1, 0x131: 1}
PREPARED_FIELDS = ('strings', 'integers', 'lifecycle', 'native_calls',
    'metadata_calls', 'sdk_event', 'guards')


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


CONTRACT = load('login-send-handoff-case-contracts')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def parent_key(spec):
    return canonical({key: spec[key] for key in CONTRACT.SPEC_FIELDS if key != 'pending_case'})


def _validate_projection(row):
    strings = row.get('strings'); integers = row.get('integers')
    if not isinstance(strings, dict) or set(strings) != {hex(offset) for offset in STRING_OFFSETS}:
        raise ValueError('Send handoff parent string fields differ')
    for text in strings.values():
        if not isinstance(text, str) or '\0' in text:
            raise ValueError('Send handoff parent string value differs')
        try:
            units = len(text.encode('utf-16le')) // 2
        except UnicodeEncodeError as error:
            raise ValueError('Send handoff parent UTF16 differs') from error
        if units + 1 > 1024:
            raise ValueError('Send handoff parent string bound differs')
    if not isinstance(integers, dict) or set(integers) != {hex(offset) for offset in SCALAR_WIDTHS}:
        raise ValueError('Send handoff parent scalar fields differ')
    for offset, width in SCALAR_WIDTHS.items():
        value = integers[hex(offset)]
        if type(value) is not int or not 0 <= value < 1 << (8 * width):
            raise ValueError('Send handoff parent raw scalar differs')
    for name in ('native_calls', 'metadata_calls'):
        calls = row.get(name)
        if (not isinstance(calls, dict) or any(not isinstance(key, str)
                or type(value) is not int or value < 0 for key, value in calls.items())):
            raise ValueError('Send handoff parent native calls differ')
    if type(row.get('sdk_event')) is not bool or row.get('guards') is not True:
        raise ValueError('Send handoff parent lifecycle flags differ')
    lifecycle = ['send', 'post_notify'] + (['sdk_event'] if row['sdk_event'] else []) + ['destructor']
    if row.get('lifecycle') != lifecycle:
        raise ValueError('Send handoff parent lifecycle differs')


def prepared_rows(prepare_report):
    """Collapse only identical old return pairs, without inventing a new outcome.

    The adapter/harness must first verify the parent pointer, SHA, proof and tool
    lineage. This pure check does not establish integrity of an arbitrary report.
    """
    if (not isinstance(prepare_report, dict) or type(prepare_report.get('schema')) is not int
            or prepare_report['schema'] != 1 or prepare_report.get('method') != 'bounded_native'
            or prepare_report.get('scope') != 'bounded_native_login_prepare_metadata'
            or not isinstance(prepare_report.get('source_sha256'), str)
            or not re.fullmatch('[0-9a-f]{64}', prepare_report['source_sha256'])
            or any(prepare_report.get(flag) is not False
                   for flag in ('network_used', 'profile_activated', 'runtime_activated'))):
        raise ValueError('Send handoff parent source/scope differs')
    CONTRACT.PARENT.validate_report('login-prepare-metadata', prepare_report)
    result = {}; returns = {}
    for row in prepare_report['cases']:
        _validate_projection(row)
        key = parent_key(row)
        projection = {name: copy.deepcopy(row[name]) for name in PREPARED_FIELDS}
        if key in result and canonical(result[key]) != canonical(projection):
            raise ValueError('Send handoff old return pair projections differ')
        result[key] = projection
        returns.setdefault(key, set()).add(row['send_return'])
    if len(result) != 224 or any(values != {0, 1} for values in returns.values()):
        raise ValueError('Send handoff unique parent matrix differs')
    return result


def expected_case(spec, prepared):
    CONTRACT.validate_spec(spec)
    key = parent_key(spec)
    if not isinstance(prepared, dict) or key not in prepared:
        raise ValueError('Send handoff prepared expectation missing')
    row = dict(copy.deepcopy(spec), **copy.deepcopy(prepared[key]))
    row['lifecycle'][0] = 'sender_entry'
    pending = CONTRACT.pending_settings(spec['pending_case'])
    forwarded = pending['forwarded']; count = int(forwarded)
    checked = True if forwarded else None
    row['handoff'] = dict(pending_case=spec['pending_case'], forwarded=forwarded,
        configured_timeout_bits=pending['timeout_bits'], entry_timeout_bits=0,
        selected_timeout_bits=pending['timeout_bits'] if forwarded else None,
        sender_calls=1, sender_returns=1, pending_insert_calls=count, delegate_calls=count,
        service_getter_calls=count, sink_calls=count, source_virtual_calls=count,
        sink_same_packet=True if forwarded else None,
        packet_immutable=True, strings_immutable=True, synthetic_service_vtable=True,
        sender_arguments_checked=True, fifth_argument_checked=True,
        pending_insert_arguments_checked=checked, delegate_arguments_checked=checked,
        getter_global_checked=checked,
        sink_arguments=dict(receiver='synthetic_service', packet='same_prepared_packet') if forwarded else None,
        sink_arguments_checked=checked,
        observed_lookup_keys=pending['lookup_keys'], bucket_storage=pending['bucket_storage'])
    return row


def validate_case(row, spec, prepared):
    if not isinstance(row, dict):
        raise ValueError('Send handoff actual row differs')
    wanted = expected_case(spec, prepared)
    try:
        same = canonical(row) == canonical(wanted)
    except (TypeError, ValueError) as error:
        raise ValueError('Send handoff actual value/type differs') from error
    if not same:
        if set(row) != set(wanted):
            raise ValueError('Send handoff case fields differ')
        for key in wanted:
            if canonical(row[key]) != canonical(wanted[key]):
                raise ValueError('Send handoff case ' + key + ' differs')
        raise ValueError('Send handoff case differs')
    return row
