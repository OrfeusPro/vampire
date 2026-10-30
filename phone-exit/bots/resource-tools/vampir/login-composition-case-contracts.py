"""Exact same-packet Login reader/handler composition contract, without dispatch."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
FAMILY = 'login-response-composition'
ORDER = [('u32', 0x10), ('string', 0x18), ('string', 0x28), ('string', 0x38),
    ('u16', 0x48), ('u64', 0x58), ('u16', 0x60), ('u64', 0x68),
    ('string', 0x70), ('u64', 0x80), ('bool', 0x88), ('string', 0x90),
    ('bool', 0xa0), ('u64', 0xb0), ('string', 0xb8), ('string', 0xc8),
    ('bool', 0xe0), ('u64', 0xf0), ('u64', 0x100), ('u64', 0x110),
    ('u64', 0x120), ('bool', 0x128), ('raw32', 0x130), ('raw32', 0x134),
    ('bool', 0x138), ('string', 0x140), ('raw32', 0x150), ('raw32', 0x154)]
WIDTH = dict(u32=4, raw32=4, u16=2, u64=8, bool=1, string=16)
BASE = 0x1234000000000000
TAIL = b'extra'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


HANDLER = load('login-full-handler-case-contracts')


def tools():
    names = ('login-composition-case-contracts.py', 'verify-login-composition-context.py',
        'verify-login-composition-harness.py', 'login-composition-handler-fixtures.py',
        'login-full-handler-case-contracts.py', 'verify-login-full-handler-context.py',
        'login-result-string-fixtures.py', 'verify-login-nested-context.py')
    return {str(HERE/n): hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in names}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def case_count(): return 77

def verifier(): return 'verify-login-composition-context'


def wire_values(scenario):
    p = dict(HANDLER.DEFAULTS, **scenario)
    values = {0x10: scenario.get('code', 0), 0x48: scenario.get('field48', 0), 0x60: scenario.get('raw16', 0x8000),
        0x130: 0xfedcba98, 0x134: 0x89abcdef, 0x150: p['field150'], 0x154: p['field154']}
    values.update({at: BASE+i for i, at in enumerate((0x58, 0x68, 0x80, 0xb0, 0xf0, 0x100, 0x110, 0x120))})
    values.update({at: 1 for at in (0x88, 0xa0, 0xe0, 0x128)})
    values[0x138] = p['flag138']
    values.update({at: '' for kind, at in ORDER if kind == 'string'})
    values.update({0x18: 'fixture', 0x38: p['message'], 0x140: p['trailing_text']})
    return values


def encode(scenario):
    values = wire_values(scenario); parts = []; ends = []
    for kind, at in ORDER:
        value = values[at]
        if kind == 'string':
            data = value.encode('utf-8'); parts.append(struct.pack('<H', len(data))+data)
        else:
            parts.append(value.to_bytes(WIDTH[kind], 'little'))
        ends.append(sum(map(len, parts)))
    return b''.join(parts), values, ends


def scenarios():
    base = HANDLER.scenarios()
    rows = [dict(kind='full', scenario=s) for s in base]
    body, _, ends = encode({})
    rows += [dict(kind='truncated', scenario={}, fail_at=i, cut=end-1) for i, end in enumerate(ends)]
    rows.append(dict(kind='trailing', scenario={}, tail_hex=TAIL.hex()))
    return rows


def expected_case(spec):
    scenario = spec['scenario']; body, values, _ = encode(scenario)
    failed = spec['kind'] == 'truncated'; tail = TAIL if spec['kind'] == 'trailing' else b''
    size = spec['cut'] if failed else len(body)+len(tail)
    operations = ORDER[:spec['fail_at']+1] if failed else ORDER
    reader = dict(returned=0 if failed else 1, size=size, consumed=size if failed else len(body),
        operations=[[kind, hex(at)] for kind, at in operations], guards=True, abi=True,
        scalar_values={} if failed else {hex(at): int(values[at] != 0) if kind == 'bool' else values[at]
            for kind, at in ORDER if kind != 'string'},
        strings={} if failed else {hex(at): values[at] for kind, at in ORDER if kind == 'string'})
    return dict(spec=spec, reader=reader, handler=None if failed else HANDLER.expected_case(scenario),
        handler_invoked=not failed, same_packet_pointer=not failed, packet_reseeded=False,
        source_buffers_unchanged=True, packet_unchanged_by_handler=True, archive_unchanged_by_handler=True,
        guards=True, abi=True)


def expected_rows(): return [expected_case(spec) for spec in scenarios()]


def validate_report(report, context):
    if (not isinstance(report, dict) or type(report.get('schema')) is not int or report['schema'] != 1
            or report.get('method') != 'bounded_native' or type(report.get('packet_bytes')) is not int or report['packet_bytes'] != 352):
        raise ValueError('Login composition schema/method/layout differs')
    for flag in ('network_used', 'profile_activated', 'runtime_activated', 'native_dispatch_used',
                 'native_post_state_used', 'native_continuation_used', 'session_executed'):
        if report.get(flag) is not False: raise ValueError('Login composition boundary differs: '+flag)
    for flag in ('same_packet_reader_used', 'native_handler_used', 'native_gate_used', 'native_strings',
                 'native_buffer_construction', 'native_scalars_used', 'native_nested_used'):
        if report.get(flag) is not True: raise ValueError('Login composition native scope differs: '+flag)
    if context.get('packet_bytes') != 352 or context.get('format') != 'login-response-composition-v1':
        raise ValueError('Login composition context layout differs')
    if canonical(report.get('operations')) != canonical(ORDER): raise ValueError('Login composition operations differ')
    if len(scenarios()) != case_count() or canonical(report.get('cases')) != canonical(expected_rows()):
        raise ValueError('Login composition matrix/outcome differs')
