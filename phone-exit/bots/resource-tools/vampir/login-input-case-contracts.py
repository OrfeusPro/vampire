"""Exact portable LoginResult bounded matrices; no source/runtime admission."""
import hashlib
import itertools
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAMILIES = ('login-nested', 'login-strings-buffer')
COUNTS = dict(zip(FAMILIES, (232, 506)))
ORDER = [('u32', 0x10), ('string', 0x18), ('string', 0x28), ('string', 0x38),
         ('u16', 0x48), ('u64', 0x58), ('u16', 0x60), ('u64', 0x68),
         ('string', 0x70), ('u64', 0x80), ('bool', 0x88), ('string', 0x90),
         ('bool', 0xa0), ('u64', 0xb0), ('string', 0xb8), ('string', 0xc8),
         ('bool', 0xe0), ('u64', 0xf0), ('u64', 0x100), ('u64', 0x110),
         ('u64', 0x120), ('bool', 0x128), ('raw32', 0x130), ('raw32', 0x134),
         ('bool', 0x138), ('string', 0x140), ('raw32', 0x150), ('raw32', 0x154)]
WIDTH = dict(u32=4, raw32=4, u16=2, u64=8, bool=1, string=16)
TEXTS = ('', 'ASCII', 'Ж界🙂', 'x' * 128)
SPECIALS = ('ff', 'c0af', 'eda080', 'f4908080', '610062', 'efbfbe')
TOOLS = ('login-input-case-contracts.py', 'verify-login-nested-context.py',
         'verify-login-input-context.py', 'verify-login-input-harness.py', 'login-result-string-fixtures.py')


def tools():
    return {str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in TOOLS}


def case_count(family):
    if not isinstance(family, str) or family not in COUNTS:
        raise ValueError('Unreviewed portable Login input family')
    return COUNTS[family]


def verifier(family):
    case_count(family)
    return 'verify-login-nested-context' if family == 'login-nested' else 'verify-login-input-context'


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _body_size(text):
    return sum(2 + len(text.encode('utf-8')) if kind == 'string' else WIDTH[kind] for kind, _ in ORDER)


def _utf16(text):
    return (text.encode('utf-16le') + b'\0\0').hex() if text else ''


def _scalars(code, flag):
    result = {}
    for i, (kind, at) in enumerate(ORDER):
        if kind == 'string':
            continue
        value = flag if kind == 'bool' else code if at == 0x10 else (
            (0xfedcba9876543210 + i) & ((1 << (8 * WIDTH[kind])) - 1))
        if kind == 'bool':
            value = int(value != 0)
        result[hex(at)] = value.to_bytes(WIDTH[kind], 'little').hex()
    return result


def _common(size, consumed, returned, text):
    return dict(size=size, consumed=consumed, returned=returned,
                first_string_utf16=_utf16(text), guards=True, constructor_guards=True, abi_guards=True)


def _full(text, code, flag, poison, trailing=0):
    size = _body_size(text)
    return dict(_common(size + trailing, size, 1, text), text=text, code=code, flag=flag,
                poison=poison, scalar_values=_scalars(code, flag))


def expected_rows(family):
    """Pure reviewed oracle for report shape, dimensions and fixed observations.

    These rows do not constitute native evidence. The verifier obtains all
    values from the source-bound execution and checks memory/ABI guards first.
    """
    case_count(family)
    if family == 'login-nested':
        return dict(cases=[dict(poison=p, flag=f, truthy=t, fail_at=at,
            operations=len(ORDER) if at is None else at + 1, returned=int(at is None),
            guards=True, constructor_guards=True, abi_guards=True)
            for p, f, t, at in itertools.product((0x55, 0xaa), (0, 255), (1, 0x101), [None] + list(range(len(ORDER))))])
    truncated = []
    for text in ('', 'x', '🙂'):
        for size in range(_body_size(text)):
            # The reviewed raw primitive consumes the available prefix before
            # failing. An incomplete string is never assigned to the FString.
            first = text if size >= 6 + len(text.encode('utf-8')) else ''
            truncated.append(dict(_common(size, size, 0, first), text=text, code=0, flag=255, poison=0x55))
    special = []
    for value in SPECIALS:
        size = _body_size('') + len(bytes.fromhex(value))
        special.append(dict(_common(size, size, 1, 'a' if value == '610062' else '?'),
                            input_hex=value, code=0, flag=0, poison=0x55))
    return dict(cases=[_full(*values) for values in itertools.product(TEXTS, (0, 16, 58, 0xffffffff),
                          (0, 1, 2, 255), (0x55, 0xaa))],
                truncated=truncated, trailing=_full('', 0, 0, 0xaa, trailing=5),
                boundaries=[_full('x' * size, 0, 255, 0xaa) for size in (15, 16, 127, 128)], special=special)


def validate_report(family, report):
    """Reject missing/duplicate cases, weak numeric types and changed outcomes.

    Full source/context/export/proof admission belongs to the adapter. This
    contract checks the complete bounded report rather than only case counts.
    """
    count = case_count(family)
    if not isinstance(report, dict) or type(report.get('schema')) is not int or report['schema'] != 1:
        raise ValueError('Portable Login input report schema differs')
    if report.get('method') != 'bounded_native':
        raise ValueError('Portable Login input report method differs')
    for flag in ('network_used', 'profile_activated', 'runtime_activated'):
        if report.get(flag) is not False:
            raise ValueError('Portable Login input activation/network flag differs')
    if _canonical(report.get('operations')) != _canonical(ORDER):
        raise ValueError('Portable Login input field order differs')
    native = family == 'login-strings-buffer'
    for flag, value in (('native_nested_used', True), ('native_scalars_used', native),
                        ('native_strings', native), ('native_buffer_construction', native)):
        if report.get(flag) is not value:
            raise ValueError('Portable Login input native scope differs')
    rows = expected_rows(family)
    try:
        for name, expected in rows.items():
            actual = report.get(name)
            if _canonical(actual) != _canonical(expected):
                raise ValueError('Portable Login input matrix/outcome differs: ' + name)
        if sum(len(value) if isinstance(value, list) else 1 for value in rows.values()) != count:
            raise ValueError('Reviewed portable Login input matrix definition changed')
    except (TypeError, OverflowError) as error:
        raise ValueError('Portable Login input report values invalid') from error
    if family == 'login-nested' and any(report.get(name) for name in ('truncated', 'trailing', 'boundaries', 'special')):
        raise ValueError('Nested Login report unexpectedly claims native input scenarios')
