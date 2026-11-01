"""Bounded, immutable diagnostics for a failed native integration projection.

Diagnostics retain actual and expected fixture observations for one failing row.
They never change admission, expected outcomes, guards or successful evidence.
"""
import copy
import json

FAMILY = 'login-state-flow'
SCOPE = 'bounded_native_login_state_flow'


def _type(value):
    if value is None: return 'null'
    return {dict: 'object', list: 'array', str: 'string', bool: 'boolean', int: 'integer', float: 'number'}.get(type(value), type(value).__name__)


def _preview(value, limit):
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    return text if len(text) <= limit else text[:limit - 1] + '\u2026'


def differences(actual, wanted, *, limit=16, max_depth=32, value_chars=240):
    """Return strict JSON-type/value differences without an unbounded error line."""
    if (type(limit) is not int or not 1 <= limit <= 64 or type(max_depth) is not int or not 1 <= max_depth <= 64
            or type(value_chars) is not int or not 16 <= value_chars <= 2048):
        raise ValueError('State-flow diagnostic bounds differ')
    # Validate full payload serialization once; malformed diagnostic input is not
    # silently converted to repr or mistaken for successful native evidence.
    json.dumps([actual, wanted], ensure_ascii=False, allow_nan=False)
    result = []

    def add(path, observed, expected, reason):
        result.append(dict(path=path, reason=reason, actual_type=_type(observed), wanted_type=_type(expected),
            actual=_preview(observed, value_chars), wanted=_preview(expected, value_chars)))

    def walk(observed, expected, path, depth):
        if len(result) >= limit: return
        if type(observed) is not type(expected):
            add(path, observed, expected, 'type'); return
        if depth >= max_depth:
            if json.dumps(observed, sort_keys=True, allow_nan=False) != json.dumps(expected, sort_keys=True, allow_nan=False):
                add(path, observed, expected, 'depth_limit')
            return
        if isinstance(observed, dict):
            for key in sorted(set(observed) | set(expected)):
                if len(result) >= limit: break
                child = path + '[' + json.dumps(key, ensure_ascii=False) + ']'
                if key not in observed:
                    add(child, None, expected[key], 'missing_actual')
                elif key not in expected:
                    add(child, observed[key], None, 'unexpected_actual')
                else:
                    walk(observed[key], expected[key], child, depth + 1)
        elif isinstance(observed, list):
            if len(observed) != len(expected):
                add(path + '.length', len(observed), len(expected), 'length')
            for index, (item, expected_item) in enumerate(zip(observed, expected)):
                if len(result) >= limit: break
                walk(item, expected_item, path + '[' + str(index) + ']', depth + 1)
        elif observed != expected:
            add(path, observed, expected, 'value')

    walk(actual, wanted, '$', 0)
    return result


def failure_payload(actual, wanted, spec, *, source_sha256, context_identity=None, tools=None):
    import re
    if not isinstance(source_sha256, str) or not re.fullmatch('[0-9a-f]{64}', source_sha256):
        raise ValueError('State-flow diagnostic requires exact source SHA')
    if (context_identity is None) != (tools is None):
        raise ValueError('State-flow diagnostic production identity is incomplete')
    if context_identity is not None:
        if (not isinstance(context_identity, dict) or set(context_identity) != {'family', 'scope', 'context_canonical_sha256', 'transfer_proof'}
                or context_identity['family'] != FAMILY or context_identity['scope'] != SCOPE
                or not isinstance(context_identity['context_canonical_sha256'], str)
                or not re.fullmatch('[0-9a-f]{64}', context_identity['context_canonical_sha256'])
                or not isinstance(context_identity['transfer_proof'], dict)
                or set(context_identity['transfer_proof']) != {'path', 'sha256'}
                or not isinstance(context_identity['transfer_proof']['path'], str)
                or not context_identity['transfer_proof']['path'].strip()
                or not isinstance(context_identity['transfer_proof']['sha256'], str)
                or not re.fullmatch('[0-9a-f]{64}', context_identity['transfer_proof']['sha256'])
                or not isinstance(tools, dict) or not tools
                or any(not isinstance(path, str) or not path or not isinstance(sha, str)
                    or not re.fullmatch('[0-9a-f]{64}', sha) for path, sha in tools.items())):
            raise ValueError('State-flow diagnostic production identity differs')
    paths = differences(actual, wanted)
    if not paths:
        raise ValueError('State-flow diagnostic requires an actual mismatch')
    return dict(schema=1, family=FAMILY, scope=SCOPE, method='bounded_native_failure_diagnostic',
        source_sha256=source_sha256, label=spec.get('label'), spec=copy.deepcopy(spec),
        actual=copy.deepcopy(actual), wanted=copy.deepcopy(wanted), differences=paths,
        context_identity=copy.deepcopy(context_identity), tools=copy.deepcopy(tools),
        differences_limited_to=16, network_used=False, profile_activated=False, runtime_activated=False,
        accepted=False)


def raise_mismatch(actual, wanted, spec, *, source_sha256, root, snapshot, context_identity=None, tools=None):
    payload = failure_payload(actual, wanted, spec, source_sha256=source_sha256,
        context_identity=context_identity, tools=tools)
    pointer = snapshot(root, 'native-login-state-flow-failures', payload)
    paths = ', '.join(item['path'] + ':' + item['reason'] for item in payload['differences'][:4])
    raise ValueError('State-flow observed scenario differs: ' + str(spec.get('label'))
        + '; diagnostic=' + str(pointer) + '; differences=' + paths)
