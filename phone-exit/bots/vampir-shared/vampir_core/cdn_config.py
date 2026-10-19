"""Offline CDN JSON/fallback decoding and the verified SDK environment field.

Evidence: HEADLESS-CDN-JSON-FLOW.md / HEADLESS-CDN-CONFIG.md. Python JSON
syntax/type/Unicode/resource rules are explicit local policy. Native branch
replays use parser/ReadJson/validation return fixtures, not a whole native
parser. Decoding a document does not apply or fully validate game settings.
"""
import json
import math

from .cdn_response import MAX_BODY_BYTES, decode_cdn_body_text
from .sdk_config import select_game_sdk_zone

MAX_JSON_DEPTH = 64
MAX_JSON_ITEMS = 65536


class _NotJsonObject(ValueError):
    pass


def _preflight(text):
    depth, items = 0, 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '{[':
            depth += 1
            items += 1
        elif char in '}]':
            depth -= 1
        elif char == ',':
            items += 1
        if depth > MAX_JSON_DEPTH or items > MAX_JSON_ITEMS:
            raise ValueError('CDN JSON exceeds local structural budget')


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate CDN JSON field')
        result[key] = value
    return result


def _number(text, converter):
    if len(text) > 128:
        raise ValueError('CDN JSON number exceeds local budget')
    result = converter(text)
    if isinstance(result, float) and not math.isfinite(result):
        raise ValueError('Nonfinite CDN JSON number')
    return result


def _constant(_):
    raise ValueError('Non-JSON CDN constant')


def _load_object(text, *, allow_nul_strings=False):
    _preflight(text)
    try:
        root = json.loads(text, object_pairs_hook=_object, parse_constant=_constant,
                          parse_int=lambda s: _number(s, int), parse_float=lambda s: _number(s, float))
    except json.JSONDecodeError:
        raise _NotJsonObject('Invalid CDN JSON syntax') from None
    except RecursionError:
        raise ValueError('CDN JSON exceeds local nesting budget') from None
    if not isinstance(root, dict):
        raise _NotJsonObject('CDN JSON root must be an object')
    pending, count = [root], 0
    while pending:
        value = pending.pop()
        count += 1
        if count > MAX_JSON_ITEMS:
            raise ValueError('CDN JSON exceeds local item budget')
        if isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            try:
                value.encode('utf-8', 'strict')
            except UnicodeEncodeError:
                raise ValueError('Invalid Unicode in CDN JSON') from None
            if '\0' in value and not allow_nul_strings:
                raise ValueError('NUL in CDN JSON string')
    return root


def decode_cdn_config_document(body: bytes) -> dict:
    """Try plain Unicode JSON object, then raw AES fallback on syntax/type failure.

    The supplied body must already be complete. Local duplicate/nonfinite/
    JSON-string Unicode/resource policy failures do not retry crypto.
    Invalid text or JSON syntax/non-object root selects the raw-body fallback.
    Crypto is loaded lazily only on that path. No ReadJson/secondary validation,
    URL trust, readiness decision or config application is performed here.
    """
    if not isinstance(body, bytes) or len(body) > MAX_BODY_BYTES:
        raise ValueError('Invalid CDN document body or local budget exceeded')
    try:
        text = decode_cdn_body_text(body)
    except ValueError:
        text = None
    if text is not None:
        try:
            return _load_object(text)
        except _NotJsonObject:
            pass
    from .cdn_fallback import decrypt_cdn_fallback
    try:
        text = decrypt_cdn_fallback(body).decode('utf-8', 'strict')
        if '\0' in text:
            raise ValueError('NUL in decrypted CDN document')
        return _load_object(text)
    except ValueError:
        raise ValueError('Invalid CDN configuration document') from None


def read_cdn_sdk_environment(document: dict) -> str:
    """Read exact local NetmarbleS/Zone string, never default missing to dev.

    Native section/key callsites and destination are verified; key matching and
    JSON value conversion inside native helpers remain unresolved. Exact names,
    object/string types and strict Unicode are local policy. The existing SDK
    selector enforces the 128 UTF-16-unit/NUL budget; it does not acquire a mode.
    """
    if not isinstance(document, dict) or not isinstance(document.get('NetmarbleS'), dict):
        raise ValueError('Missing or invalid CDN SDK section')
    environment = document['NetmarbleS'].get('Zone')
    if not isinstance(environment, str):
        raise ValueError('Missing or invalid CDN SDK environment')
    try:
        environment.encode('utf-8', 'strict')
    except UnicodeEncodeError:
        raise ValueError('Invalid CDN SDK environment encoding') from None
    select_game_sdk_zone(environment)
    return environment
