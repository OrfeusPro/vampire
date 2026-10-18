"""Offline SDK string-map merge/URL getter; no response acquisition or HTTP.

Evidence: HEADLESS-SDK-MAP.md / HEADLESS-SDK-PATH.md. Values must be strings, as in the
client's final SDK map; conversion of arbitrary JSON values is unresolved.
"""
_ASCII_UPPER = str.maketrans('abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')


def _fold(key):
    return key.translate(_ASCII_UPPER)


def select_game_sdk_zone(environment: str) -> int:
    """Game override: explicit environment 'real' (ASCII case ignored) -> 2, else 1.

    Does not read or guess the active environment. Local input policy: at most
    128 UTF-16 units, no embedded NUL; native C-string truncation is rejected.
    Evidence: HEADLESS-SDK-SETTINGS.md, actual game comparison/zone-write slice.
    """
    if not isinstance(environment, str) or len(environment) > 128 or '\0' in environment:
        raise ValueError('Invalid explicit game environment')
    if len(environment.encode('utf-16le', 'surrogatepass')) > 256:
        raise ValueError('Game environment exceeds local budget')
    return 2 if _fold(environment) == 'REAL' else 1


def _key(key):
    if not isinstance(key, str) or not key or len(key) > 256 or '\0' in key:
        raise ValueError('Invalid SDK configuration key')
    if len(key.encode('utf-16le', 'surrogatepass')) > 512:
        raise ValueError('SDK configuration key exceeds local budget')
    return _fold(key)


def _checked(values):
    if not isinstance(values, dict) or len(values) > 512:
        raise ValueError('Expected bounded SDK string map')
    index, total = {}, 0
    for key, value in values.items():
        folded = _key(key)
        if folded in index:
            raise ValueError('Ambiguous SDK configuration keys')
        if not isinstance(value, str) or len(value) > 4096 or '\0' in value:
            raise ValueError('Expected bounded SDK string value')
        size = len(value.encode('utf-16le', 'surrogatepass'))
        total += size
        if size > 8192 or total > 65536:
            raise ValueError('SDK string map exceeds local budget')
        index[folded] = (key, value)
    return index


def merge_sdk_string_constants(ordinary: dict, secret: dict) -> dict:
    """Merge already-stringified maps: secret replaces ASCII-equivalent keys.

    Preserve the replacing key's spelling. Reject ambiguous aliases within one
    input map; inputs stay unchanged and no partial result is returned on error.
    """
    merged = _checked(ordinary)
    merged.update(_checked(secret))
    result = dict(merged.values())
    _checked(result)
    return result


def lookup_sdk_url_value(constants: dict, key: str) -> str | None:
    """Return a matching value passing the client's HTTP(S) prefix check.

    ASCII key/prefix comparison ignores case; non-ASCII keys remain exact.
    This is not hostname/URL validation. Missing keys and failed prefixes return
    None. No endpoint, environment, path separator or network request is inferred.
    """
    entry = _checked(constants).get(_key(key))
    if entry is None:
        return None
    value = entry[1]
    return value if _fold(value).startswith(('HTTP://', 'HTTPS://')) else None


def append_sdk_path(base: str, segment: str) -> str:
    """Repeat native path append, preserving existing slashes/backslashes.

    This is string concatenation, not URL parsing. Empty segment adds a trailing
    slash to a nonempty base lacking either separator. Local bound: 4096 UTF-16
    units for each input and result; NUL is rejected.
    """
    for value in (base, segment):
        if not isinstance(value, str) or len(value) > 4096 or '\0' in value:
            raise ValueError('Invalid SDK path argument')
        if len(value.encode('utf-16le', 'surrogatepass')) > 8192:
            raise ValueError('SDK path exceeds local budget')
    if not segment:
        result = base if not base or base.endswith(('/', '\\')) else base+'/'
    elif base and not base.endswith(('/', '\\')) and not segment.startswith('/'):
        result = base+'/'+segment
    else:
        result = base+segment
    if len(result.encode('utf-16le', 'surrogatepass')) > 8192:
        raise ValueError('SDK path result exceeds local budget')
    return result
