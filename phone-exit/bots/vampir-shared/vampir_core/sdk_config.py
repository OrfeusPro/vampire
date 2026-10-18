"""Offline SDK string-map merge/URL getter; no response acquisition or HTTP.

Evidence: HEADLESS-SDK-MAP.md. Values must already be strings, as in the
client's final SDK map; conversion of arbitrary JSON values is unresolved.
"""
_ASCII_UPPER = str.maketrans('abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')


def _fold(key):
    return key.translate(_ASCII_UPPER)


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
