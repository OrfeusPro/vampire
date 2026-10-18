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


def select_cdn_config_base(*, prefix: str, normal: str, qa: str) -> str:
    """Select explicit CDN base by substring 'real', ignoring ASCII case.

    Different from select_game_sdk_zone's exact equality. Both base values must
    be supplied; no URL validation, defaults, acquisition or network IO. Local
    budgets: prefix128/base4096 UTF-16 units each, no embedded NUL.
    Evidence: HEADLESS-CDN-SELECTION.md.
    """
    for value, limit in [(prefix, 128), (normal, 4096), (qa, 4096)]:
        if not isinstance(value, str) or len(value) > limit or '\0' in value:
            raise ValueError('Invalid explicit CDN configuration value')
        if len(value.encode('utf-16le', 'surrogatepass')) > limit * 2:
            raise ValueError('CDN configuration value exceeds local budget')
    return normal if 'REAL' in _fold(prefix) else qa


def assemble_cdn_config_url_ascii(*, base: str, platform: str, prefix: str, version_fragment: str) -> str:
    """Repeat native URL tail with explicitly preprocessed printable ASCII parts.

    No separator is inserted between base and platform. Other separators and
    query/fragment characters are preserved. Does not acquire configuration,
    convert AppVersion, infer platform, validate URL or send HTTP. Local budget:
    4096 bytes per part and result. Evidence: HEADLESS-CDN-URL.md.
    """
    for value in (base, platform, prefix, version_fragment):
        if not isinstance(value, str) or len(value) > 4096 or any(not 32 <= ord(c) <= 126 for c in value):
            raise ValueError('Expected bounded printable ASCII CDN fragment')
    result = base + platform + '/' + prefix + '/' + version_fragment + '/config.json'
    if len(result) > 4096:
        raise ValueError('Assembled CDN URL exceeds local budget')
    return result


def prepare_cdn_version_ascii(app_version: str) -> str:
    """Native CDN preprocessing replaces every '.' with '_'; no version inference.

    Explicit printable ASCII only, at most 4096 bytes (local policy). This is not
    semantic version parsing. Evidence: HEADLESS-CDN-PREPARATION.md.
    """
    if not isinstance(app_version, str) or len(app_version) > 4096 or any(not 32 <= ord(c) <= 126 for c in app_version):
        raise ValueError('Expected bounded printable ASCII AppVersion')
    return app_version.replace('.', '_')


def select_cdn_platform_label(platform_code: int) -> str:
    """Repeat CDN caller's int32 mapping; code must be explicitly supplied.

    Compiled Windows platform initialization returns 2, mapped to window. Other
    code paths are verified with synthetic return tags, not Android/iOS builds.
    """
    if type(platform_code) is not int or not -(1 << 31) <= platform_code < (1 << 31):
        raise ValueError('Expected explicit int32 platform code')
    return 'ios' if platform_code == 1 else 'window' if platform_code == 2 else 'android'


def prepare_cdn_config_url_ascii(*, normal: str, qa: str, prefix: str, app_version: str, platform_code: int) -> str:
    """Compose proven offline CDN stages with explicit settings; no HTTP or defaults.

    Neither this function nor the individual stages obtains current Game config,
    validates the final URL or establishes server/platform compatibility.
    """
    return assemble_cdn_config_url_ascii(
        base=select_cdn_config_base(prefix=prefix, normal=normal, qa=qa),
        platform=select_cdn_platform_label(platform_code), prefix=prefix,
        version_fragment=prepare_cdn_version_ascii(app_version))


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
