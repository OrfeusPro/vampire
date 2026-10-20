"""Read existing Windows SDK identities without generation or registry writes.

Caller supplies the proven SDK store/game context. An observation is not an
account binding, active-cache snapshot or proof of server/device confirmation.
winreg is imported lazily so portable core imports still work on Android.
"""
from dataclasses import dataclass, field

SOURCE_SHA256 = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'


@dataclass(frozen=True, slots=True)
class WindowsDeviceIdentity:
    device_key: str = field(repr=False)
    nid_device_key: str = field(repr=False)
    nm_device_key: str = field(repr=False)
    sdk_registry_path: str
    nm_registry_path: str


def _segment(value):
    if type(value) is not str or not 1 <= len(value) <= 128:
        raise ValueError('Expected explicit SDK registry context')
    if value.strip() != value or any(ord(c) < 32 or c in '\\/' for c in value):
        raise ValueError('Invalid SDK registry path segment')
    return value


def _read(registry, path, name):
    try:
        with registry.OpenKey(registry.HKEY_CURRENT_USER, path, 0, registry.KEY_READ) as key:
            value, kind = registry.QueryValueEx(key, name)
    except OSError:
        raise ValueError('SDK registry identity is unavailable') from None
    if kind != registry.REG_SZ or type(value) is not str or not 1 <= len(value) <= 8192:
        raise ValueError('Unsupported SDK registry identity value')
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Invalid SDK registry identity text')
    # Preserve stored text: native SDK DeviceKey/NID getters accept nonempty
    # strings; NM getter has a separate GUID parser. This reader does not
    # pretend to implement that parser or normalize to Python UUID syntax.
    return value


def _observe(registry, *, store_name, game_code):
    sdk_path = 'Software\\' + _segment(store_name) + '\\' + _segment(game_code)
    nm_path = 'Software\\Netmarble\\NetmarbleSDK'
    locations = ((sdk_path, 'DeviceKey'), (sdk_path, 'DeviceKeyForNetmarbleId'), (nm_path, 'NMDeviceKey'))
    first = tuple(_read(registry, path, name) for path, name in locations)
    again = tuple(_read(registry, path, name) for path, name in locations)
    if first != again:
        raise ValueError('SDK identity changed during observation')
    return WindowsDeviceIdentity(*first, sdk_path, nm_path)


def observe_windows_device_identity(*, store_name, game_code):
    """Observe three existing values, twice, in explicit HKCU locations.

    No creation, fallback, cache mutation, disk persistence or account update.
    Matching reads detect a simple concurrent change, not an atomic registry
    transaction. Caller still establishes active platform/zone and provenance.
    """
    try:
        import winreg
    except ImportError:
        raise RuntimeError('Windows registry identity requires Windows') from None
    return _observe(winreg, store_name=store_name, game_code=game_code)
