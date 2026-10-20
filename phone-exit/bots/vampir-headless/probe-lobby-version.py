"""Source-profile LobbyVersion only; account/device values never printed."""
import argparse
import ctypes
from ctypes import wintypes
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
sys.path.insert(0, str(HERE.parents[1] / '.tools/vampir-python-runtime'))
from vampir_core.device_registry import DeviceRegistry
from vampir_core.windows_device_identity import observe_windows_device_identity
from vampir_core.windows_version import observe_windows_version
from vampir_core.lobby_packets import LobbyVersionPayload
from vampir_core.lobby_version_probe import exchange_lobby_version
from vampir_core.socks_route import SocksRoute


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def observe_computer_name():
    if sys.platform != 'win32': raise RuntimeError('Windows computer name required')
    api = ctypes.WinDLL('kernel32', use_last_error=True).GetComputerNameW
    api.argtypes, api.restype = [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL
    buffer = ctypes.create_unicode_buffer(256)
    size = wintypes.DWORD(256)
    if not api(buffer, ctypes.byref(size)) or not 0 < size.value < 256:
        raise RuntimeError('Computer name unavailable')
    return buffer[:size.value]


def prepare_version(*, app_version, windows_version, computer_name, nm_device_key):
    if windows_version is None: raise ValueError('Observed Windows version required')
    for value in (app_version, computer_name, nm_device_key):
        if type(value) is not str or not value: raise ValueError('Explicit observed lobby inputs required')
    # Normal Windows branch in 0x1467aae20 and ctor 0x145745330.
    return LobbyVersionPayload((app_version, windows_version.suffix(), computer_name, nm_device_key, ''), (0, 3), 1)


def run(email, *, selected_profile, manifest_path, socks_port):
    source = module('lobby_version_profile', 'game-source-profile.py').load_profile(selected_profile=selected_profile)
    route = SocksRoute(socks_port)
    endpoint = module('lobby_version_endpoint', 'probe-lobby-connection.py').selected_endpoint(manifest_path, route=route)
    binding = DeviceRegistry(HERE / '.local/accounts.sqlite3').get(email)
    if (binding.kind != 'real' or not binding.identity_recorded or not binding.nid_identity_recorded or binding.confirmation == 'required'):
        raise ValueError('Observed device/account profile required')
    identity = observe_windows_device_identity(store_name='Netmarble', game_code='thered')
    if (binding.nm_device_key, binding.device_key, binding.nid_device_key) != (
            identity.nm_device_key, identity.device_key, identity.nid_device_key):
        raise ValueError('Device identity changed')
    payload = prepare_version(app_version=source.app_version, windows_version=observe_windows_version(),
        computer_name=observe_computer_name(), nm_device_key=binding.nm_device_key)
    connection = route.connect(*endpoint, timeout=10)
    try: return exchange_lobby_version(connection, payload, timeout=10)
    finally: connection.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--email', required=True)
    parser.add_argument('--profile', choices=['recovered-base'], required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--socks-port', type=int, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.email, selected_profile=args.profile, manifest_path=args.manifest, socks_port=args.socks_port)))
    except (OSError, ValueError, RuntimeError, KeyError):
        print(json.dumps(dict(status='lobby_version_probe_not_completed', login_sent=False)))
        sys.exit(2)
