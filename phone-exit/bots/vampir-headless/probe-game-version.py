"""Diagnostic Version request to CDN lobby; its game-protocol role is unproven."""
import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
sys.path.insert(0, str(HERE.parents[1] / '.tools/vampir-python-runtime'))
from vampir_core.device_registry import DeviceRegistry
from vampir_core.windows_device_identity import observe_windows_device_identity
from vampir_core.version_packet import VersionPayload
from vampir_core.version_inputs import bind_windows_version_inputs
from vampir_core.version_probe import exchange_version
from vampir_core.socks_route import SocksRoute

COMPILED_TAG = 'AC7F34E3AFA91ED417BE86CD45BF18C8'


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def prepare_version(*, app_version, nm_device_key, local_address, cpu, windows_version):
    address = str(ipaddress.IPv4Address(local_address))
    if type(nm_device_key) is not str or not nm_device_key: raise ValueError('Observed NM device key required')
    if type(app_version) is not str or not app_version: raise ValueError('Explicit AppVersion required')
    # Covered normal Windows connected path: ctor zeros, callback assignments,
    # compiled tag pointer / raw DWORD1, raw DWORD207; see source evidence.
    payload = VersionPayload((app_version, '', '', nm_device_key, address, '', '', '', '', COMPILED_TAG), (0, 207, 1))
    return bind_windows_version_inputs(payload, cpu=cpu, windows_version=windows_version)


def run(email, *, selected_profile, manifest_path, socks_port, diagnostic_cdn_lobby=False):
    if diagnostic_cdn_lobby is not True:
        raise ValueError('CDN lobby is not a verified game endpoint; explicit diagnostic mode required')
    profile_tool = module('version_game_source', 'game-source-profile.py')
    profile = profile_tool.load_profile(selected_profile=selected_profile)
    lobby = module('version_lobby_source', 'probe-lobby-connection.py')
    route = SocksRoute(socks_port)
    endpoint = lobby.selected_endpoint(manifest_path, route=route)
    binding = DeviceRegistry(HERE / '.local/accounts.sqlite3').get(email)
    if (binding.kind != 'real' or not binding.identity_recorded or not binding.nid_identity_recorded or
            binding.confirmation == 'required'):
        raise ValueError('Observed account/device profile is not ready')
    identity = observe_windows_device_identity(store_name='Netmarble', game_code='thered')
    if (binding.nm_device_key, binding.device_key, binding.nid_device_key) != (
            identity.nm_device_key, identity.device_key, identity.nid_device_key):
        raise ValueError('Observed identity differs from registered device')
    inputs = module('version_windows_inputs', 'windows-system-inputs.py')
    cpu, version = inputs.observe_inputs()
    connection = route.connect(*endpoint, timeout=10)
    try:
        payload = prepare_version(app_version=profile.app_version, nm_device_key=binding.nm_device_key,
            local_address=connection.getsockname()[0], cpu=cpu, windows_version=version)
        result = exchange_version(connection, payload, timeout=10)
        result.update(target_role='cdn_lobby', game_endpoint_verified=False)
        return result
    finally:
        connection.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--email', required=True)
    parser.add_argument('--profile', choices=['recovered-base'], required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--socks-port', type=int, required=True)
    parser.add_argument('--diagnostic-cdn-lobby', action='store_true', required=True,
        help='Explicit diagnostic only: CDN lobby is not a verified game endpoint')
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.email, selected_profile=args.profile,
            manifest_path=args.manifest, socks_port=args.socks_port,
            diagnostic_cdn_lobby=args.diagnostic_cdn_lobby)))
    except (OSError, ValueError, RuntimeError, KeyError):
        print(json.dumps(dict(status='version_probe_not_completed', login_sent=False)))
        sys.exit(2)
