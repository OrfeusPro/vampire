"""One SDK-only lobby login, using the proven native no-NID-UserInfo branch."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
sys.path.insert(0, str(HERE.parents[1] / '.tools/vampir-python-runtime'))
from vampir_core.lobby_packets import LobbyLoginPayload, LobbyServerListPayload
from vampir_core.lobby_login_probe import exchange_lobby_login
from vampir_core.socks_route import SocksRoute
from vampir_core.windows_version import observe_windows_version


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def run(email, *, selected_profile, manifest_path, socks_port, context, password='', read_server_list=False, server_policy_byte=None,
        _progress=None):
    if context != 'sdk-without-nid-info': raise ValueError('Explicit source-supported SDK context required')
    if type(read_server_list) is not bool: raise ValueError('Explicit server-list operation required')
    if read_server_list and (type(server_policy_byte) is not int or not 0 <= server_policy_byte <= 255):
        raise ValueError('Explicit raw server-list policy byte required')
    if not read_server_list and server_policy_byte is not None: raise ValueError('Server-list policy without request')
    source = module('lobby_sdk_source', 'game-source-profile.py').load_profile(selected_profile=selected_profile)
    route = SocksRoute(socks_port)
    endpoint = module('lobby_sdk_endpoint', 'probe-lobby-connection.py').selected_endpoint(manifest_path, route=route)
    sdk = module('lobby_sdk_signin', 'run-nid-sdk-sign-in.py')
    binding, _, _ = sdk.load_inputs(email, route=route)
    browser = module('lobby_sdk_browser', 'nid-browser.py')
    captured = {}
    def capture(*args, **kwargs):
        if _progress: _progress('nid_browser')
        value = browser.capture_nid_credential(*args, **kwargs)
        captured['provider'] = value
        if _progress: _progress('sdk_sign_in')
        return value
    data = sdk.run(email, timeout=180, password=password, socks_port=socks_port, _capture=capture)
    password = None
    provider = captured.pop('provider')
    version_tool = module('lobby_sdk_version_inputs', 'probe-lobby-version.py')
    version = version_tool.prepare_version(app_version=source.app_version,
        windows_version=observe_windows_version(), computer_name=version_tool.observe_computer_name(),
        nm_device_key=binding.nm_device_key)
    # Exact native SDK-auth-present / NID-UserInfo-absent branch. Initial kind 0
    # is our explicit local policy; server 0 matches the game peer constructor.
    login = LobbyLoginPayload((data.player_id, data.access_token, binding.nm_device_key, '', provider.netmarble_id, ''),
        (2, 0, 0, 0), 7)
    # Source path uses NMDeviceKey when initial global player text is empty.
    request = (LobbyServerListPayload((binding.nm_device_key, provider.netmarble_id), 2, (server_policy_byte, 0))
        if read_server_list else None)
    provider = None
    if _progress: _progress('lobby_connect')
    connection = route.connect(*endpoint, timeout=10)
    try:
        if _progress: _progress('lobby_exchange')
        result = exchange_lobby_login(connection, version, login, timeout=15, server_list=request)
        result.summary.update(context=context, sdk_response_accepted=True)
        return result
    finally: connection.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--email', required=True)
    parser.add_argument('--profile', choices=['recovered-base'], required=True)
    parser.add_argument('--context', choices=['sdk-without-nid-info'], required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--socks-port', type=int, required=True)
    parser.add_argument('--password-stdin', action='store_true')
    parser.add_argument('--read-server-list', action='store_true')
    parser.add_argument('--server-policy-byte', type=int)
    args = parser.parse_args()
    try:
        password = sys.stdin.readline(258).rstrip('\r\n') if args.password_stdin else ''
        if args.password_stdin and (not password or len(password) > 256): raise ValueError('Invalid password input')
        result = run(args.email, selected_profile=args.profile, manifest_path=args.manifest,
            socks_port=args.socks_port, context=args.context, password=password,
            read_server_list=args.read_server_list, server_policy_byte=args.server_policy_byte)
        password = None
        print(json.dumps(result.summary))
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        summary = dict(status='lobby_sdk_login_not_completed', error_type=type(error).__name__)
        if type(getattr(error, 'status', None)) is int: summary['http_status'] = error.status
        if type(getattr(error, 'sdk_code', None)) is int: summary['sdk_error_code'] = error.sdk_code
        print(json.dumps(summary))
        sys.exit(2)
