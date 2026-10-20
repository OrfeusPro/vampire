"""One lobby login with an explicit choice of fresh joined-country context."""
import argparse
from dataclasses import replace
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
from vampir_core.nid_metadata import encode_nid_metadata_with_device_key


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def run(email, *, selected_profile, manifest_path, socks_port, context, password='', read_server_list=False, server_policy_byte=None,
        auth_flow='nid', _progress=None, _consume_auth=None, _select_server=None, _use_session=None):
    if auth_flow not in ('nid', 'launcher'): raise ValueError('Unsupported explicit SDK auth flow')
    if _consume_auth is not None and not callable(_consume_auth): raise TypeError('Expected in-memory auth consumer')
    if _select_server is not None and (not callable(_select_server) or not read_server_list):
        raise TypeError('Server selection requires a callback and server list')
    if _use_session is not None and (not callable(_use_session) or _select_server is None):
        raise TypeError('Session consumer requires server selection')
    if context not in ('sdk-without-nid-info','sdk-with-joined-country','sdk-with-partial-metadata'):
        raise ValueError('Explicit source-supported SDK context required')
    if type(read_server_list) is not bool: raise ValueError('Explicit server-list operation required')
    if read_server_list and (type(server_policy_byte) is not int or not 0 <= server_policy_byte <= 255):
        raise ValueError('Explicit raw server-list policy byte required')
    if not read_server_list and server_policy_byte is not None: raise ValueError('Server-list policy without request')
    source = module('lobby_sdk_source', 'game-source-profile.py').load_profile(selected_profile=selected_profile)
    route = SocksRoute(socks_port)
    endpoint = module('lobby_sdk_endpoint', 'probe-lobby-connection.py').selected_endpoint(manifest_path, route=route)
    sdk = module('lobby_sdk_signin', 'run-nid-sdk-sign-in.py')
    binding, sdk_profile, _ = sdk.load_inputs(email, route=route)
    browser = module('lobby_sdk_browser', 'nid-browser.py')
    captured = {}
    def capture(*args, **kwargs):
        if _progress: _progress('nid_browser')
        value = browser.capture_nid_credential(*args, **kwargs)
        captured['provider'] = value
        if _progress: _progress('sdk_sign_in')
        return value
    data = sdk.run(email, timeout=180, password=password, socks_port=socks_port, _capture=capture,
        auth_flow=auth_flow, _progress=_progress)
    password = None
    provider = captured.pop('provider')
    country = ''
    if context in ('sdk-with-joined-country','sdk-with-partial-metadata'):
        country = data.joined_country_code
        if (type(country) is not str or len(country)!=2 or any(not 'A'<=c<='Z' for c in country)
                or country!=provider.joined_country_code):
            raise ValueError('Fresh SDK and NID joined countries must agree')
    metadata = ''
    if context == 'sdk-with-partial-metadata':
        # Only independently sourced fields; no TID/IP/hardware values invented
        # and no old session metadata loaded. This is explicitly incomplete.
        values = dict(I_GameCode=sdk_profile['game_code'],I_GameVersion=source.app_version,
            I_PID=data.player_id,I_JoinedCountryCode=country,I_NMDeviceKey=binding.nm_device_key)
        if any(type(value) is not str or not value for value in values.values()):
            raise ValueError('Current metadata sources are incomplete')
        metadata = encode_nid_metadata_with_device_key(values,
            device_key=binding.device_key,user_info_available=True)
    version_tool = module('lobby_sdk_version_inputs', 'probe-lobby-version.py')
    version = version_tool.prepare_version(app_version=source.app_version,
        windows_version=observe_windows_version(), computer_name=version_tool.observe_computer_name(),
        nm_device_key=binding.nm_device_key)
    # Metadata is absent or an explicitly selected subset of current sources.
    # Selection replaces the template's server 0 before any lobby Login is sent.
    login = LobbyLoginPayload((data.player_id, data.access_token, binding.nm_device_key, country, provider.netmarble_id, metadata),
        (2, 0, 0, 0), 7)
    # Source path uses NMDeviceKey when initial global player text is empty.
    request = (LobbyServerListPayload((binding.nm_device_key, provider.netmarble_id), 2, (server_policy_byte, 0))
        if read_server_list else None)
    netmarble_id = provider.netmarble_id
    provider = None
    if _progress: _progress('lobby_connect')
    connection = route.connect(*endpoint, timeout=10)
    try:
        if _progress: _progress('lobby_exchange')
        def selected_login(response):
            server_id = _select_server(response, data.joined_country_code)
            if type(server_id) is not int or not 1 <= server_id <= 0xffffffff:
                raise ValueError('Expected selected nonzero server ID')
            if _progress: _progress('selected_lobby_login')
            return replace(login, integers=(login.integers[0], login.integers[1], server_id, login.integers[3]))
        def use_session(completed):
            completed.summary.update(context=context, sdk_response_accepted=True, lobby_open_during_game=True, sdk_auth_flow=auth_flow,
                joined_country_present=bool(country),metadata_bytes=len(metadata.encode('utf-8')))
            if _consume_auth:
                extra={'nid_metadata':metadata} if metadata else {}
                _consume_auth(binding=binding, sdk_data=data, netmarble_id=netmarble_id,**extra)
            _use_session(completed)
        result = exchange_lobby_login(connection, version, login, timeout=15, server_list=request,
            select_login=selected_login if _select_server is not None else None,
            on_selected_login=use_session if _use_session is not None else None)
        result.summary.update(context=context, sdk_response_accepted=True, sdk_auth_flow=auth_flow,
            joined_country_present=bool(country),metadata_bytes=len(metadata.encode('utf-8')))
        if _use_session is None and _consume_auth and result.response is not None and result.response.result_code == 0:
            extra={'nid_metadata':metadata} if metadata else {}
            _consume_auth(binding=binding, sdk_data=data, netmarble_id=netmarble_id,**extra)
        return result
    finally: connection.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--email', required=True)
    parser.add_argument('--profile', choices=['recovered-base'], required=True)
    parser.add_argument('--context', choices=['sdk-without-nid-info','sdk-with-joined-country','sdk-with-partial-metadata'], required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--socks-port', type=int, required=True)
    parser.add_argument('--password-stdin', action='store_true')
    parser.add_argument('--read-server-list', action='store_true')
    parser.add_argument('--server-policy-byte', type=int)
    parser.add_argument('--auth-flow', choices=['nid', 'launcher'], default='nid')
    args = parser.parse_args()
    try:
        password = sys.stdin.readline(258).rstrip('\r\n') if args.password_stdin else ''
        if args.password_stdin and (not password or len(password) > 256): raise ValueError('Invalid password input')
        result = run(args.email, selected_profile=args.profile, manifest_path=args.manifest,
            socks_port=args.socks_port, context=args.context, password=password,
            read_server_list=args.read_server_list, server_policy_byte=args.server_policy_byte, auth_flow=args.auth_flow)
        password = None
        print(json.dumps(result.summary))
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        summary = dict(status='lobby_sdk_login_not_completed', error_type=type(error).__name__)
        if type(getattr(error, 'status', None)) is int: summary['http_status'] = error.status
        if type(getattr(error, 'sdk_code', None)) is int: summary['sdk_error_code'] = error.sdk_code
        print(json.dumps(summary))
        sys.exit(2)
