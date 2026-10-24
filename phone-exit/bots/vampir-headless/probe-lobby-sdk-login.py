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
from vampir_core.direct_route import connect_direct
from vampir_core.windows_version import observe_windows_version
from vampir_core.nid_metadata import encode_nid_metadata_with_device_key
from vampir_core.metadata_tid import resolve_metadata_tid, SOURCE_SHA256 as METADATA_TID_SOURCE_SHA256
from vampir_core.gmc2_context import SdkInputs


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def run(email, *, selected_profile, manifest_path, socks_port, context, password='', read_server_list=False, server_policy_byte=None,
        auth_flow='nid', lobby_region=None, auth_timeout=180, _progress=None, _consume_auth=None, _select_server=None, _use_session=None, device_settings=None):
    if type(auth_timeout) is not int or not 1 <= auth_timeout <= 900:
        raise ValueError('Bounded authentication timeout required')
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
    from vampir_core.bot_device_settings import validate, apply_system, metadata_values
    device_settings = validate(device_settings)
    source = module('lobby_sdk_source', 'game-source-profile.py').load_profile(selected_profile=selected_profile)
    route = SocksRoute(socks_port) if socks_port is not None else None
    endpoint = module('lobby_sdk_endpoint', 'probe-lobby-connection.py').selected_endpoint(manifest_path,
        route=route, expected_config_snapshot_sha256=source.source_snapshot_sha256, lobby_region=lobby_region)
    sdk = module('lobby_sdk_signin', 'run-nid-sdk-sign-in.py')
    prepared = sdk.load_inputs(email, route=route, selected_profile=selected_profile, **({'device_settings': device_settings} if device_settings else {}))
    binding, sdk_profile, _ = prepared
    if selected_profile == 'recovered-release' and not isinstance(prepared, SdkInputs):
        raise ValueError('Current SDK profile requires a fresh GMC2 context')
    browser = module('lobby_sdk_browser', 'nid-browser.py')
    captured = {}
    def capture(*args, **kwargs):
        if _progress: _progress('nid_browser')
        value = browser.capture_nid_credential(*args, **kwargs)
        captured['provider'] = value
        if _progress: _progress('sdk_sign_in')
        return value
    extra = {'_prepared_inputs': prepared} if isinstance(prepared, SdkInputs) else {}
    if device_settings: extra['device_settings'] = device_settings
    data = sdk.run(email, timeout=auth_timeout, password=password, socks_port=socks_port, _capture=capture,
        auth_flow=auth_flow, selected_profile=selected_profile, _progress=_progress, **extra)
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
        # Only sourced fields; no captured session/IP/hardware values replayed.
        # TID is persistent bot-owned state under the verified generation policy.
        values = dict(I_GameCode=sdk_profile['game_code'],I_GameVersion=source.app_version,
            I_PID=data.player_id,I_JoinedCountryCode=country,I_NMDeviceKey=binding.nm_device_key)
        if getattr(source, 'source_exe_sha256', '') == METADATA_TID_SOURCE_SHA256:
            if not isinstance(prepared, SdkInputs) or prepared.source_sha256 != source.source_exe_sha256:
                raise ValueError('Current metadata requires matching fresh GMC2 source')
            prepared.check_usage(email=email, selected_profile=selected_profile, route=route)
            # Bot-owned geo state starts empty for each run; no game cache read.
            values.update(prepared.geo.metadata(previous_country=''))
            values['I_TID'] = resolve_metadata_tid(HERE / '.local/metadata.sqlite3',
                nm_device_key=binding.nm_device_key, source_sha256=source.source_exe_sha256)
        if any(type(value) is not str or not value for value in values.values()):
            raise ValueError('Current metadata sources are incomplete')
        values.update(metadata_values(device_settings))
        metadata = encode_nid_metadata_with_device_key(values,
            device_key=binding.device_key,user_info_available=True)
    version_tool = module('lobby_sdk_version_inputs', 'probe-lobby-version.py')
    version = version_tool.prepare_version(app_version=source.app_version,
        windows_version=apply_system(None, observe_windows_version(), device_settings)[1], computer_name=version_tool.observe_computer_name(),
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
    connection = (route.connect if route else connect_direct)(*endpoint, timeout=10)
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
    parser.add_argument('--profile', choices=['recovered-base', 'recovered-release'], required=True)
    parser.add_argument('--context', choices=['sdk-without-nid-info','sdk-with-joined-country','sdk-with-partial-metadata'], required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    route_choice = parser.add_mutually_exclusive_group(required=True)
    route_choice.add_argument('--socks-port', type=int)
    route_choice.add_argument('--direct', action='store_true', help='Use the ordinary route for browser, SDK and lobby')
    parser.add_argument('--password-stdin', action='store_true')
    parser.add_argument('--read-server-list', action='store_true')
    parser.add_argument('--server-policy-byte', type=int)
    parser.add_argument('--auth-flow', choices=['nid', 'launcher'], default='nid')
    parser.add_argument('--lobby-region', choices=['SG', 'NA', 'EU'], help='Explicit current CDN regional lobby')
    parser.add_argument('--auth-timeout', type=int, default=180, help='Bounded time for the official sign-in window, at most 900 seconds')
    args = parser.parse_args()
    try:
        password = sys.stdin.readline(258).rstrip('\r\n') if args.password_stdin else ''
        if args.password_stdin and (not password or len(password) > 256): raise ValueError('Invalid password input')
        result = run(args.email, selected_profile=args.profile, manifest_path=args.manifest,
            socks_port=args.socks_port, context=args.context, password=password,
            read_server_list=args.read_server_list, server_policy_byte=args.server_policy_byte, auth_flow=args.auth_flow,
            lobby_region=args.lobby_region, auth_timeout=args.auth_timeout)
        password = None
        print(json.dumps(result.summary))
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        summary = dict(status='lobby_sdk_login_not_completed', error_type=type(error).__name__)
        if type(getattr(error, 'status', None)) is int: summary['http_status'] = error.status
        if type(getattr(error, 'sdk_code', None)) is int: summary['sdk_error_code'] = error.sdk_code
        print(json.dumps(summary))
        sys.exit(2)
