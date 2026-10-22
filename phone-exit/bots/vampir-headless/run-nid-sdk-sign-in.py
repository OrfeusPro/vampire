"""One explicit NID window -> SDK sign-in attempt. Never print live credentials."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
sys.path.insert(0, str(HERE.parents[1] / '.tools/vampir-python-runtime'))
from vampir_core.device_registry import DeviceRegistry
from vampir_core.windows_device_identity import observe_windows_device_identity
from vampir_core.gmc2_response import decode_gmc2_configuration
from vampir_core.gmc2_http import fetch as fetch_gmc2
from vampir_core.gmc2_context import SdkInputs, decode_gmc2_geo
from vampir_core.nid_web_context import prepare_nid_sign_in_context
from vampir_core.nid_web_url import bind_nid_web_url
from vampir_core.nid_sdk_credential import build_nid_sdk_credential
from vampir_core.sdk_sign_in import plan_nid_sdk_sign_in, plan_nid_sdk_sign_up
from vampir_core.sdk_launcher_auth import plan_nid_launcher_token, plan_launcher_sign_in
from vampir_core.sdk_sign_in_http import (execute_sdk_sign_in, execute_sdk_sign_up, SdkSignInHttpError,
    execute_launcher_token, execute_launcher_sign_in)
from vampir_core.socks_route import SocksRoute
from vampir_core.windows_version import observe_windows_version

PROFILE_SHA = '1d98be691d899b6c9d6280c86d6f42ceeab8ce01cac9685d5e0b8495793cc7ad'


def load_inputs(email, *, route=None, selected_profile='recovered-base'):
    if selected_profile == 'recovered-release':
        spec = importlib.util.spec_from_file_location('nid_release_source', HERE / 'sdk-source-profile.py')
        loader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loader)
        source = loader.load_release_profile('nid', root=ROOT)
    elif selected_profile == 'recovered-base':
        path = ROOT / 'code-clues/nid-windows-initial-profile.json'
        if hashlib.sha256(path.read_bytes()).hexdigest() != PROFILE_SHA: raise ValueError('NID source profile changed')
        source = json.loads(path.read_text('utf-8'))
    else:
        raise ValueError('Select a verified SDK source profile')
    if hashlib.sha256(Path(source['source']).read_bytes()).hexdigest() != source['source_sha256']:
        raise ValueError('Installed client changed')
    registry = DeviceRegistry(HERE / '.local/accounts.sqlite3')
    binding = registry.get(email)
    if binding.kind != 'real' or not binding.identity_recorded or not binding.nid_identity_recorded:
        raise ValueError('Observed device profile is incomplete')
    if binding.confirmation == 'required': raise PermissionError('Device confirmation is required')
    identity = observe_windows_device_identity(store_name='Netmarble', game_code='thered')
    if (identity.device_key, identity.nid_device_key, identity.nm_device_key) != (
            binding.device_key, binding.nid_device_key, binding.nm_device_key):
        raise ValueError('Observed device identity differs from the fixed profile')
    geo = None
    if selected_profile == 'recovered-release':
        public = loader.load_release_profile('public_gmc2', root=ROOT)
        if (public['source_sha256'], public['profile_sha256']) != (source['source_sha256'], source['profile_sha256']):
            raise ValueError('SDK public request and NID source profiles differ')
        fetched_at = time.monotonic()
        body, transport = fetch_gmc2(public['request'], route=route)
        if transport.get('status') != 200 or transport.get('tls_certificate_verification') is not True:
            raise ValueError('SDK configuration HTTP/TLS rejected')
        if transport.get('socks5_loopback_port') != (route.port if route else None):
            raise ValueError('SDK configuration route differs')
        geo = decode_gmc2_geo(body, source_sha256=source['source_sha256'])
    else:
        # Historical profile retains its explicit offline snapshot workflow.
        pointer = json.loads((ROOT / 'code-clues/public-gmc2-recovery.json').read_text('utf-8'))
        path = Path(pointer['manifest'])
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != pointer['sha256']: raise ValueError('SDK snapshot manifest changed')
        manifest = json.loads(data)
        transport = manifest['transport']
        if transport.get('status') != 200: raise ValueError('SDK snapshot HTTP status rejected')
        if transport.get('socks5_loopback_port') != (route.port if route else None):
            raise ValueError('SDK snapshot route differs from the selected route; fetch fresh configuration')
        body = (path.parent / 'body.bin').read_bytes()
        if hashlib.sha256(body).hexdigest() != manifest['body_sha256']: raise ValueError('SDK snapshot body changed')
    config = decode_gmc2_configuration(body, transport['headers'])
    profile = dict(source['profile'])
    version = observe_windows_version()
    profile['os_version'] = version.suffix() if version is not None else ''
    if route:
        country = geo.iso_country if geo is not None else json.loads(body)['resultData']['geoIp']['isoCountry']
        if type(country) is not str or len(country) != 2 or any(not 'A' <= c <= 'Z' for c in country):
            raise ValueError('Missing observed country for selected route')
        profile['country_code'] = country
    if geo is not None:
        prepared = SdkInputs(email, binding, profile, dict(config.constants), selected_profile,
            route.port if route else None, source['source_sha256'], geo, fetched_at)
        prepared.check_usage(email=email, selected_profile=selected_profile, route=route)
        return prepared
    return binding, profile, dict(config.constants)


def run(email, *, timeout=300, password='', create_sdk_player=False, socks_port=None, auth_flow='nid', selected_profile='recovered-base',
        _capture=None, _execute=None, _execute_token=None, _progress=None, _prepared_inputs=None):
    if type(create_sdk_player) is not bool: raise ValueError('Explicit SDK operation required')
    if auth_flow not in ('nid', 'launcher') or (auth_flow == 'launcher' and create_sdk_player):
        raise ValueError('Unsupported explicit SDK auth flow')
    route = SocksRoute(socks_port) if socks_port is not None else None
    prepared = _prepared_inputs if _prepared_inputs is not None else load_inputs(email, route=route, selected_profile=selected_profile)
    if _prepared_inputs is not None and not isinstance(prepared, SdkInputs):
        raise TypeError('Expected a fresh in-memory SDK context')
    if isinstance(prepared, SdkInputs):
        prepared.check_usage(email=email, selected_profile=selected_profile, route=route)
    binding, profile, constants = prepared
    context = prepare_nid_sign_in_context(binding=binding, **profile)
    url = bind_nid_web_url(context, constants=constants, max_url_size=32768)
    if _capture is None:
        spec = importlib.util.spec_from_file_location('nid_browser_live', HERE / 'nid-browser.py')
        browser = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(browser)
        _capture = browser.capture_nid_credential
    # Concurrent accounts must not share WebView cookies or browser-profile locks.
    account_directory = hashlib.sha256(email.strip().lower().encode('utf-8')).hexdigest()[:24]
    provider = _capture(url, expected_game_code=profile['game_code'], timeout=timeout,
                        data_directory=HERE / '.local/nid-accounts' / account_directory / ('socks-' + str(route.port) if route else 'direct'),
                        expected_email=email, sign_in_password=password, socks_port=socks_port)
    if isinstance(prepared, SdkInputs):
        prepared.check_usage(email=email, selected_profile=selected_profile, route=route)
    # SDK DeviceKey differs from the NID DeviceKey used by the preceding page.
    inputs = dict(constants=constants, game_code=profile['game_code'], build_code=profile['build_code'], nm_device_key=binding.nm_device_key,
        device_key=binding.device_key, country_code=profile['country_code'] if route else provider.joined_country_code,
        os_type=profile['os_type'])
    credential = build_nid_sdk_credential(provider)
    if auth_flow == 'launcher':
        # Deliberately selected experiment; never a fallback from ordinary SignIn.
        if _progress: _progress('sdk_launcher_token')
        request = plan_nid_launcher_token(credential=credential, **inputs)
        token = (_execute_token or execute_launcher_token)(request, expected_url=request.url, route=route)
        if _progress: _progress('sdk_launcher_sign_in')
        request = plan_launcher_sign_in(launcher_token=token, **inputs)
        token = credential = provider = None
        return (_execute or execute_launcher_sign_in)(request, expected_url=request.url, route=route)
    planner = plan_nid_sdk_sign_up if create_sdk_player else plan_nid_sdk_sign_in
    request = planner(credential=credential, **inputs)
    executor = _execute or (execute_sdk_sign_up if create_sdk_player else execute_sdk_sign_in)
    return executor(request, expected_url=request.url, route=route)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--email', required=True)
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--password-stdin', action='store_true', help='Read the password from stdin, never from process arguments')
    parser.add_argument('--create-sdk-player', action='store_true', help='Explicit SDK SignUp instead of SignIn; never automatic on errors')
    parser.add_argument('--socks-port', type=int, help='Explicit loopback SOCKS5 route for both browser and SDK HTTPS')
    parser.add_argument('--auth-flow', choices=['nid', 'launcher'], default='nid', help='Explicit SDK flow, no automatic fallback')
    parser.add_argument('--profile', choices=['recovered-base', 'recovered-release'], default='recovered-base')
    args = parser.parse_args()
    try:
        password = sys.stdin.readline(258).rstrip('\r\n') if args.password_stdin else ''
        if args.password_stdin and (not password or len(password) > 256): raise ValueError('Invalid password input')
        data = run(args.email, timeout=args.timeout, password=password, create_sdk_player=args.create_sdk_player,
                   socks_port=args.socks_port, auth_flow=args.auth_flow, selected_profile=args.profile)
        password = None
        print(json.dumps(dict(sdk_response_accepted=True, operation='sign-up' if args.create_sdk_player else 'sign-in', auth_flow=args.auth_flow,
                              player_id_present=bool(data.player_id),
                              sdk_token_present=False if args.create_sdk_player else bool(data.access_token), game_session_ready=False)))
    except SdkSignInHttpError as error:
        print(json.dumps(dict(sdk_response_accepted=False, error=error.kind, http_status=error.status,
                              sdk_error_code=error.sdk_code)))
        sys.exit(2)
    except (ValueError, RuntimeError, PermissionError, KeyError):
        print(json.dumps(dict(sdk_response_accepted=False, error='sign_in_not_completed')))
        sys.exit(2)
