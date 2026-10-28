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
from vampir_core.sdk_fetch import plan_nid_sdk_fetch
from vampir_core.sdk_first_login import execute_first_sdk_login, FirstSdkLoginStopped
from vampir_core.sdk_terms import plan_basic_terms_read
from vampir_core.sdk_sign_in_http import (execute_sdk_sign_in, execute_sdk_sign_up, SdkSignInHttpError,
    execute_launcher_token, execute_launcher_sign_in, execute_sdk_fetch)
from vampir_core.socks_route import SocksRoute
from vampir_core.windows_version import observe_windows_version
from vampir_core.runtime_admission import prepared_entrypoint,is_prepared

PROFILE_SHA = '1d98be691d899b6c9d6280c86d6f42ceeab8ce01cac9685d5e0b8495793cc7ad'


@prepared_entrypoint(root=ROOT,workspace=HERE.parents[2])
def load_inputs(email, *, device_settings=None, route=None, selected_profile='recovered-base'):
    if selected_profile == 'recovered-release' or is_prepared(selected_profile):
        spec = importlib.util.spec_from_file_location('nid_release_source', HERE / 'sdk-source-profile.py')
        loader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loader)
        source = (loader.load_prepared_profile('nid',selected_profile=selected_profile,root=ROOT)
            if is_prepared(selected_profile) else loader.load_release_profile('nid', root=ROOT))
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
    from vampir_core.bot_device_settings import validate, apply_binding
    settings = validate(device_settings)
    binding = apply_binding(binding, settings)
    geo = None
    if selected_profile == 'recovered-release' or is_prepared(selected_profile):
        public = (loader.load_prepared_profile('public_gmc2',selected_profile=selected_profile,root=ROOT)
            if is_prepared(selected_profile) else loader.load_release_profile('public_gmc2', root=ROOT))
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
    from vampir_core.bot_device_settings import apply_system
    _, version = apply_system(None, version, settings)
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


@prepared_entrypoint(root=ROOT,workspace=HERE.parents[2])
def run(email, *, timeout=300, password='', create_sdk_player=False, fetch_player=False, first_sdk_login=False,
        terms_country=None, terms_locale=None, basic_filtered=None, socks_port=None, auth_flow='nid', selected_profile='recovered-base',
        _capture=None, _execute=None, _execute_token=None, _progress=None, _prepared_inputs=None, device_settings=None):
    from vampir_core.bot_device_settings import validate
    device_settings = validate(device_settings)
    if is_prepared(selected_profile) and (auth_flow!='launcher' or create_sdk_player or fetch_player or first_sdk_login):
        raise ValueError('Prepared SDK supports launcher sign-in only')
    if type(create_sdk_player) is not bool: raise ValueError('Explicit SDK operation required')
    if type(first_sdk_login) is not bool or (first_sdk_login and (
            create_sdk_player or fetch_player or auth_flow != 'nid' or selected_profile != 'recovered-release')):
        raise ValueError('First SDK login requires its separate current NID flow')
    if type(fetch_player) is not bool or (fetch_player and (create_sdk_player or auth_flow != 'nid')):
        raise ValueError('Fetch is a separate explicit NID operation')
    if auth_flow not in ('nid', 'launcher') or (auth_flow == 'launcher' and create_sdk_player):
        raise ValueError('Unsupported explicit SDK auth flow')
    route = SocksRoute(socks_port) if socks_port is not None else None
    prepared = _prepared_inputs if _prepared_inputs is not None else load_inputs(email, route=route, selected_profile=selected_profile, **({'device_settings': device_settings} if device_settings else {}))
    if _prepared_inputs is not None and not isinstance(prepared, SdkInputs):
        raise TypeError('Expected a fresh in-memory SDK context')
    if isinstance(prepared, SdkInputs):
        prepared.check_usage(email=email, selected_profile=selected_profile, route=route)
        prepared.check_auth_operation(auth_flow=auth_flow, create_sdk_player=create_sdk_player,
            fetch_player=fetch_player, first_sdk_login=first_sdk_login)
    binding, profile, constants = prepared
    if first_sdk_login:
        if not isinstance(prepared, SdkInputs): raise ValueError('First SDK login requires fresh current inputs')
        plan_basic_terms_read(constants=constants, game_code=profile['game_code'], country=terms_country,
                              locale=terms_locale, platform=profile['os_type'], filtered=basic_filtered)
    context = prepare_nid_sign_in_context(binding=binding, **profile)
    url = bind_nid_web_url(context, constants=constants, max_url_size=32768)
    if _capture is None:
        spec = importlib.util.spec_from_file_location('nid_browser_live', HERE / 'nid-browser.py')
        browser = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(browser)
        _capture = browser.capture_nid_credential
    # Concurrent accounts must not share WebView cookies or browser-profile locks.
    account_directory = hashlib.sha256(email.strip().lower().encode('utf-8')).hexdigest()[:24]
    if device_settings and device_settings.get('identity'):
        identity_digest = hashlib.sha256(('|'.join((binding.device_key, binding.nm_device_key, binding.nid_device_key))).encode()).hexdigest()[:24]
        account_directory += '/device-' + identity_digest
    if _progress: _progress('nid_browser')
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
    if first_sdk_login:
        return execute_first_sdk_login(credential=credential, inputs=inputs,
            terms_country=terms_country, terms_locale=terms_locale, basic_filtered=basic_filtered,
            route=route, progress=_progress,
            check_context=lambda: prepared.check_usage(email=email, selected_profile=selected_profile, route=route))
    if fetch_player:
        if _progress: _progress('sdk_fetch_player')
        request = plan_nid_sdk_fetch(credential=credential, **inputs)
        credential = provider = None
        return (_execute or execute_sdk_fetch)(request, expected_url=request.url, route=route)
    if auth_flow == 'launcher':
        # Deliberately selected experiment; never a fallback from ordinary SignIn.
        if _progress: _progress('sdk_launcher_token')
        request = plan_nid_launcher_token(credential=credential, **inputs)
        token = (_execute_token or execute_launcher_token)(request, expected_url=request.url, route=route)
        if isinstance(prepared, SdkInputs):
            prepared.check_usage(email=email, selected_profile=selected_profile, route=route)
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
    parser.add_argument('--fetch-player', action='store_true', help='Read SDK profile state only; no sign-in, terms or creation after Fetch')
    parser.add_argument('--first-sdk-login', action='store_true', help='Первый SDK-вход: Fetch → условия → SDK-профиль → SignIn; без повторной регистрации Netmarble')
    parser.add_argument('--terms-country', help='Явная ISO-страна запроса условий')
    parser.add_argument('--terms-locale', help='Явный язык запроса условий; язык игры автоматически не определяется')
    parser.add_argument('--basic-terms-mode', choices=['all', 'filtered-unique'], help='Явный выбор ветви BasicTerms')
    parser.add_argument('--socks-port', type=int, help='Explicit loopback SOCKS5 route for both browser and SDK HTTPS')
    parser.add_argument('--auth-flow', choices=['nid', 'launcher'], default='nid', help='Explicit SDK flow, no automatic fallback')
    parser.add_argument('--profile', default='recovered-base', help='Проверенный профиль либо prepared-next / prepared:<SHA>')
    args = parser.parse_args()
    try:
        password = sys.stdin.readline(258).rstrip('\r\n') if args.password_stdin else ''
        if args.password_stdin and (not password or len(password) > 256): raise ValueError('Invalid password input')
        data = run(args.email, timeout=args.timeout, password=password, create_sdk_player=args.create_sdk_player, fetch_player=args.fetch_player,
                   first_sdk_login=args.first_sdk_login, terms_country=args.terms_country, terms_locale=args.terms_locale,
                   basic_filtered=None if args.basic_terms_mode is None else args.basic_terms_mode == 'filtered-unique',
                   socks_port=args.socks_port, auth_flow=args.auth_flow, selected_profile=args.profile)
        password = None
        if args.fetch_player:
            print(json.dumps(dict(sdk_fetch_accepted=True, result_object_present=data.result_object_present,
                                  game_session_ready=False, player_created=False)))
            sys.exit(0)
        print(json.dumps(dict(sdk_response_accepted=True, operation='sign-up' if args.create_sdk_player else 'sign-in', auth_flow=args.auth_flow,
                              player_id_present=bool(data.player_id),
                              sdk_token_present=False if args.create_sdk_player else bool(data.access_token), game_session_ready=False)))
    except SdkSignInHttpError as error:
        print(json.dumps(dict(sdk_response_accepted=False, error=error.kind, http_status=error.status,
                              sdk_error_code=error.sdk_code)))
        sys.exit(2)
    except FirstSdkLoginStopped as error:
        print(json.dumps(dict(sdk_response_accepted=False, error=error.kind)))
        sys.exit(2)
    except (ValueError, RuntimeError, PermissionError, KeyError):
        print(json.dumps(dict(sdk_response_accepted=False, error='sign_in_not_completed')))
        sys.exit(2)
