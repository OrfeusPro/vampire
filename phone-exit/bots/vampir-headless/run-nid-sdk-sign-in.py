"""One explicit NID window -> SDK sign-in attempt. Never print live credentials."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.device_registry import DeviceRegistry
from vampir_core.windows_device_identity import observe_windows_device_identity
from vampir_core.gmc2_response import decode_gmc2_configuration
from vampir_core.nid_web_context import prepare_nid_sign_in_context
from vampir_core.nid_web_url import bind_nid_web_url
from vampir_core.nid_sdk_credential import build_nid_sdk_credential
from vampir_core.sdk_sign_in import plan_nid_sdk_sign_in, plan_nid_sdk_sign_up
from vampir_core.sdk_sign_in_http import execute_sdk_sign_in, execute_sdk_sign_up, SdkSignInHttpError

PROFILE_SHA = '1d98be691d899b6c9d6280c86d6f42ceeab8ce01cac9685d5e0b8495793cc7ad'


def load_inputs(email):
    path = ROOT / 'code-clues/nid-windows-initial-profile.json'
    if hashlib.sha256(path.read_bytes()).hexdigest() != PROFILE_SHA: raise ValueError('NID source profile changed')
    source = json.loads(path.read_text('utf-8'))
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
    pointer = json.loads((ROOT / 'code-clues/public-gmc2-recovery.json').read_text('utf-8'))
    path = Path(pointer['manifest'])
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != pointer['sha256']: raise ValueError('SDK snapshot manifest changed')
    manifest = json.loads(data)
    body = (path.parent / 'body.bin').read_bytes()
    if hashlib.sha256(body).hexdigest() != manifest['body_sha256']: raise ValueError('SDK snapshot body changed')
    config = decode_gmc2_configuration(body, manifest['transport']['headers'])
    return binding, source['profile'], dict(config.constants)


def run(email, *, timeout=300, password='', create_sdk_player=False, _capture=None, _execute=None):
    if type(create_sdk_player) is not bool: raise ValueError('Explicit SDK operation required')
    binding, profile, constants = load_inputs(email)
    context = prepare_nid_sign_in_context(binding=binding, **profile)
    url = bind_nid_web_url(context, constants=constants, max_url_size=32768)
    if _capture is None:
        spec = importlib.util.spec_from_file_location('nid_browser_live', HERE / 'nid-browser.py')
        browser = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(browser)
        _capture = browser.capture_nid_credential
    provider = _capture(url, expected_game_code=profile['game_code'], timeout=timeout,
                        data_directory=HERE / '.local/nid-sign-in-webview', expected_email=email,
                        sign_in_password=password)
    # SDK DeviceKey differs from the NID DeviceKey used by the preceding page.
    planner = plan_nid_sdk_sign_up if create_sdk_player else plan_nid_sdk_sign_in
    request = planner(constants=constants, credential=build_nid_sdk_credential(provider),
        game_code=profile['game_code'], build_code=profile['build_code'], nm_device_key=binding.nm_device_key,
        device_key=binding.device_key, country_code=provider.joined_country_code, os_type=profile['os_type'])
    executor = _execute or (execute_sdk_sign_up if create_sdk_player else execute_sdk_sign_in)
    return executor(request, expected_url=request.url)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--email', required=True)
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--password-stdin', action='store_true', help='Read the password from stdin, never from process arguments')
    parser.add_argument('--create-sdk-player', action='store_true', help='Explicit SDK SignUp instead of SignIn; never automatic on errors')
    args = parser.parse_args()
    try:
        password = sys.stdin.readline(258).rstrip('\r\n') if args.password_stdin else ''
        if args.password_stdin and (not password or len(password) > 256): raise ValueError('Invalid password input')
        data = run(args.email, timeout=args.timeout, password=password, create_sdk_player=args.create_sdk_player)
        password = None
        print(json.dumps(dict(sdk_response_accepted=True, operation='sign-up' if args.create_sdk_player else 'sign-in',
                              player_id_present=bool(data.player_id),
                              sdk_token_present=False if args.create_sdk_player else bool(data.access_token), game_session_ready=False)))
    except SdkSignInHttpError as error:
        print(json.dumps(dict(sdk_response_accepted=False, error=error.kind, http_status=error.status,
                              sdk_error_code=error.sdk_code)))
        sys.exit(2)
    except (ValueError, RuntimeError, PermissionError, KeyError):
        print(json.dumps(dict(sdk_response_accepted=False, error='sign_in_not_completed')))
        sys.exit(2)
