"""One current-source read-only SDK Fetch for a saved mail account; no creation."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[2]
ROOT = Path('F:/PhoneExit Resources/Vampir')
INSTALLED = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.account_store import AccountStore
from vampir_core.nid_web_context import prepare_nid_sign_in_context
from vampir_core.nid_web_url import bind_nid_web_url
from vampir_core.sdk_fetch import SdkFetchSummary
from vampir_core.sdk_fetch_admission import scope, execute_fetch
from vampir_core.sdk_sign_in_http import SdkSignInHttpError, execute_sdk_fetch
from vampir_core.socks_route import SocksRoute


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(account, profile_sha256, *, timeout=180, capture_sdk_http=False):
    if type(timeout) is not int or not 1 <= timeout <= 180 or type(capture_sdk_http) is not bool:
        raise ValueError('Fetch requires a bounded explicit operation')
    store = AccountStore(HERE / '.local/console.sqlite3')
    email, password, settings = store.credential(account)
    settings = AccountStore.assignment(settings)
    if not settings['enabled'] or not email.endswith('@vampir.top'):
        raise ValueError('Fetch requires an enabled saved mail account')
    fingerprint = store._fingerprint(settings)
    runner, browser = load('run-nid-sdk-sign-in'), load('nid-browser')
    # Preserve real-PC fallback bindings; custom keys still come from the shared template.
    load('verify-account').ensure_pc_binding(runner, email)
    capture = None
    if capture_sdk_http:
        import uuid
        capture = load('run-account-entry-diagnostic').Capture(
            HERE / '.local/verification-captures' / uuid.uuid4().hex)
    result = dict(operation='v1/fetch-player', accepted=False, game_session_ready=False,
                  player_created=False, read_only=True)
    progress = lambda stage: print(json.dumps(dict(stage=stage)), flush=True)
    try:
        with scope(profile_sha256, root=ROOT, workspace=WORKSPACE, installed=INSTALLED) as (profile, selector):
            port = settings['socks_port']
            route = SocksRoute(port) if port is not None else None
            progress('configuration')
            prepared = runner.load_inputs(email, route=route, selected_profile=selector,
                device_settings=settings['device_settings'])
            context = prepare_nid_sign_in_context(binding=prepared.binding, **prepared.profile)
            url = bind_nid_web_url(context, constants=prepared.constants, max_url_size=32768)
            identity = '|'.join((email, prepared.binding.device_key, prepared.binding.nm_device_key,
                                 prepared.binding.nid_device_key, str(port)))
            directory = HERE / '.local/nid-fetch' / hashlib.sha256(identity.encode()).hexdigest()[:32]
            progress('nid_browser')
            provider = browser.capture_nid_credential(url, expected_game_code=prepared.profile['game_code'],
                timeout=timeout, expected_email=email, sign_in_password=password, socks_port=port,
                data_directory=directory)
            password = None
            current = next(a for a in store.accounts() if a['id'] == account)
            if store._fingerprint(current) != fingerprint or not current['enabled']:
                raise ValueError('Account/device changed during Fetch preparation')
            executor = capture.executor('sdk/fetch-player', execute_sdk_fetch) if capture else None
            summary = execute_fetch(prepared, provider, route=route, progress=progress, _execute=executor)
            provider = None
            if type(summary) is not SdkFetchSummary or summary.result_object_present is not True:
                raise ValueError('Fetch result is not a verified summary')
            result.update(accepted=True, result_object_present=True)
    except SdkSignInHttpError as error:
        result.update(error=error.kind, http_status=error.status, sdk_error_code=error.sdk_code)
    except browser.NidBrowserStatusError as error:
        result.update(error='nid_not_completed', browser_status=error.browser_status)
    except (ValueError, RuntimeError, OSError, KeyError) as error:
        result.update(error='fetch_not_completed', error_type=type(error).__name__)
    finally:
        password = None
        if capture:
            capture.finish(result)
        print(json.dumps(dict(result=result, report=str(capture.folder / 'report.json') if capture else None)), flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account', required=True, help='Локальный ID; пароль читается из DPAPI')
    parser.add_argument('--profile', required=True, help='Полный SHA отдельного Fetch-профиля')
    parser.add_argument('--capture-sdk-http', action='store_true', help='Явная ограниченная запись SDK HTTP под DPAPI')
    args = parser.parse_args()
    outcome = run(args.account, args.profile, capture_sdk_http=args.capture_sdk_http)
    sys.exit(0 if outcome['accepted'] else 2)
