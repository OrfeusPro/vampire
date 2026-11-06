"""One admitted first SDK login for a saved account; no game or blind retries."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import uuid

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[2]
ROOT = Path('F:/PhoneExit Resources/Vampir')
INSTALLED = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.account_store import AccountStore
from vampir_core.nid_web_context import prepare_nid_sign_in_context
from vampir_core.nid_web_url import bind_nid_web_url
from vampir_core.sdk_first_login import FirstSdkLoginStopped
from vampir_core.sdk_first_profile_admission import scope, execute_first_profile
from vampir_core.sdk_sign_in_http import SdkSignInHttpError, execute_sdk_fetch, execute_sdk_sign_up, execute_sdk_sign_in
from vampir_core.sdk_terms_http import TermsReadError
from vampir_core.socks_route import SocksRoute


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def atomic(path, value):
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')
    temporary = path.with_suffix('.tmp')
    with temporary.open('wb') as stream:
        stream.write(raw)
        stream.flush()
        import os
        os.fsync(stream.fileno())
    temporary.replace(path)


def nid_failure(error):
    return {name: getattr(error,name) for name in ('browser_status','sign_in_step','nid_http_status',
        'nid_error_code','nid_response_state','nid_error_hint','nid_response_shape')}


@contextmanager
def account_lease(account, folder):
    # The kernel releases the lease after a crash. A stale pathname is not a lock.
    try:
        canonical = str(uuid.UUID(account))
    except (ValueError, TypeError, AttributeError):
        raise ValueError('First SDK requires a local account ID') from None
    if canonical != account:
        raise ValueError('First SDK requires a local account ID')
    folder.mkdir(parents=True, exist_ok=True)
    with (folder / (account + '.lock')).open('a+b') as stream:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b'\0'); stream.flush()
        stream.seek(0)
        try:
            if sys.platform == 'win32':
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RuntimeError('First SDK already has an owner for this account') from None
        try:
            yield
        finally:
            stream.seek(0)
            if sys.platform == 'win32':
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def run(account, profile_sha256, *, terms_country, terms_locale, basic_filtered,
        timeout=180, capture_sdk_http=False):
    if type(timeout) is not int or not 1 <= timeout <= 180 or type(capture_sdk_http) is not bool:
        raise ValueError('First SDK requires a bounded explicit operation')
    with account_lease(account, HERE / '.local/first-sdk-leases'):
        return _run(account, profile_sha256, terms_country=terms_country, terms_locale=terms_locale,
                    basic_filtered=basic_filtered, timeout=timeout, capture_sdk_http=capture_sdk_http)


def _run(account, profile_sha256, *, terms_country, terms_locale, basic_filtered, timeout, capture_sdk_http):
    store = AccountStore(HERE / '.local/console.sqlite3')
    email, password, settings = store.credential(account)
    settings = AccountStore.assignment(settings)
    if not settings['enabled'] or not email.endswith('@vampir.top'):
        raise ValueError('First SDK requires an enabled saved mail account')
    fingerprint = store._fingerprint(settings)
    runner, browser = load('run-nid-sdk-sign-in'), load('nid-browser')
    load('verify-account').ensure_pc_binding(runner, email)
    attempt = HERE / '.local/first-sdk-attempts' / uuid.uuid4().hex
    attempt.mkdir(parents=True, exist_ok=False)
    result = dict(accepted=False, sdk_response_accepted=False, game_session_ready=False, sdk_profile_created=False, signup_attempted=False,
                  operation='first-sdk-profile', profile_sha256=profile_sha256, stages=[])
    capture = (load('run-account-entry-diagnostic').Capture(attempt / 'capture') if capture_sdk_http else None)

    def progress(stage):
        # Fixed stage names only; values and credentials never enter the journal.
        if stage not in ('configuration', 'nid_browser', 'sdk_fetch_player', 'sdk_basic_terms',
                         'sdk_individual_terms', 'sdk_first_profile', 'sdk_sign_in', 'verify_device-registration',
                         'verify_workplace', 'manual_verification_code', 'verification_mail'):
            raise ValueError('Unexpected first SDK stage')
        if stage == 'sdk_first_profile': result['signup_attempted'] = True
        if stage == 'sdk_sign_in' and result['signup_attempted']: result['sdk_profile_created'] = True
        result['stages'].append(stage)
        atomic(attempt / 'report.json', result)
        print(json.dumps(dict(stage=stage)), flush=True)

    def check_account():
        current = next(a for a in store.accounts() if a['id'] == account)
        if store._fingerprint(current) != fingerprint or not current['enabled']:
            raise ValueError('Account/device changed during first SDK preparation')

    try:
        with scope(profile_sha256, root=ROOT, workspace=WORKSPACE, installed=INSTALLED) as (_, selector):
            port = settings['socks_port']
            route = SocksRoute(port) if port is not None else None
            progress('configuration')
            prepared = runner.load_inputs(email, route=route, selected_profile=selector,
                device_settings=settings['device_settings'])
            country = prepared.geo.iso_country if terms_country == 'observed' else terms_country
            # Validate both explicit query choices before opening NID.
            from vampir_core.sdk_terms import plan_basic_terms_read, plan_individual_terms_read
            query = dict(constants=prepared.constants, game_code=prepared.profile['game_code'], country=country,
                         locale=terms_locale, platform=prepared.profile['os_type'])
            plan_basic_terms_read(**query, filtered=basic_filtered)
            plan_individual_terms_read(**query, terms_name='terms_of_service_ko')
            context = prepare_nid_sign_in_context(binding=prepared.binding, **prepared.profile)
            url = bind_nid_web_url(context, constants=prepared.constants, max_url_size=32768)
            identity = '|'.join((email, prepared.binding.device_key, prepared.binding.nm_device_key,
                                 prepared.binding.nid_device_key, str(port)))
            directory = HERE / '.local/nid-first-sdk' / hashlib.sha256(identity.encode()).hexdigest()[:32]
            progress('nid_browser')
            provider = browser.capture_nid_credential(url, expected_game_code=prepared.profile['game_code'],
                timeout=timeout, expected_email=email, sign_in_password=password, socks_port=port,
                data_directory=directory)
            password = None
            executors = ({name: capture.executor(stage, execute) for name, stage, execute in (
                ('_fetch', 'sdk/fetch-player', execute_sdk_fetch), ('_signup', 'sdk/sign-up', execute_sdk_sign_up),
                ('_signin', 'sdk/sign-in', execute_sdk_sign_in))} if capture else {})
            signed = execute_first_profile(prepared, provider, terms_country=country, terms_locale=terms_locale,
                basic_filtered=basic_filtered, route=route, progress=progress, check_account=check_account, **executors)
            result.update(sdk_response_accepted=True, player_id_present=bool(signed.player_id), sdk_token_present=bool(signed.access_token))
            check_account()
            store.registration_status(account, 'sdk_created')
            verification = load('verify-account')
            steps = signed.verification_steps
            needs_code = steps in (('device-registration',), ('workplace',), ('device-registration', 'workplace'))
            mail_password = store.reveal_password(account, 'mail') if needs_code else None
            try:
                # This is terminal preparation. The existing form keeps its own 10-minute
                # limit, and no lobby may consume the old GMC2 context after it finishes.
                status, completed = verification.continue_verification(email=email, settings=settings,
                    prepared=prepared, data=signed, mail_password=mail_password, progress=progress,
                    require_fresh_context=False)
            finally:
                mail_password = None
                signed = provider = None
            result.update(verification_status=status, verification_completed=completed)
            check_account()
            if status == 'verified':
                if not store.record_device_verification(account, fingerprint):
                    raise ValueError('First SDK device changed before confirmation was recorded')
                result['accepted'] = True
    except SdkSignInHttpError as error:
        result.update(error=error.kind, http_status=error.status, sdk_error_code=error.sdk_code)
    except FirstSdkLoginStopped as error:
        result.update(error=error.kind)
    except TermsReadError as error:
        result.update(error='terms_' + error.kind)
    except browser.NidBrowserStatusError as error:
        result.update(error='nid_not_completed', **nid_failure(error))
    except (ValueError, RuntimeError, OSError, KeyError) as error:
        result.update(error='first_sdk_not_completed', error_type=type(error).__name__)
    finally:
        password = None
        result['signup_outcome_unknown'] = result['signup_attempted'] and not result['sdk_profile_created']
        atomic(attempt / 'report.json', result)
        if capture: capture.finish(result)
        print(json.dumps(dict(result=result, report=str(attempt / 'report.json'))), flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account', required=True, help='Локальный ID; пароль читается из DPAPI')
    parser.add_argument('--profile', required=True, help='Полный SHA отдельного first SDK профиля')
    parser.add_argument('--terms-country', required=True, help='ISO-страна либо observed из свежего GMC2')
    parser.add_argument('--terms-locale', required=True, help='Явный язык условий')
    parser.add_argument('--basic-terms-mode', required=True, choices=('all', 'filtered-unique'))
    parser.add_argument('--capture-sdk-http', action='store_true', help='Ограниченная приватная запись SDK HTTP под DPAPI')
    args = parser.parse_args()
    outcome = run(args.account, args.profile, terms_country=args.terms_country, terms_locale=args.terms_locale,
        basic_filtered=args.basic_terms_mode == 'filtered-unique', capture_sdk_http=args.capture_sdk_http)
    sys.exit(0 if outcome['accepted'] else 2)
