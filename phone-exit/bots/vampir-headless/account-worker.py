"""One owned account job. Only redacted progress is written to stdout."""
import argparse
from datetime import datetime, timezone
from functools import partial
import importlib.util
import json
import ssl
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.account_store import AccountStore
from vampir_core.device_registry import DeviceRegistry
from vampir_core.windows_device_identity import observe_windows_device_identity
from vampir_core.account_catalog import build_account_catalog
from vampir_core.patch_revision import parse_patch_client_revision
from vampir_core.sdk_sign_in_http import SdkSignInHttpError
from vampir_core.character_creation_candidate import carnage_creation_candidate
from vampir_core.world_move_start import SOURCE_SHA256


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def emit(kind, **values):
    print(json.dumps(dict(event=kind, **values), ensure_ascii=False), flush=True)


def run(args):
    store = AccountStore(args.store)
    email, password, settings = store.credential(args.account)
    if not settings.get('enabled', True):
        raise ValueError('This account is disabled')
    if args.operation not in ('servers', 'characters', 'start', 'register', 'create'):
        raise ValueError('Unknown account operation')
    if getattr(args, 'manual_sign_in', False) and args.operation == 'register':
        raise ValueError('Manual sign-in cannot start registration')
    if settings['server_id'] is None and args.operation not in ('servers', 'register'):
        raise ValueError('Select a server first')
    if args.operation == 'create' and (settings.get('create_class') != 'Gunner'
            or settings.get('character_index') is not None or settings.get('character_key') is not None):
        raise ValueError('Creation supports only explicitly selected Carnage without an assigned character')
    registry = DeviceRegistry(HERE / '.local/accounts.sqlite3')
    try:
        binding = registry.get(email)
    except KeyError:
        binding = registry.register(email, kind='real')
        identity = observe_windows_device_identity(store_name='Netmarble', game_code='thered')
        registry.record_real_identity(email, device_key=identity.device_key, nm_device_key=identity.nm_device_key,
            source='Observed current Windows PC, account manager')
        registry.record_real_nid_identity(email, nid_device_key=identity.nid_device_key,
            source='Observed current Windows PC, account manager')
    if args.operation == 'register':
        register_account(store, args, email, password)
        return
    if getattr(args, 'manual_sign_in', False):
        password = ''
    def progress(stage):
        # The lobby wrapper emits this only after a validated NID email callback.
        if stage == 'sdk_sign_in':
            account = next(a for a in store.accounts() if a['id'] == args.account)
            if account['registration_status'] != 'sdk_created':
                store.registration_status(args.account, 'nid_verified')
        emit('phase', stage=stage)
    emit('phase', stage='configuration')
    cdn = load('account_cdn', HERE.parent / 'resource-tools/vampir/fetch-public-cdn-config.py')
    profile = cdn.profile('recovered-release')
    body, transport = cdn.fetch(profile['url'])
    report = dict(profile=profile, transport=transport, body_sha256=cdn.digest(body), body_bytes=len(body),
        fetched_utc=datetime.now(timezone.utc).isoformat(), analysis=cdn.analyze(body))
    manifest, _ = cdn.save(report, body)
    if args.operation == 'servers':
        tool = load('account_lobby', HERE / 'probe-lobby-sdk-login.py')
        response = tool.run(email, selected_profile='recovered-release', manifest_path=manifest, socks_port=None,
            context='sdk-with-partial-metadata', password=password, read_server_list=True, server_policy_byte=0,
            auth_flow=settings.get('auth_flow', 'launcher'), lobby_region=settings['region'] if settings['region'] in ('EU', 'NA', 'SG') else None,
            auth_timeout=300, _progress=progress)
        password = None
        listing = response.server_list_response
        if listing is None or listing.result_code != 0:
            emit('result', status='error', message='Лобби не вернуло список серверов.'); return
        catalog = build_account_catalog(listing, region=settings['region'],
            observed_utc=datetime.now(timezone.utc).isoformat())
        store.save_catalog(settings['region'], catalog)
        emit('result', status='stopped', message='Список серверов загружен.', catalog=catalog); return
    tool = load('account_login', HERE / 'probe-selected-game-login.py')
    # Explicit presentation adapter: labels are opt-in, never returned by ordinary probes.
    start_world = args.operation == 'start' and settings['character_index'] is not None
    expected = settings.get('character_key') if start_world else None
    tool.exchange_game_login = partial(tool.exchange_game_login, expose_character_labels=True,
        expected_character_key=int(expected) if expected is not None else None)
    revision = parse_patch_client_revision(Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Saved/PersistentDownloadDir/Patch/windows.manifestlist').read_bytes())
    def world(position):
        if position is not None:
            emit('active', message='Персонаж в мире; соединение активно.')
    def catalog(listing):
        if listing.result_code != 0:
            raise ValueError('Server catalog was not accepted')
        store.save_catalog(settings['region'], build_account_catalog(listing, region=settings['region'],
            observed_utc=datetime.now(timezone.utc).isoformat()))
    attempt = [None]
    def prepare_creation(characters):
        if characters.result_code != 0 or characters.records: raise ValueError('Expected accepted empty list')
        store.save_characters(args.account, region=settings['region'], server_id=settings['server_id'],
            characters=[], observed_utc=datetime.now(timezone.utc).isoformat())
        nickname = store.creation_nickname(args.account, region=settings['region'], server_id=settings['server_id'])
        payload = carnage_creation_candidate(nickname, source_sha256=SOURCE_SHA256)
        attempt[0] = store.begin_creation(args.account, region=settings['region'], server_id=settings['server_id'],
            nickname=nickname, source_sha256=SOURCE_SHA256)
        emit('phase', stage='character_creation')
        return payload
    def login_attempt():
        return tool.run(email, selected_profile='recovered-release', manifest_path=manifest, socks_port=None,
            server_policy_byte=0, extra_number=revision, context='windows-sdk-initial-reset', region=settings['region'],
            server_id=settings['server_id'], password=password, auth_flow=settings.get('auth_flow', 'launcher'), language_code=1,
            lobby_context='sdk-with-partial-metadata', read_character_list=True,
            character_index=settings['character_index'] if start_world else None,
            read_world_start=start_world, read_world_finish=start_world,
            observe_world_seconds=300 if start_world else 0, world_observer=world if start_world else None,
            _progress=progress, _server_list_observer=catalog,
            creation_factory=prepare_creation if args.operation == 'create' else None)
    try:
        result = login_attempt()
        game = result.get('game', {})
        if attempt[0] is not None:
            state = game.get('character_creation_state', 'unknown')
            store.finish_creation(attempt[0], state=state if state in ('created', 'rejected', 'needs_refresh', 'not_queued') else 'unknown',
                result_code=game.get('character_creation_result_code'), key=game.get('created_character_key'),
                name=game.get('created_character_name'))
    finally:
        if attempt[0] is not None: store.finish_creation(attempt[0], state='unknown')
    password = None
    if result.get('browser_status') in ('timeout', 'login_failed'):
        browser = load('account_browser_failure', HERE / 'nid-browser.py')
        error = browser.NidBrowserStatusError(result['browser_status'], result.get('sign_in_step'),
            result.get('nid_http_status'), result.get('nid_error_code'), result.get('nid_response_state'))
        emit('result', **failure(error))
        return
    if result.get('error_type') == 'SdkSignInHttpError':
        emit('result', **failure(SdkSignInHttpError('redacted', result.get('http_status'), result.get('sdk_error_code'))))
        return
    game = result.get('game', {})
    code = game.get('login_result_code')
    remember_characters(store, args.account, settings, game)
    if args.operation == 'characters' and (game.get('login_result_code') == 0
            and game.get('character_list_received') is True and game.get('character_list_result_code') == 0):
        store.reconcile_creation(args.account, region=settings['region'], server_id=settings['server_id'])
    if code not in (None, 0):
        message = f"Login {code}: {game.get('login_result_key') or 'отказ сервера'}"
        state = 'error'
    elif result.get('status') != 'game_login_probe' or game.get('error'):
        message, state = 'Вход не завершён: ' + str(result.get('stage', 'unknown')), 'error'
        if result.get('browser_status') == 'timeout':
            message = 'Истекло время входа Netmarble. Игровое соединение не открыто; проверьте окно авторизации.'
    elif args.operation == 'create' and attempt[0] is not None:
        status = game.get('character_creation_state')
        state = 'needs_character'
        message = {'created': 'Персонаж создан. Прочитайте список, чтобы назначить его и войти.',
            'rejected': 'Сервер отклонил создание. Ник не менялся; автоматического повтора нет.',
            'not_queued': 'Создание не отправлено. Прочитайте список перед новой попыткой.'}.get(status,
            'Исход создания не подтверждён. Прочитайте список перед новой попыткой.')
    elif game.get('character_entry_state') == 'empty_list':
        name = store.creation_nickname(args.account, region=settings['region'], server_id=settings['server_id'])
        message, state = ('Персонажей нет. ' + ('Ник подготовлен; ' if name else 'Укажите ник; ') +
            'сетевое создание ещё не подключено.'), 'needs_character'
    elif game.get('selection_error'):
        message, state = 'Проверьте выбранного персонажа: ' + game['selection_error'], 'needs_character'
    elif game.get('characters') and settings['character_index'] is None:
        message, state = 'Персонажи уже есть. Выберите существующего; новый создаваться не будет.', 'needs_character'
    else:
        message, state = ('Проверка завершена; соединение закрыто.', 'stopped')
    emit('result', status=state, message=message, characters=game.get('characters', []),
        login_code=code, character_count=game.get('character_count'))


def remember_characters(store, identifier, settings, game):
    if (game.get('login_result_code') == 0 and game.get('character_list_received') is True
            and game.get('character_list_result_code') == 0 and 'characters' in game):
        store.save_characters(identifier, region=settings['region'], server_id=settings['server_id'],
            characters=game['characters'], observed_utc=datetime.now(timezone.utc).isoformat())


def register_account(store, args, email, password):
    if not args.accept_required_terms:
        raise ValueError('Explicit terms acceptance required')
    if next(a for a in store.accounts() if a['id'] == args.account)['registration_status'] == 'registered':
        raise ValueError('Registration already confirmed')
    mail_password = None if args.manual_mail_code else store.mail_credential(args.account)
    tool = load('account_registration', HERE / 'register-nid-account.py')
    store.registration_status(args.account, 'in_progress')
    def progress(state):
        if state.get('stopped') == 'email_already_in_use':
            store.registration_status(args.account, 'email_in_use')
        emit('phase', stage='registration_code' if state.get('need_code') else 'registration_form')
        paths = ('/auth/signin', '/auth/signin/email', '/auth/signup/terms', '/auth/signup/email/input',
            '/auth/signup/email/verify', '/auth/signup/password/input', '/auth/signup/email/complete', '/auth/signup/complete')
        emit('registration', path=state.get('path') if state.get('path') in paths else 'other',
            mail_sent=state.get('email_sent') is True, code_submitted=state.get('code_submitted') is True,
            password_submitted=state.get('password_submitted') is True, complete=state.get('complete') is True)
    def read_code():
        emit('phase', stage='registration_code')
        value = sys.stdin.readline(8).strip()
        if len(value) != 5 or not value.isascii() or not value.isdigit():
            raise ValueError('Invalid verification input')
        return value
    try:
        tool.run(email, password=password, mail_password=mail_password, socks_port=None,
            selected_profile='recovered-release', timeout=300, accept_required_terms=True, _progress=progress,
            _code_provider=read_code if args.manual_mail_code else None)
    except BaseException:
        account = next(a for a in store.accounts() if a['id'] == args.account)
        if account['registration_status'] == 'email_in_use':
            emit('result', status='stopped', message='Netmarble: почта уже используется. Повторная регистрация остановлена; вход ещё не проверен.')
            return
        store.registration_status(args.account, 'unconfirmed')
        raise
    finally:
        password = mail_password = None
    store.registration_status(args.account, 'registered')
    emit('result', status='stopped', message='Регистрация Netmarble подтверждена. Можно загрузить серверы и войти.')


def failure(error):
    browser_status = getattr(error, 'browser_status', None)
    if browser_status in ('timeout', 'login_failed'):
        status, code = getattr(error, 'nid_http_status', None), getattr(error, 'nid_error_code', None)
        status = status if type(status) is int and 100 <= status <= 599 else None
        code = code if type(code) is int and -(2**31) <= code < 2**31 else None
        message = ('Netmarble показал Login Failed. Причина отказа не установлена.' if browser_status == 'login_failed' else
            'Истекло время входа Netmarble. Проверьте окно авторизации.')
        step = {'waiting': 'ожидание формы', 'opened_email': 'выбор входа по почте', 'filled': 'поля заполнены',
            'submitted': 'форма отправлена', 'form_changed': 'форма изменилась', 'script_failed': 'обработка формы остановлена'
            }.get(getattr(error, 'sign_in_step', None))
        response = {'non_json': 'ответ не в JSON', 'length_limit': 'объявленный размер вне лимита',
            'body_limit': 'тело больше лимита', 'length_mismatch': 'длина ответа не совпала',
            'no_numeric_code': 'числовой код не найден', 'read_failed': 'не удалось прочитать поток ответа',
            'invalid_utf8': 'ответ содержит некорректный UTF-8',
            'content_unavailable': 'WebView не предоставил тело ответа',
            'response_observation_failed': 'ошибка получения ответа из WebView'
            }.get(getattr(error, 'nid_response_state', None))
        return dict(status='error', message=message + ' Игровое соединение не открыто.' +
            (f' Этап: {step}.' if step is not None else '') +
            (f' Диагностика NID: {response}.' if response is not None else '') +
            (f' HTTP {status}.' if status is not None else '') + (f' Код NID: {code}.' if code is not None else ''))
    if isinstance(error, SdkSignInHttpError):
        code = error.sdk_code if type(error.sdk_code) is int and -(2**31) <= error.sdk_code < 2**31 else None
        status = error.status if type(error.status) is int and 100 <= error.status <= 599 else None
        return dict(status='error', message='Netmarble принят; запрос игрового SDK отклонён.' +
            (f' HTTP {status}.' if status is not None else '') + (f' Код SDK: {code}.' if code is not None else ''),
            sdk_error=dict(http_status=status, code=code))
    return dict(status='error', message=(
        'Почтовый сервер не прошёл проверку TLS. Исправьте сертификат или выберите ввод кода из письма вручную.'
        if isinstance(error, ssl.SSLCertVerificationError) else 'Операция не завершена: ' + type(error).__name__))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--store', required=True, type=Path)
    parser.add_argument('--account', required=True)
    parser.add_argument('--operation', choices=['servers', 'characters', 'start', 'register', 'create'], required=True)
    parser.add_argument('--accept-required-terms', action='store_true')
    parser.add_argument('--manual-mail-code', action='store_true')
    parser.add_argument('--manual-sign-in', action='store_true')
    try:
        run(parser.parse_args())
    except Exception as error:
        # Messages from networking / auth helpers may contain sensitive values.
        emit('result', **failure(error))
        raise SystemExit(2)
