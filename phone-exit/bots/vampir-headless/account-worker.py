"""One owned account job. Only redacted progress is written to stdout."""
import argparse
from datetime import datetime, timezone
from functools import partial
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.account_store import AccountStore
from vampir_core.device_registry import DeviceRegistry
from vampir_core.windows_device_identity import observe_windows_device_identity
from vampir_core.account_catalog import build_account_catalog
from vampir_core.patch_revision import parse_patch_client_revision


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
    if settings['server_id'] is None and args.operation not in ('servers', 'register'):
        raise ValueError('Select a server first')
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
            auth_flow='launcher', lobby_region=settings['region'] if settings['region'] in ('EU', 'NA', 'SG') else None,
            auth_timeout=300, _progress=lambda stage: emit('phase', stage=stage))
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
    result = tool.run(email, selected_profile='recovered-release', manifest_path=manifest, socks_port=None,
        server_policy_byte=0, extra_number=revision, context='windows-sdk-initial-reset', region=settings['region'],
        server_id=settings['server_id'], password=password, auth_flow='launcher', language_code=1,
        lobby_context='sdk-with-partial-metadata', read_character_list=True,
        character_index=settings['character_index'] if start_world else None,
        read_world_start=start_world, read_world_finish=start_world,
        observe_world_seconds=300 if start_world else 0, world_observer=world if start_world else None,
        _progress=lambda stage: emit('phase', stage=stage))
    password = None
    game = result.get('game', {})
    code = game.get('login_result_code')
    if code not in (None, 0):
        message = f"Login {code}: {game.get('login_result_key') or 'отказ сервера'}"
        state = 'error'
    elif result.get('status') != 'game_login_probe' or game.get('error'):
        message, state = 'Вход не завершён: ' + str(result.get('stage', 'unknown')), 'error'
    elif game.get('character_entry_state') == 'empty_list':
        message, state = 'Персонажей нет. Ник сохранён; сетевое создание ещё не подключено.', 'needs_character'
    elif game.get('selection_error'):
        message, state = 'Проверьте выбранного персонажа: ' + game['selection_error'], 'needs_character'
    else:
        message, state = ('Проверка завершена; соединение закрыто.', 'stopped')
    emit('result', status=state, message=message, characters=game.get('characters', []),
        login_code=code, character_count=game.get('character_count'))


def register_account(store, args, email, password):
    if not args.accept_required_terms:
        raise ValueError('Explicit terms acceptance required')
    if next(a for a in store.accounts() if a['id'] == args.account)['registration_status'] == 'registered':
        raise ValueError('Registration already confirmed')
    mail_password = store.mail_credential(args.account)
    tool = load('account_registration', HERE / 'register-nid-account.py')
    store.registration_status(args.account, 'in_progress')
    def progress(state):
        emit('phase', stage='registration_code' if state.get('need_code') else 'registration_form')
    try:
        tool.run(email, password=password, mail_password=mail_password, socks_port=None,
            selected_profile='recovered-release', timeout=300, accept_required_terms=True, _progress=progress)
    except BaseException:
        store.registration_status(args.account, 'unconfirmed')
        raise
    finally:
        password = mail_password = None
    store.registration_status(args.account, 'registered')
    emit('result', status='stopped', message='Регистрация Netmarble подтверждена. Можно загрузить серверы и войти.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--store', required=True, type=Path)
    parser.add_argument('--account', required=True)
    parser.add_argument('--operation', choices=['servers', 'characters', 'start', 'register'], required=True)
    parser.add_argument('--accept-required-terms', action='store_true')
    try:
        run(parser.parse_args())
    except Exception as error:
        # Messages from networking / auth helpers may contain sensitive values.
        emit('result', status='error', message='Операция не завершена: ' + type(error).__name__)
        raise SystemExit(2)
