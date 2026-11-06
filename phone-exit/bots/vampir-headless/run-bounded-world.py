"""Assigned current characters with a detached loopback session owner."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from datetime import datetime, timezone
import importlib.util
import http.client
import json
import os
from pathlib import Path
import sys
from threading import BoundedSemaphore

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
STORE = HERE / '.local/console.sqlite3'
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.account_store import AccountStore
from vampir_core.bounded_world_admission import scope, current
from vampir_core.live_session import LiveSession, LiveSessions
from vampir_core.live_session_server import LiveSessionServer


def load_entry():
    spec = importlib.util.spec_from_file_location('bounded_world_parent_entry', HERE / 'run-bounded-entry.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_accounts(identifiers, store):
    if (not isinstance(identifiers, list) or not 1 <= len(identifiers) <= 50
            or any(type(value) is not str for value in identifiers) or len(set(identifiers)) != len(identifiers)):
        raise ValueError('Expected one to fifty unique assigned accounts')
    rows = {row['id']: row for row in store.accounts()}
    for identifier in identifiers:
        row = rows.get(identifier)
        if (row is None or row['enabled'] is not True or row['device_type'] == 'Не использовать'
                or row['server_id'] is None or row['character_index'] is None or row['character_key'] is None
                or row['auth_flow'] != 'launcher'):
            raise ValueError('World entry requires enabled accounts with saved character identities')
    return identifiers


def existing_owner(identifiers, port):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('Explicit loopback port required')
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    try:
        connection.request('GET', '/sessions')
        with connection.getresponse() as response:
            if response.status != 200:
                raise ValueError('The selected API port belongs to another service')
            raw = response.read(65537)
    except ConnectionRefusedError:
        return None
    finally:
        connection.close()
    if len(raw) > 65536:
        raise ValueError('Existing owner status exceeds budget')
    value = json.loads(raw)
    rows = value.get('sessions') if isinstance(value, dict) else None
    if (not isinstance(rows, list) or {row.get('bot_id') for row in rows if isinstance(row, dict)} != set(identifiers)
            or len(rows) != len(identifiers)):
        raise ValueError('The selected API port has a different session owner')
    return dict(status='existing_owner', port=port, sessions=rows)


def run(identifiers, selector, *, port=17947, store_path=STORE, ready_callback=lambda value: None):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('Explicit loopback port required')
    store = AccountStore(store_path)
    validate_accounts(identifiers, store)
    with scope(selector, root=ROOT, workspace=HERE.parents[2]):
        profile = current(selector)
    registry = LiveSessions(capacity=len(identifiers))
    sessions = {identifier: LiveSession(bot_id=identifier, keep_online=True) for identifier in identifiers}
    for session in sessions.values():
        registry.attach(session)
    sign_in_slots = BoundedSemaphore(2)
    def worker(identifier):
        session = sessions[identifier]
        slot = False
        def release_sign_in():
            nonlocal slot
            if slot:
                slot = False
                sign_in_slots.release()
        def progress(stage):
            if stage == 'game_login_exchange':
                release_sign_in()
        try:
            while not session.stop_requested and not slot:
                slot = sign_in_slots.acquire(timeout=.1)
            if session.stop_requested:
                return dict(account_id=identifier, status='session_stopped')
            # Every worker validates and enters its own immutable context.
            with scope(selector, root=ROOT, workspace=HERE.parents[2]):
                result = load_entry().run(identifier, profile['entry']['selected_profile'],
                    _world_session=session, progress=progress, _store=store)['result']
                game = result.get('game', {})
                if result.get('status') == 'selected_game_login_not_completed' and not session.stop_requested:
                    session.close(result.get('verification_status') or result.get('stage') or 'world_entry_not_completed')
                return dict(account_id=identifier, status=result.get('status'), stage=result.get('stage'),
                    verification_status=result.get('verification_status'), sdk_error_code=result.get('sdk_error_code'),
                    game_status=game.get('status'), login_result_code=game.get('login_result_code'),
                    character_select_result_code=game.get('character_select_result_code'),
                    world_finish_result_code=game.get('world_finish_result_code'),
                    periodic_ping_queued=game.get('periodic_ping_queued'),
                    ping_results_received=game.get('ping_results_received'))
        except (ValueError, RuntimeError, OSError, KeyError) as error:
            if not session.stop_requested:
                session.close('world_entry_not_completed')
            return dict(account_id=identifier, status='world_entry_not_completed', error_type=type(error).__name__)
        finally:
            release_sign_in()
            session.close()
    summaries = []
    with ExitStack() as resources:
        server = resources.enter_context(LiveSessionServer(registry, port=port))
        ready_callback(dict(status='ready', pid=os.getpid(), port=server.server.server_port,
            sessions=registry.list(), keep_online=True, max_runtime_seconds=None, selected_profile=selector))
        with ThreadPoolExecutor(max_workers=len(identifiers), thread_name_prefix='vampir-current-world') as pool:
            try:
                for future in as_completed([pool.submit(worker, identifier) for identifier in identifiers]):
                    summaries.append(future.result())
            finally:
                registry.close()
    return dict(completed_utc=datetime.now(timezone.utc).isoformat(), sessions=summaries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account', action='append')
    parser.add_argument('--profile')
    parser.add_argument('--port', type=int, default=17947)
    parser.add_argument('--store', type=Path, default=STORE)
    parser.add_argument('--output', type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--detached', action='store_true')
    mode.add_argument('--detached-worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    readiness, announced = None, False
    try:
        if args.detached_worker:
            from vampir_core.detached_worker import ready_channel, receive_handoff
            readiness = ready_channel()
            options = receive_handoff(sys.stdin.buffer)
            if not isinstance(options, dict) or set(options) != {'accounts', 'profile', 'port', 'output', 'store'}:
                raise ValueError('Invalid current world owner handoff')
        else:
            if args.account is None or args.profile is None:
                parser.error('Нужны --account и --profile')
            store = args.store.resolve(strict=True)
            if not store.is_file():
                raise ValueError('Expected the saved console database')
            options = dict(accounts=args.account, profile=args.profile, port=args.port, store=str(store),
                           output=str(args.output.resolve()) if args.output else None)
            with scope(args.profile, root=ROOT, workspace=HERE.parents[2]):
                validate_accounts(args.account, AccountStore(store))
            existing = existing_owner(args.account, args.port)
            if existing is not None:
                print(json.dumps(existing, ensure_ascii=False), flush=True)
                return
            if args.detached:
                from vampir_core.scheduled_worker import launch_scheduled
                result = launch_scheduled([sys.executable, '-X', 'utf8', str(Path(__file__).resolve()), '--detached-worker'],
                    options, cwd=str(HERE.parents[2]), unlimited=True)
                print(json.dumps(result, ensure_ascii=False), flush=True)
                return
        def ready(value):
            nonlocal announced
            if readiness is not None:
                readiness(value)
            else:
                print(json.dumps(value, ensure_ascii=False), flush=True)
            announced = True
        if options['output'] is not None:
            path = Path(options['output'])
            if path.exists() or not path.parent.is_dir():
                raise ValueError('Expected a new result file in an existing directory')
        result = run(options['accounts'], options['profile'], port=options['port'],
                     store_path=options['store'], ready_callback=ready)
        if options['output'] is not None:
            path = Path(options['output'])
            with path.open('x', encoding='utf-8') as stream:
                json.dump(result, stream, ensure_ascii=False, indent=2)
                stream.write('\n')
    except (ValueError, RuntimeError, OSError, KeyError) as error:
        result = dict(status='launch_failed', error_type=type(error).__name__)
        if readiness is not None and not announced:
            readiness(dict(result, pid=os.getpid()))
        else:
            print(json.dumps(result), flush=True)
        raise SystemExit(2)


if __name__ == '__main__':
    main()
