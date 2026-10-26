"""Явный запуск нескольких аккаунтов с общим loopback API и раздельными сессиями."""
import argparse
from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor, as_completed
import getpass
import importlib.util
import json
import os
from pathlib import Path
import sys
from threading import BoundedSemaphore, Timer

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'vampir-shared'))
from vampir_core.live_session import LiveSession,LiveSessions
from vampir_core.live_session_server import LiveSessionServer


def validate_accounts(value):
    fields={'bot_id','email','socks_port','region','server_id','character_index'}
    if not isinstance(value,list) or not 1<=len(value)<=50:
        raise ValueError('Нужен список из 1–50 аккаунтов')
    bots=set();emails=set()
    for row in value:
        if not isinstance(row,dict) or set(row)!=fields:raise ValueError('Неверные поля аккаунта; пароли в JSON запрещены')
        LiveSession(bot_id=row['bot_id'])
        email=row['email']
        if not isinstance(email,str) or len(email)>254 or email.count('@')!=1 or any(c.isspace() for c in email):
            raise ValueError('Неверный email')
        if row['bot_id'] in bots or email.lower() in emails:raise ValueError('Повторный бот или аккаунт')
        bots.add(row['bot_id']);emails.add(email.lower())
        for key,lower,upper in [('socks_port',1024,65535),('server_id',1,0xffffffff),('character_index',0,65535)]:
            if type(row[key]) is not int or not lower<=row[key]<=upper:raise ValueError('Неверный '+key)
        if row['region'] not in ('HK','JP'):raise ValueError('Неверный регион')
    return value


def run_accounts(accounts,passwords,*,manifest,client_version,profile='candidate-11316',probe=None,port=17947,sign_in_parallelism=2,projection=None,ready_callback=None,max_runtime_seconds=None):
    accounts=validate_accounts(accounts)
    if max_runtime_seconds is not None and (type(max_runtime_seconds) is not int or not 1<=max_runtime_seconds<=86400):
        raise ValueError('Срок отдельного запуска должен быть 1–86400 секунд')
    if type(sign_in_parallelism) is not int or not 1<=sign_in_parallelism<=8:raise ValueError('Параллельных входов должно быть 1–8')
    sign_in_slots=BoundedSemaphore(sign_in_parallelism)
    if set(passwords)!={row['bot_id'] for row in accounts} or any(not isinstance(p,str) or not p for p in passwords.values()):
        raise ValueError('Нужен пароль каждого выбранного аккаунта')
    if probe is None:
        spec=importlib.util.spec_from_file_location('live_selected_probe',HERE/'probe-selected-game-login.py')
        probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
    registry=LiveSessions(capacity=len(accounts))
    sessions={row['bot_id']:LiveSession(bot_id=row['bot_id'],projection=projection) for row in accounts}
    for session in sessions.values():registry.attach(session)
    def emit(value):print(json.dumps(value,ensure_ascii=False),flush=True)
    def worker(row):
        bot=row['bot_id'];session=sessions[bot]
        password=None;permit=False
        def release_sign_in():
            nonlocal permit
            if permit:permit=False;sign_in_slots.release()
        def progress(stage):
            # Keep all world connections running, while limiting simultaneous
            # SDK/browser setup. This stage runs after the browser is closed.
            if stage=='game_login_exchange':release_sign_in()
            emit(dict(event='phase',bot_id=bot,stage=stage))
        try:
            while not session.stop_requested:
                if sign_in_slots.acquire(timeout=.1):permit=True;break
            if session.stop_requested:return dict(bot_id=bot,status='session_stopped')
            password=passwords.pop(bot)
            result=probe.run(row['email'],password=password,selected_profile=profile,
                manifest_path=manifest,socks_port=row['socks_port'],server_policy_byte=0,
                extra_number=client_version,context='windows-sdk-initial-reset',region=row['region'],
                server_id=row['server_id'],auth_flow='launcher',language_code=1,
                lobby_context='sdk-with-partial-metadata',read_character_list=True,
                character_index=row['character_index'],read_world_start=True,read_world_finish=True,
                observe_world_seconds=300,session_control=session,
                _progress=progress)
            game=result.get('game',{})
            session.close(game.get('login_result_key') if game.get('login_result_code') not in (None,0) else game.get('error'))
            return dict(bot_id=bot,status=result.get('status'),game_status=game.get('status'),
                login_result_code=game.get('login_result_code'),login_result_key=game.get('login_result_key'))
        except Exception as error:
            return dict(bot_id=bot,status='failed',error_type=type(error).__name__)
        finally:
            release_sign_in();password=None;session.close()
    summaries=[]
    # API outlives every owned worker; Ctrl+C asks all owners to stop and joins them.
    with ExitStack() as resources:
        server=resources.enter_context(LiveSessionServer(registry,port=port))
        if max_runtime_seconds is not None:
            lifetime=Timer(max_runtime_seconds,registry.close);lifetime.daemon=True
            resources.callback(lifetime.cancel);lifetime.start()
        ready=dict(event='live_api_ready',port=server.server.server_port,sessions=registry.list(),
            ui_urls=[dict(bot_id=session.bot_id,url='http://127.0.0.1:17946/maps/ui-prototype/index.html?mode=live&bot='+session.bot_id+'&session='+session.session_id)
                for session in sessions.values()])
        if ready_callback is not None:ready_callback(ready)
        emit(ready)
        with ThreadPoolExecutor(max_workers=len(accounts),thread_name_prefix='vampir-live') as pool:
            futures=[]
            try:
                for row in accounts:futures.append(pool.submit(worker,row))
                for future in as_completed(futures):
                    summary=future.result();summaries.append(summary);emit(summary)
            finally:
                registry.close();passwords.clear()
    return summaries


def launch_options(options,passwords,*,ready_callback=None):
    fields={'accounts','manifest','client_version','projection','sign_in_parallelism','port','max_runtime_seconds','result_path'}
    if type(options) is not dict or set(options)!=fields:raise ValueError('Неверные параметры владельца')
    if type(options['client_version']) is not int or not 0<=options['client_version']<=0xffffffff:
        raise ValueError('Неверная версия клиента')
    if type(options['port']) is not int or not 1024<=options['port']<=65535:raise ValueError('Неверный порт API')
    if type(options['manifest']) is not str or not Path(options['manifest']).is_file():raise ValueError('Нужен manifest')
    result_path=options['result_path']
    if result_path is not None:
        if type(result_path) is not str:raise ValueError('Неверный путь результата')
        result_path=Path(result_path)
        if result_path.exists() or not result_path.parent.is_dir():raise ValueError('Нужен новый файл результата в существующем каталоге')
    projection=None
    if options['projection'] is not None:
        if type(options['projection']) is not str:raise ValueError('Неверный manifest проекции')
        from vampir_core.map_projection_input import load_projection
        from vampir_core.world_move_start import CURRENT_PROBE_SOURCE
        projection=load_projection(Path(options['projection']),source_sha256=CURRENT_PROBE_SOURCE)
    result=run_accounts(options['accounts'],passwords,manifest=Path(options['manifest']),
        client_version=options['client_version'],sign_in_parallelism=options['sign_in_parallelism'],
        projection=projection,port=options['port'],max_runtime_seconds=options['max_runtime_seconds'],ready_callback=ready_callback)
    if result_path is not None:
        # Explicit opt-in only: bounded terminal status, no credentials, packet
        # bodies, account email or traffic content. Never replace an older file.
        text=json.dumps(dict(status='finished',results=result),ensure_ascii=False)
        if len(text.encode('utf-8'))>65536:raise ValueError('Результат превышает лимит')
        with result_path.open('x',encoding='utf-8') as stream:stream.write(text+'\n')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accounts',type=Path)
    parser.add_argument('--manifest',type=Path)
    parser.add_argument('--client-version',type=int)
    parser.add_argument('--projection',type=Path,help='Проверенный manifest проекции для текущей версии клиента')
    parser.add_argument('--sign-in-parallelism',type=int,default=2,help='Одновременные SDK-входы; все вошедшие боты остаются активны')
    parser.add_argument('--port',type=int,default=17947)
    parser.add_argument('--result',type=Path,help='Новый файл итоговых кодов после завершения, без паролей и содержимого трафика')
    modes=parser.add_mutually_exclusive_group()
    modes.add_argument('--detached',action='store_true',help='Windows: одноразовая задача текущего пользователя вне дерева Codex; пароли только через anonymous pipe')
    modes.add_argument('--detached-worker',action='store_true',help=argparse.SUPPRESS)
    args=parser.parse_args()
    passwords={};startup=None;announced=False
    try:
        if args.detached_worker:
            from vampir_core.detached_worker import ready_channel,receive_handoff
            startup=ready_channel()
            payload=receive_handoff(sys.stdin.buffer)
            if set(payload)!={'options','passwords'} or type(payload['passwords']) is not dict:raise ValueError('Неверный stdin владельца')
            passwords=payload.pop('passwords');options=payload.pop('options')
            def on_ready(value):
                nonlocal announced
                startup(dict(status='ready',pid=os.getpid(),**value));announced=True
            launch_options(options,passwords,ready_callback=on_ready)
            return
        if args.accounts is None or args.manifest is None or args.client_version is None:
            parser.error('Нужны --accounts, --manifest и --client-version')
        if args.accounts.stat().st_size>65536:raise ValueError('Слишком большой список аккаунтов')
        accounts=validate_accounts(json.loads(args.accounts.read_text(encoding='utf-8')))
        options=dict(accounts=accounts,manifest=str(args.manifest.resolve()),client_version=args.client_version,
            projection=str(args.projection.resolve()) if args.projection else None,
            sign_in_parallelism=args.sign_in_parallelism,port=args.port,max_runtime_seconds=86400 if args.detached else None,
            result_path=str(args.result.resolve()) if args.result else None)
        passwords={row['bot_id']:getpass.getpass('Пароль '+row['bot_id']+': ') for row in accounts}
        if args.detached:
            from vampir_core.scheduled_worker import launch_scheduled
            notice=launch_scheduled([sys.executable,'-X','utf8',str(Path(__file__).resolve()),'--detached-worker'],
                dict(options=options,passwords=passwords),cwd=str(HERE.parents[2]))
            print(json.dumps(notice,ensure_ascii=False),flush=True)
        else:launch_options(options,passwords)
    except KeyboardInterrupt:
        print('Запускающая консоль прервана; состояние отдельного владельца проверьте через API.' if args.detached else 'Сессии остановлены.')
    except (OSError,ValueError,RuntimeError) as error:
        if startup is not None and not announced:
            startup(dict(status='launch_failed',pid=os.getpid(),error_type=type(error).__name__))
        print(json.dumps(dict(status='launch_failed',error_type=type(error).__name__)),flush=True)
        sys.exit(2)
    finally:passwords.clear()


if __name__=='__main__':main()
