"""Явный запуск нескольких аккаунтов с общим loopback API и раздельными сессиями."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import getpass
import importlib.util
import json
from pathlib import Path
import sys

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


def run_accounts(accounts,passwords,*,manifest,client_version,profile='candidate-11316',probe=None,port=17947):
    accounts=validate_accounts(accounts)
    if set(passwords)!={row['bot_id'] for row in accounts} or any(not isinstance(p,str) or not p for p in passwords.values()):
        raise ValueError('Нужен пароль каждого выбранного аккаунта')
    if probe is None:
        spec=importlib.util.spec_from_file_location('live_selected_probe',HERE/'probe-selected-game-login.py')
        probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
    registry=LiveSessions(capacity=len(accounts))
    sessions={row['bot_id']:LiveSession(bot_id=row['bot_id']) for row in accounts}
    for session in sessions.values():registry.attach(session)
    def emit(value):print(json.dumps(value,ensure_ascii=False),flush=True)
    def worker(row):
        bot=row['bot_id'];session=sessions[bot]
        password=passwords.pop(bot)
        try:
            result=probe.run(row['email'],password=password,selected_profile=profile,
                manifest_path=manifest,socks_port=row['socks_port'],server_policy_byte=0,
                extra_number=client_version,context='windows-sdk-initial-reset',region=row['region'],
                server_id=row['server_id'],auth_flow='launcher',language_code=1,
                lobby_context='sdk-with-partial-metadata',read_character_list=True,
                character_index=row['character_index'],read_world_start=True,read_world_finish=True,
                observe_world_seconds=300,session_control=session,
                _progress=lambda stage:emit(dict(event='phase',bot_id=bot,stage=stage)))
            game=result.get('game',{})
            session.close(game.get('login_result_key') if game.get('login_result_code') not in (None,0) else game.get('error'))
            return dict(bot_id=bot,status=result.get('status'),game_status=game.get('status'),
                login_result_code=game.get('login_result_code'),login_result_key=game.get('login_result_key'))
        except Exception as error:
            return dict(bot_id=bot,status='failed',error_type=type(error).__name__)
        finally:
            password=None;session.close()
    summaries=[]
    # API outlives every owned worker; Ctrl+C asks all owners to stop and joins them.
    with LiveSessionServer(registry,port=port) as server:
        emit(dict(event='live_api_ready',port=server.server.server_port,sessions=registry.list()))
        with ThreadPoolExecutor(max_workers=len(accounts),thread_name_prefix='vampir-live') as pool:
            futures=[pool.submit(worker,row) for row in accounts]
            try:
                for future in as_completed(futures):
                    summary=future.result();summaries.append(summary);emit(summary)
            finally:
                registry.close();passwords.clear()
    return summaries


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accounts',type=Path,required=True)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--client-version',type=int,required=True)
    args=parser.parse_args()
    try:
        if args.accounts.stat().st_size>65536:raise ValueError('Слишком большой список аккаунтов')
        accounts=validate_accounts(json.loads(args.accounts.read_text(encoding='utf-8')))
        passwords={row['bot_id']:getpass.getpass('Пароль '+row['bot_id']+': ') for row in accounts}
        run_accounts(accounts,passwords,manifest=args.manifest,client_version=args.client_version)
    except KeyboardInterrupt:
        print('Сессии остановлены.')
    except (OSError,ValueError) as error:
        print(json.dumps(dict(status='launch_failed',error_type=type(error).__name__)),flush=True)
        sys.exit(2)
