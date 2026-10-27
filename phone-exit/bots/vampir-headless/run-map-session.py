"""Explicit bounded headless session with a read-only atlas feed on loopback."""
import argparse
import getpass
import importlib.util
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'vampir-shared'))
from vampir_core.map_session import MapSession,MapSessionServer
from vampir_core.world_move_start import SOURCE_SHA256


def run(args,password,*,tutorial_observer=None):
    persistent=getattr(args,'persistent',False)
    selected_profile=getattr(args,'profile','recovered-release')
    if selected_profile=='candidate-11318':
        spec=importlib.util.spec_from_file_location('map_source_preflight',HERE/'game-source-profile.py')
        source=importlib.util.module_from_spec(spec);spec.loader.exec_module(source)
        source.load_profile(selected_profile=selected_profile)
        if args.projection is not None:raise ValueError('Проекция карты 1.13.18 ещё не подтверждена')
    projection=None
    if args.projection is not None:
        from vampir_core.map_projection_input import load_projection
        from vampir_core.world_move_start import CURRENT_PROBE_SOURCE
        selected_source=CURRENT_PROBE_SOURCE if getattr(args,'profile','recovered-release')=='candidate-11316' else SOURCE_SHA256
        projection=load_projection(args.projection,source_sha256=selected_source)
    if not persistent and projection is None:
        raise ValueError('Bounded atlas feed requires a verified projection')
    if persistent:
        from vampir_core.live_session import LiveSession
        from vampir_core.live_session_server import LiveSessionServer
        session=LiveSession(bot_id=args.bot_id,projection=projection)
        server_type=LiveSessionServer
    else:
        session=MapSession(projection)
        server_type=MapSessionServer
    def observe(position):
        if position is None:session.disconnect()
        else:session.update(position)
    spec=importlib.util.spec_from_file_location('map_session_probe',HERE/'probe-selected-game-login.py')
    probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
    with server_type(session):
        print(json.dumps(dict(event='map_feed_ready',port=17947)),flush=True)
        return probe.run(args.email,selected_profile=getattr(args,'profile','recovered-release'),manifest_path=args.manifest,
            socks_port=args.socks_port,server_policy_byte=0,extra_number=args.client_version,
            context='windows-sdk-initial-reset',region=args.region,server_id=args.server_id,
            password=password,auth_flow='launcher',language_code=1,lobby_context='sdk-with-partial-metadata',
            read_character_list=True,character_index=args.character_index,read_world_start=True,
            read_world_finish=True,observe_world_seconds=300 if persistent else args.seconds,world_observer=None if persistent else observe,
            session_control=session if persistent else None,
            tutorial_observer=tutorial_observer,
            _progress=lambda stage:print(json.dumps(dict(event='phase',stage=stage)),flush=True))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--email',required=True)
    parser.add_argument('--manifest',required=True,type=Path)
    parser.add_argument('--projection',type=Path,help='Explicit source-matching immutable atlas projection audit')
    parser.add_argument('--socks-port',required=True,type=int)
    parser.add_argument('--client-version',required=True,type=int)
    parser.add_argument('--server-id',required=True,type=int)
    parser.add_argument('--character-index',required=True,type=int)
    parser.add_argument('--region',choices=['JP','HK'],required=True)
    parser.add_argument('--seconds',type=float,default=60)
    parser.add_argument('--bot-id',help='Opaque UI bot identity; credentials are never used as UI identity')
    parser.add_argument('--persistent',action='store_true',help='Keep this owned session until explicit Stop or transport loss; no reconnect')
    parser.add_argument('--profile',choices=['recovered-release','candidate-11316','candidate-11318'],default='recovered-release')
    args=parser.parse_args()
    try:
        if not 0<args.seconds<=300:raise ValueError('Bounded session duration required')
        if args.persistent and not args.bot_id:raise ValueError('Explicit --bot-id required for persistent session')
        if args.profile=='candidate-11318':
            spec=importlib.util.spec_from_file_location('map_cli_source',HERE/'game-source-profile.py')
            source=importlib.util.module_from_spec(spec);spec.loader.exec_module(source)
            source.load_profile(selected_profile=args.profile)
            if args.projection is not None:raise ValueError('Проекция карты 1.13.18 ещё не подтверждена')
        password=getpass.getpass('Bot password: ')
        result=run(args,password);password=None
        print(json.dumps(result,ensure_ascii=False))
    except (OSError,ValueError,RuntimeError,KeyError) as error:
        print(json.dumps(dict(status='map_session_failed',error_type=type(error).__name__)))
        sys.exit(2)
