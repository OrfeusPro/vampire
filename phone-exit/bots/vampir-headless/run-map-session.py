"""Explicit bounded headless session with a read-only atlas feed on loopback."""
import argparse
import getpass
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'vampir-shared'))
from vampir_core.map_position import MapProjection
from vampir_core.map_session import MapSession,MapSessionServer
from vampir_core.world_move_start import SOURCE_SHA256


def run(args,password):
    raw=args.projection.read_bytes()
    if len(raw)>1048576 or hashlib.sha256(raw).hexdigest()!=args.projection.parent.name:
        raise ValueError('Immutable projection audit required')
    manifest=json.loads(raw)
    projection=MapProjection(manifest,source_sha256=SOURCE_SHA256)
    # Verify the installed resource used by this audit, not only its old snapshot.
    archive=manifest['installed_archive']
    with Path(archive['path']).open('rb') as stream:
        if hashlib.file_digest(stream,'sha256').hexdigest()!=archive['sha256']:
            raise ValueError('Map resource changed since audit')
    session=MapSession(projection)
    def observe(position):
        if position is None:session.disconnect()
        else:session.update(position)
    spec=importlib.util.spec_from_file_location('map_session_probe',HERE/'probe-selected-game-login.py')
    probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
    with MapSessionServer(session):
        print(json.dumps(dict(event='map_feed_ready',port=17947)),flush=True)
        return probe.run(args.email,selected_profile='recovered-release',manifest_path=args.manifest,
            socks_port=args.socks_port,server_policy_byte=0,extra_number=args.client_version,
            context='windows-sdk-initial-reset',region=args.region,server_id=args.server_id,
            password=password,auth_flow='launcher',language_code=1,lobby_context='sdk-with-partial-metadata',
            read_character_list=True,character_index=args.character_index,read_world_start=True,
            read_world_finish=True,observe_world_seconds=args.seconds,world_observer=observe,
            _progress=lambda stage:print(json.dumps(dict(event='phase',stage=stage)),flush=True))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--email',required=True)
    parser.add_argument('--manifest',required=True,type=Path)
    parser.add_argument('--projection',required=True,type=Path)
    parser.add_argument('--socks-port',required=True,type=int)
    parser.add_argument('--client-version',required=True,type=int)
    parser.add_argument('--server-id',required=True,type=int)
    parser.add_argument('--character-index',required=True,type=int)
    parser.add_argument('--region',choices=['JP','HK'],required=True)
    parser.add_argument('--seconds',type=float,default=60)
    args=parser.parse_args()
    try:
        if not 0<args.seconds<=300:raise ValueError('Bounded session duration required')
        password=getpass.getpass('Bot password: ')
        result=run(args,password);password=None
        print(json.dumps(result,ensure_ascii=False))
    except (OSError,ValueError,RuntimeError,KeyError) as error:
        print(json.dumps(dict(status='map_session_failed',error_type=type(error).__name__)))
        sys.exit(2)
