"""Fresh lobby list -> exact diagnostic targets; never open a game socket."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.socks_route import SocksRoute


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def endpoint_line(host, port):
    if (type(host) is not str or not re.fullmatch(r'[a-zA-Z0-9.-]{1,253}', host) or
            type(port) is not int or not 1 <= port <= 65535):
        raise ValueError('Unsupported diagnostic endpoint')
    return host + ':' + str(port)


def run(email, *, manifest_path, socks_port, server_id, region, output, password='', _progress=None):
    if type(server_id) is not int or not 1 <= server_id <= 0xffffffff:
        raise ValueError('Explicit server ID required')
    if region not in ('KR', 'ASIA', 'TW', 'JP'): raise ValueError('Explicit region required')
    output = Path(output).resolve()
    evidence = output.with_suffix(output.suffix + '.json')
    if output.exists() or evidence.exists(): raise ValueError('Filter output already exists')
    route = SocksRoute(socks_port)
    source = module('capture_source', 'game-source-profile.py')
    profile = source.load_profile(selected_profile='recovered-base')
    lobby_endpoint = module('capture_lobby_endpoint', 'probe-lobby-connection.py').selected_endpoint(manifest_path, route=route)
    manifest_digest = hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest()
    country = {}
    def consume_auth(**values):
        country['value'] = values['sdk_data'].joined_country_code
    lobby = module('capture_lobby', 'probe-lobby-sdk-login.py').run(email,
        selected_profile='recovered-base', manifest_path=manifest_path, socks_port=socks_port,
        context='sdk-without-nid-info', password=password, read_server_list=True,
        server_policy_byte=0, auth_flow='launcher', _progress=_progress, _consume_auth=consume_auth)
    password = None
    if lobby.server_list_response is None or lobby.summary.get('login_result_code') != 0 or 'value' not in country:
        raise ValueError('Successful fresh lobby list required')
    target = module('capture_target', 'probe-selected-game-version.py').choose_target(
        lobby.server_list_response, server_id=server_id, region=region, joined_country_code=country['value'])
    lines = list(dict.fromkeys((endpoint_line(*lobby_endpoint), endpoint_line(target.host, target.port))))
    content = ('\n'.join(lines) + '\n').encode('ascii')
    if hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest() != manifest_digest:
        raise ValueError('CDN manifest changed during filter preparation')
    proof = dict(version=1, created_utc=datetime.now(timezone.utc).isoformat(),
        server_id=target.server_id, group_id=target.group_id, region=region,
        source_exe_sha256=source.SOURCE_SHA, app_version=profile.app_version,
        cdn_manifest_sha256=manifest_digest,
        filter_sha256=hashlib.sha256(content).hexdigest(), endpoint_count=len(lines),
        target_source='fresh_lobby_id104', auth_flow='launcher', game_connection_opened=False,
        game_login_sent=False, capture_started=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('xb') as stream: stream.write(content)
    with evidence.open('x', encoding='utf-8') as stream: stream.write(json.dumps(proof, indent=2) + '\n')
    # No endpoint, account ID, SDK body or token in stdout.
    return dict(status='diagnostic_filter_prepared', endpoint_count=len(lines),
        selected_server_id=target.server_id, selected_group_id=target.group_id,
        filter_sha256=proof['filter_sha256'], game_connection_opened=False,
        game_login_sent=False, capture_started=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--email', required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--socks-port', type=int, required=True)
    parser.add_argument('--server-id', type=int, required=True)
    parser.add_argument('--region', choices=('KR', 'ASIA', 'TW', 'JP'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--password-stdin', action='store_true')
    args = parser.parse_args()
    try:
        password = sys.stdin.readline(258).rstrip('\r\n') if args.password_stdin else ''
        if args.password_stdin and (not password or len(password) > 256): raise ValueError('Invalid secret input')
        value = run(args.email, manifest_path=args.manifest, socks_port=args.socks_port,
            server_id=args.server_id, region=args.region, output=args.output, password=password,
            _progress=lambda stage: print(json.dumps(dict(event='phase', stage=stage)), file=sys.stderr, flush=True))
        password = None
        print(json.dumps(value))
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(json.dumps(dict(status='diagnostic_filter_not_prepared', error_type=type(error).__name__, game_login_sent=False)))
        sys.exit(2)
