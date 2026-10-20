"""Fresh SDK/lobby list -> one explicit-policy game endpoint -> Version only."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
sys.path.insert(0, str(HERE.parents[1] / '.tools/vampir-python-runtime'))
from vampir_core.game_server_target import select_game_server_target, select_game_server_in_region
from vampir_core.device_registry import DeviceRegistry
from vampir_core.socks_route import SocksRoute
from vampir_core.version_probe import exchange_version


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def choose_target(server_list, *, server_id=None, selection=None, region=None, joined_country_code=None):
    if (server_id is None) == (selection is None): raise ValueError('Choose one explicit server selection policy')
    if selection is not None and selection != 'lowest-valid-id': raise ValueError('Unsupported local server selection policy')
    if region is not None:
        return select_game_server_in_region(server_list, region=region, server_id=server_id,
            joined_country_code=joined_country_code)
    if server_id is not None: return select_game_server_target(server_list, server_id=server_id)
    if selection != 'lowest-valid-id': raise ValueError('Unsupported local server selection policy')
    # A local diagnostic policy, not native availability/region/character logic.
    for identifier in sorted({record.u32[1] for record in server_list.servers}):
        try: return select_game_server_target(server_list, server_id=identifier)
        except ValueError: continue
    raise ValueError('No supported unique public game target')


def run(email, *, selected_profile, manifest_path, socks_port, password='', server_policy_byte,
        server_id=None, selection=None, _progress=None):
    # Validate policy before auth or network.
    if (server_id is None) == (selection is None): raise ValueError('Explicit server selection required')
    if selection is not None and selection != 'lowest-valid-id': raise ValueError('Unsupported selection policy')
    if server_id is not None and (type(server_id) is not int or not 1 <= server_id <= 0xffffffff):
        raise ValueError('Invalid explicit server ID')
    state = dict(stage='source_validation', game_login_sent=False)
    def phase(value):
        state['stage'] = value
        if _progress: _progress(value)
    try:
        return _run(email, selected_profile=selected_profile, manifest_path=manifest_path,
            socks_port=socks_port, password=password, server_policy_byte=server_policy_byte,
            server_id=server_id, selection=selection, phase=phase, state=state)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        # Exception messages may contain remote data or auth context. Keep only
        # the local phase, fixed exception type and already redacted summaries.
        return dict(state, status='selected_game_version_not_completed', error_type=type(error).__name__)


def _run(email, *, selected_profile, manifest_path, socks_port, password, server_policy_byte,
         server_id, selection, phase, state):
    phase('source_validation')
    source = module('selected_game_profile', 'game-source-profile.py').load_profile(selected_profile=selected_profile)
    phase('lobby_preparation')
    lobby = module('selected_game_lobby', 'probe-lobby-sdk-login.py').run(email,
        selected_profile=selected_profile, manifest_path=manifest_path, socks_port=socks_port,
        context='sdk-without-nid-info', password=password, read_server_list=True,
        server_policy_byte=server_policy_byte, _progress=phase)
    password = None
    state['lobby'] = lobby.summary
    if lobby.server_list_response is None:
        return dict(status='lobby_list_not_received', lobby=lobby.summary, game_login_sent=False)
    phase('game_target_selection')
    target = choose_target(lobby.server_list_response, server_id=server_id, selection=selection)
    state.update(selected_server_id=target.server_id, selected_group_id=target.group_id)
    phase('game_system_inputs')
    binding = DeviceRegistry(HERE / '.local/accounts.sqlite3').get(email)
    inputs = module('selected_game_system', 'windows-system-inputs.py')
    cpu, windows = inputs.observe_inputs()
    prepare = module('selected_game_payload', 'probe-game-version.py').prepare_version
    phase('game_connect')
    connection = SocksRoute(socks_port).connect(target.host, target.port, timeout=10)
    try:
        version = prepare(app_version=source.app_version, nm_device_key=binding.nm_device_key,
            local_address=connection.getsockname()[0], cpu=cpu, windows_version=windows)
        phase('game_version_exchange')
        summary = exchange_version(connection, version, timeout=10)
        return dict(status='game_version_probe', selection=selection or 'explicit-id',
            selected_server_id=target.server_id, selected_group_id=target.group_id,
            target_source='fresh_lobby_id104', lobby=lobby.summary, game=summary)
    finally: connection.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--email', required=True)
    parser.add_argument('--profile', choices=['recovered-base'], required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--socks-port', type=int, required=True)
    parser.add_argument('--server-policy-byte', type=int, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--server-id', type=int)
    choice.add_argument('--selection', choices=['lowest-valid-id'])
    parser.add_argument('--password-stdin', action='store_true')
    args = parser.parse_args()
    try:
        password = sys.stdin.readline(258).rstrip('\r\n') if args.password_stdin else ''
        if args.password_stdin and (not password or len(password) > 256): raise ValueError('Invalid password input')
        result = run(args.email, selected_profile=args.profile, manifest_path=args.manifest,
            socks_port=args.socks_port, server_policy_byte=args.server_policy_byte,
            server_id=args.server_id, selection=args.selection, password=password,
            _progress=lambda stage: print(json.dumps(dict(event='phase', stage=stage)), file=sys.stderr, flush=True))
        password = None
        print(json.dumps(result))
        if result['status'] == 'selected_game_version_not_completed': sys.exit(2)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(json.dumps(dict(status='selected_game_version_not_completed', error_type=type(error).__name__,
            game_login_sent=False)))
        sys.exit(2)
