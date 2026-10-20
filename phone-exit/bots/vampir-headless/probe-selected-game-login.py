"""Fresh SDK/lobby context -> selected endpoint -> bounded Version/Login."""
import argparse
from dataclasses import dataclass, field
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
sys.path.insert(0, str(HERE.parents[1] / '.tools/vampir-python-runtime'))
from vampir_core.game_login_probe import exchange_game_login
from vampir_core.login_context import prepare_initial_windows_game_login
from vampir_core.socks_route import SocksRoute
from vampir_core.game_server_target import SERVER_REGION_CODES, is_game_server_state_excluded, game_server_allows_joined_country


@dataclass(frozen=True)
class AuthForGame:
    binding: object = field(repr=False)
    sdk_data: object = field(repr=False)
    netmarble_id: str = field(repr=False)


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def run(email, *, selected_profile, manifest_path, socks_port, server_policy_byte,
        extra_number, context, region, server_id=None, selection=None, password='', server_list_only=False, _progress=None):
    if type(server_list_only) is not bool: raise ValueError('Explicit server-list-only policy required')
    if type(region) is not str or region not in SERVER_REGION_CODES: raise ValueError('Explicit server region required')
    if context != 'windows-sdk-initial-reset': raise ValueError('Explicit game Login context required')
    if type(extra_number) is not int or not 0 <= extra_number <= 0xffffffff: raise ValueError('Explicit uint32 extra number required')
    if (server_id is None) == (selection is None): raise ValueError('One explicit selection policy required')
    if selection is not None and selection != 'lowest-valid-id': raise ValueError('Unsupported selection policy')
    if server_id is not None and (type(server_id) is not int or not 1 <= server_id <= 0xffffffff):
        raise ValueError('Invalid selected server ID')
    state = dict(stage='source_validation', game_session_ready=False)
    def phase(value):
        state['stage'] = value
        if _progress: _progress(value)
    try:
        return _run(email, selected_profile=selected_profile, manifest_path=manifest_path,
            socks_port=socks_port, server_policy_byte=server_policy_byte, extra_number=extra_number,
            context=context, region=region, server_id=server_id, selection=selection, password=password,
            server_list_only=server_list_only, state=state, phase=phase)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        result = dict(state, status='selected_game_login_not_completed', error_type=type(error).__name__)
        for name, attribute in (('http_status', 'status'), ('sdk_error_code', 'sdk_code')):
            if type(getattr(error, attribute, None)) is int: result[name] = getattr(error, attribute)
        for name, allowed in (('browser_status', ('timeout', 'cancelled', 'browser_initialization_failed',
                'browser_process_failed', 'untrusted_callback_origin', 'unknown')),
                ('sign_in_step', ('manual', 'waiting', 'opened_email', 'filled', 'submitted', 'form_changed', 'script_failed', 'unknown'))):
            value = getattr(error, name, None)
            if value in allowed: result[name] = value
        return result


def _run(email, *, selected_profile, manifest_path, socks_port, server_policy_byte,
         extra_number, context, region, server_id, selection, password, server_list_only, state, phase):
    phase('source_validation')
    source = module('game_login_source', 'game-source-profile.py').load_profile(selected_profile=selected_profile)
    auth = {}
    def consume(**values): auth['context'] = AuthForGame(**values)
    phase('lobby_preparation')
    lobby = module('game_login_lobby', 'probe-lobby-sdk-login.py').run(email,
        selected_profile=selected_profile, manifest_path=manifest_path, socks_port=socks_port,
        context='sdk-without-nid-info', password=password, read_server_list=True,
        server_policy_byte=server_policy_byte, _progress=phase, _consume_auth=consume)
    password = None
    state['lobby'] = lobby.summary
    if lobby.server_list_response is None or 'context' not in auth:
        return dict(state, status='lobby_context_not_received')
    credentials = auth.pop('context')
    phase('game_target_selection')
    # Public record flags only: never include host, text or array50 identities.
    groups = lobby.server_list_response.groups
    country = credentials.sdk_data.joined_country_code
    state['sdk_joined_country_code'] = (country.upper() if type(country) is str and len(country) == 2
        and country.isascii() and country.isalpha() else None)
    def country_status(record):
        try: return game_server_allows_joined_country(record, joined_country_code=country)
        except ValueError: return None
    state['region_server_states'] = [dict(server_id=r.u32[1], enums=r.enums, flags=r.flags,
        array50_count=len(r.array50), excluded_by_native_state=is_game_server_state_excluded(r),
        sdk_joined_country_allowed=country_status(r))
        for r in lobby.server_list_response.servers
        if len(matches := [g for g in groups if g.raw_08 == r.u32[0]]) == 1
        and matches[0].raw_20 == SERVER_REGION_CODES[region]]
    target = module('game_login_target', 'probe-selected-game-version.py').choose_target(
        lobby.server_list_response, server_id=server_id, selection=selection, region=region, joined_country_code=country)
    state.update(selected_server_id=target.server_id, selected_group_id=target.group_id, selected_region=region)
    if server_list_only:
        credentials = None
        return dict(state, status='server_country_policy_checked', game_login_sent=False)
    reference = [r for r in lobby.server_list_response.servers if r.u32[1] == 101]
    if len(reference) == 1:
        groups = [g for g in lobby.server_list_response.groups if g.raw_08 == reference[0].u32[0]]
        if len(groups) == 1: state['reference_server_101_region_code'] = groups[0].raw_20
    phase('game_system_inputs')
    cpu, windows = module('game_login_system', 'windows-system-inputs.py').observe_inputs()
    prepare_version = module('game_login_version', 'probe-game-version.py').prepare_version
    phase('game_connect')
    connection = SocksRoute(socks_port).connect(target.host, target.port, timeout=10)
    try:
        version = prepare_version(app_version=source.app_version, nm_device_key=credentials.binding.nm_device_key,
            local_address=connection.getsockname()[0], cpu=cpu, windows_version=windows)
        phase('game_login_preparation')
        login = prepare_initial_windows_game_login(version, binding=credentials.binding,
            sdk_data=credentials.sdk_data, netmarble_id=credentials.netmarble_id,
            lobby_result=lobby.response, server_id=target.server_id, extra_number=extra_number, context=context)
        credentials = None
        phase('game_login_exchange')
        game = exchange_game_login(connection, version, login, timeout=10)
        login = None
        return dict(state, status='game_login_probe', selection=selection or 'explicit-id',
            target_source='fresh_lobby_id104', context=context, extra_number=extra_number, game=game)
    finally:
        credentials = None
        connection.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--email', required=True)
    parser.add_argument('--profile', choices=['recovered-base'], required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--socks-port', type=int, required=True)
    parser.add_argument('--server-policy-byte', type=int, required=True)
    parser.add_argument('--extra-number', type=int, required=True)
    parser.add_argument('--context', choices=['windows-sdk-initial-reset'], required=True)
    parser.add_argument('--region', choices=list(SERVER_REGION_CODES), required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--server-id', type=int)
    choice.add_argument('--selection', choices=['lowest-valid-id'])
    parser.add_argument('--password-stdin', action='store_true')
    parser.add_argument('--server-list-only', action='store_true', help='Check region/state/country policy without a game connection')
    args = parser.parse_args()
    try:
        password = sys.stdin.readline(258).rstrip('\r\n') if args.password_stdin else ''
        if args.password_stdin and (not password or len(password) > 256): raise ValueError('Invalid password input')
        result = run(args.email, selected_profile=args.profile, manifest_path=args.manifest,
            socks_port=args.socks_port, server_policy_byte=args.server_policy_byte,
            extra_number=args.extra_number, context=args.context, region=args.region, server_id=args.server_id,
            selection=args.selection, password=password, server_list_only=args.server_list_only,
            _progress=lambda stage: print(json.dumps(dict(event='phase', stage=stage)), file=sys.stderr, flush=True))
        password = None
        print(json.dumps(result))
        if result['status'] == 'selected_game_login_not_completed': sys.exit(2)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(json.dumps(dict(status='selected_game_login_not_completed', error_type=type(error).__name__)))
        sys.exit(2)
