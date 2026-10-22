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
from vampir_core.socks_route import SocksRoute, socks_game_address_context
from vampir_core.direct_route import connect_direct, direct_game_address_context
from vampir_core.game_server_target import SERVER_REGION_CODES, is_game_server_state_excluded, game_server_allows_joined_country
from vampir_core.patch_revision import parse_patch_client_revision
from vampir_core.session_clock import LobbyPingClock, SOURCE_SHA256 as PING_CLOCK_SOURCE_SHA256


@dataclass(frozen=True)
class AuthForGame:
    binding: object = field(repr=False)
    sdk_data: object = field(repr=False)
    netmarble_id: str = field(repr=False)
    nid_metadata: str = field(default='',repr=False)


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def run(email, *, selected_profile, manifest_path, socks_port, server_policy_byte,
        extra_number, context, region, server_id=None, selection=None, password='', server_list_only=False, auth_flow='nid', language_code=None,
        lobby_context='sdk-without-nid-info', read_character_list=False, character_index=None, read_world_start=False, read_world_finish=False, observe_world_seconds=0, world_observer=None, tutorial_observer=None, ack_initial_tutorial=False, read_quest_list=False, quest_observer=None, quest_wire_observer=None, _progress=None):
    if auth_flow not in ('nid', 'launcher'): raise ValueError('Unsupported explicit SDK auth flow')
    if lobby_context not in ('sdk-without-nid-info','sdk-with-joined-country','sdk-with-partial-metadata'):
        raise ValueError('Explicit supported lobby context required')
    if type(server_list_only) is not bool: raise ValueError('Explicit server-list-only policy required')
    if type(read_character_list) is not bool or (read_character_list and server_list_only):
        raise ValueError('Explicit game character-list operation required')
    if character_index is not None and (type(character_index) is not int or not 0 <= character_index <= 65535 or not read_character_list):
        raise ValueError('Character selection requires a list operation and uint16 index')
    if world_observer is not None and (not callable(world_observer) or not read_world_finish):
        raise ValueError('World observer requires explicit completion')
    if tutorial_observer is not None and (not callable(tutorial_observer) or not read_world_finish):
        raise ValueError('Tutorial observer requires explicit completion')
    if type(observe_world_seconds) not in (int,float) or not 0<=observe_world_seconds<=300 or (observe_world_seconds and not read_world_finish):
        raise ValueError('Explicit world finish and bounded observation duration required')
    if type(read_world_finish) is not bool or (read_world_finish and not read_world_start):
        raise ValueError('World finish requires explicit world start')
    if type(read_world_start) is not bool or (read_world_start and (character_index is None or selected_profile!='recovered-release')):
        raise ValueError('World start requires explicit selection and release profile')
    if type(ack_initial_tutorial) is not bool or (ack_initial_tutorial and not observe_world_seconds):
        raise ValueError('Initial tutorial ack requires bounded world observation')
    if type(read_quest_list) is not bool or (read_quest_list and (not observe_world_seconds or ack_initial_tutorial)):
        raise ValueError('Quest diagnostic requires bounded observation without tutorial ack')
    if quest_observer is not None and (not callable(quest_observer) or not read_quest_list):
        raise ValueError('Quest observer requires explicit diagnostic read')
    if quest_wire_observer is not None and (not callable(quest_wire_observer) or not read_quest_list):
        raise ValueError('Quest wire observer requires explicit diagnostic read')
    if type(region) is not str or region not in SERVER_REGION_CODES: raise ValueError('Explicit server region required')
    if context != 'windows-sdk-initial-reset': raise ValueError('Explicit game Login context required')
    if type(extra_number) is not int or not 0 <= extra_number <= 0xffffffff: raise ValueError('Explicit uint32 extra number required')
    if language_code is not None and (type(language_code) is not int or not 0 <= language_code <= 255):
        raise ValueError('Explicit uint8 language required')
    if (server_id is None) == (selection is None): raise ValueError('One explicit selection policy required')
    if selection is not None and selection != 'lowest-valid-id': raise ValueError('Unsupported selection policy')
    if server_id is not None and (type(server_id) is not int or not 1 <= server_id <= 0xffffffff):
        raise ValueError('Invalid selected server ID')
    state = dict(stage='source_validation', game_session_ready=False, sdk_auth_flow=auth_flow,
        selected_transport='direct' if socks_port is None else 'socks5')
    def phase(value):
        state['stage'] = value
        if _progress: _progress(value)
    try:
        return _run(email, selected_profile=selected_profile, manifest_path=manifest_path,
            socks_port=socks_port, server_policy_byte=server_policy_byte, extra_number=extra_number,
            context=context, region=region, server_id=server_id, selection=selection, password=password,
            server_list_only=server_list_only, auth_flow=auth_flow, language_code=language_code, lobby_context=lobby_context,
            read_character_list=read_character_list, character_index=character_index, read_world_start=read_world_start, read_world_finish=read_world_finish, observe_world_seconds=observe_world_seconds, world_observer=world_observer, tutorial_observer=tutorial_observer, ack_initial_tutorial=ack_initial_tutorial, read_quest_list=read_quest_list, quest_observer=quest_observer, quest_wire_observer=quest_wire_observer, state=state, phase=phase)
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
         extra_number, context, region, server_id, selection, password, server_list_only, auth_flow, language_code, lobby_context,
         read_character_list, character_index, read_world_start, read_world_finish, observe_world_seconds, world_observer, tutorial_observer, ack_initial_tutorial, read_quest_list, quest_observer, quest_wire_observer, state, phase):
    phase('source_validation')
    source = module('game_login_source', 'game-source-profile.py').load_profile(selected_profile=selected_profile)
    auth = {}
    selection_proof = {}
    def consume(**values): auth['context'] = AuthForGame(**values)
    def select_server(response, country):
        phase('game_target_selection')
        target = module('game_login_target', 'probe-selected-game-version.py').choose_target(
            response, server_id=server_id, selection=selection, region=region, joined_country_code=country)
        selection_proof['target'] = target
        return target.server_id
    completed = {}
    def use_session(lobby):
        completed['result'] = _after_lobby(lobby, auth=auth, selection_proof=selection_proof,
            source=source, socks_port=socks_port, extra_number=extra_number, context=context,
            region=region, server_id=server_id, selection=selection, server_list_only=False, language_code=language_code,
            read_character_list=read_character_list, character_index=character_index, read_world_start=read_world_start, read_world_finish=read_world_finish, observe_world_seconds=observe_world_seconds, world_observer=world_observer, tutorial_observer=tutorial_observer, ack_initial_tutorial=ack_initial_tutorial, read_quest_list=read_quest_list, quest_observer=quest_observer, quest_wire_observer=quest_wire_observer, state=state, phase=phase)
    phase('lobby_preparation')
    lobby = module('game_login_lobby', 'probe-lobby-sdk-login.py').run(email,
        selected_profile=selected_profile, manifest_path=manifest_path, socks_port=socks_port,
        lobby_region=region if region in ('SG', 'NA', 'EU') else None,
        context=lobby_context, password=password, read_server_list=True, auth_flow=auth_flow,
        server_policy_byte=server_policy_byte, _progress=phase, _consume_auth=consume,
        _select_server=None if server_list_only else select_server,
        _use_session=None if server_list_only else use_session)
    password = None
    if 'result' in completed: return completed.pop('result')
    if not server_list_only:
        state['lobby'] = lobby.summary
        return dict(state, status='selected_lobby_context_not_received')
    return _after_lobby(lobby, auth=auth, selection_proof=selection_proof,
        source=source, socks_port=socks_port, extra_number=extra_number, context=context,
        region=region, server_id=server_id, selection=selection, server_list_only=True, language_code=language_code,
        read_character_list=read_character_list, character_index=character_index, read_world_start=read_world_start, read_world_finish=read_world_finish, observe_world_seconds=observe_world_seconds, world_observer=world_observer, tutorial_observer=tutorial_observer, ack_initial_tutorial=ack_initial_tutorial, read_quest_list=read_quest_list, quest_observer=quest_observer, quest_wire_observer=quest_wire_observer, state=state, phase=phase)


def _after_lobby(lobby, *, auth, selection_proof, source, socks_port, extra_number,
                 context, region, server_id, selection, server_list_only, state, phase, language_code=None, read_character_list=False, character_index=None, read_world_start=False, read_world_finish=False, observe_world_seconds=0, world_observer=None, tutorial_observer=None, ack_initial_tutorial=False, read_quest_list=False, quest_observer=None, quest_wire_observer=None):
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
    if not server_list_only and ('target' not in selection_proof or
            selection_proof['target'] != target or lobby.summary.get('login_server_id') != target.server_id or
            lobby.summary.get('login_after_server_selection') is not True or
            lobby.summary.get('lobby_open_during_game') is not True or lobby.summary.get('login_result_code') != 0):
        raise ValueError('Game Login requires successful lobby Login for the same selected target')
    state.update(selected_server_id=target.server_id, selected_group_id=target.group_id, selected_region=region)
    if server_list_only:
        credentials = None
        return dict(state, status='server_country_policy_checked', game_login_sent=False)
    reference = [r for r in lobby.server_list_response.servers if r.u32[1] == 101]
    if len(reference) == 1:
        groups = [g for g in lobby.server_list_response.groups if g.raw_08 == reference[0].u32[0]]
        if len(groups) == 1: state['reference_server_101_region_code'] = groups[0].raw_20
    phase('game_system_inputs')
    ping_clock = None
    if getattr(source, 'source_exe_sha256', '') == PING_CLOCK_SOURCE_SHA256:
        ping_clock = LobbyPingClock.from_version_result(lobby.version_response,
            source_sha256=source.source_exe_sha256)
    cpu, windows = module('game_login_system', 'windows-system-inputs.py').observe_inputs()
    prepare_version = module('game_login_version', 'probe-game-version.py').prepare_version
    phase('game_connect')
    connection = (connect_direct(target.host, target.port, timeout=10) if socks_port is None else
        SocksRoute(socks_port).connect(target.host, target.port, timeout=10))
    try:
        address_context = (direct_game_address_context(connection) if socks_port is None else
            socks_game_address_context(connection))
        state['game_address_source'] = address_context.source
        version = prepare_version(app_version=source.app_version, nm_device_key=credentials.binding.nm_device_key,
            local_address=address_context.address, cpu=cpu, windows_version=windows, compiled_tag=source.compiled_tag)
        phase('game_login_preparation')
        login = prepare_initial_windows_game_login(version, binding=credentials.binding,
            sdk_data=credentials.sdk_data, netmarble_id=credentials.netmarble_id,
            lobby_result=lobby.response, server_id=target.server_id, extra_number=extra_number, context=context,
            language_code=language_code,nid_metadata=credentials.nid_metadata, compiled_tag=source.compiled_tag)
        credentials = None
        phase('game_login_exchange')
        state['login_language_code'] = login.raw_bytes[2]
        game = exchange_game_login(connection, version, login, timeout=10,
            read_character_list=read_character_list, character_index=character_index, ping_clock=ping_clock, read_world_start=read_world_start, read_world_finish=read_world_finish, observe_world_seconds=observe_world_seconds, world_observer=world_observer, tutorial_observer=tutorial_observer, ack_initial_tutorial=ack_initial_tutorial, read_quest_list=read_quest_list, quest_observer=quest_observer, quest_wire_observer=quest_wire_observer,
            source_sha256=getattr(source,'source_exe_sha256',''))
        login = None
        return dict(state, status='game_login_probe', selection=selection or 'explicit-id',
            target_source='fresh_lobby_id104', context=context, extra_number=extra_number, game=game)
    finally:
        credentials = None
        connection.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--email', required=True)
    parser.add_argument('--profile', choices=['recovered-base', 'recovered-release'], required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    route_choice = parser.add_mutually_exclusive_group(required=True)
    route_choice.add_argument('--socks-port', type=int)
    route_choice.add_argument('--direct', action='store_true', help='Use the ordinary route for the complete login chain')
    parser.add_argument('--server-policy-byte', type=int, required=True)
    revision_choice = parser.add_mutually_exclusive_group(required=True)
    revision_choice.add_argument('--extra-number', type=int)
    revision_choice.add_argument('--patch-manifestlist', type=Path,
        help='Read explicit ClientVersion from an installed or verified snapshot manifestlist')
    parser.add_argument('--context', choices=['windows-sdk-initial-reset'], required=True)
    parser.add_argument('--region', choices=list(SERVER_REGION_CODES), required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--server-id', type=int)
    choice.add_argument('--selection', choices=['lowest-valid-id'])
    parser.add_argument('--password-stdin', action='store_true')
    parser.add_argument('--server-list-only', action='store_true', help='Check region/state/country policy without a game connection')
    parser.add_argument('--read-character-list', action='store_true', help='Explicit list-entry probe after successful Login; selection requires --character-index')
    parser.add_argument('--observe-world-seconds',type=float,default=0,help='Keep the explicit world session open with periodic Ping, up to 300 seconds')
    parser.add_argument('--read-quest-list',action='store_true',help='One explicit ID1801 diagnostic with reset fields 0/0 after world finish; requires observation; no tutorial ack')
    parser.add_argument('--ack-initial-tutorial',action='store_true',help='Explicit server tutorial 1001/step 2 ack after fresh snapshot; not a quest-panel click; requires world observation')
    parser.add_argument('--read-world-finish',action='store_true',help='Explicit headless ID205 -> ID206 after successful start; requires --read-world-start')
    parser.add_argument('--read-world-start',action='store_true',help='Explicit ID202 envelope -> ID203 -> ID204 probe; no world completion')
    parser.add_argument('--character-index', type=int, help='Explicit zero-based index in the fresh character list; requires --read-character-list')
    parser.add_argument('--auth-flow', choices=['nid', 'launcher'], default='nid')
    parser.add_argument('--language-code',type=int,help='Explicit source-bound Login language byte; absent preserves reset value 7')
    parser.add_argument('--lobby-context',choices=['sdk-without-nid-info','sdk-with-joined-country','sdk-with-partial-metadata'],default='sdk-without-nid-info')
    args = parser.parse_args()
    try:
        extra_number = args.extra_number
        if args.patch_manifestlist is not None:
            with args.patch_manifestlist.open('rb') as stream:
                extra_number = parse_patch_client_revision(stream.read(2097153))
        password = sys.stdin.readline(258).rstrip('\r\n') if args.password_stdin else ''
        if args.password_stdin and (not password or len(password) > 256): raise ValueError('Invalid password input')
        result = run(args.email, selected_profile=args.profile, manifest_path=args.manifest,
            socks_port=args.socks_port, server_policy_byte=args.server_policy_byte,
            extra_number=extra_number, context=args.context, region=args.region, server_id=args.server_id,
            selection=args.selection, password=password, server_list_only=args.server_list_only, auth_flow=args.auth_flow, language_code=args.language_code, lobby_context=args.lobby_context,
            read_character_list=args.read_character_list, character_index=args.character_index, read_world_start=args.read_world_start, read_world_finish=args.read_world_finish, observe_world_seconds=args.observe_world_seconds, ack_initial_tutorial=args.ack_initial_tutorial, read_quest_list=args.read_quest_list,
            _progress=lambda stage: print(json.dumps(dict(event='phase', stage=stage)), file=sys.stderr, flush=True))
        password = None
        print(json.dumps(result))
        if result['status'] == 'selected_game_login_not_completed': sys.exit(2)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(json.dumps(dict(status='selected_game_login_not_completed', error_type=type(error).__name__)))
        sys.exit(2)
