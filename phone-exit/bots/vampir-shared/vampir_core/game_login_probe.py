"""Bounded Version -> Login exchange using the runtime socket owner."""
import math
import select
import time

from .game_connection import GameConnection, PumpBudget
from .receive_stream import ReceiveLimits
from .selection_flow import SelectionLimits, SelectionState
from .game_login_error import describe_game_login_error
from .session_clock import LobbyPingClock
from .world_move_start import SOURCE_SHA256 as WORLD_SOURCE_SHA256
from .character_target import CharacterTargetTracker
from .tutorial_update import decode_tutorial_update


def exchange_game_login(sock, version, login, *, timeout=10, read_character_list=False, ping_clock=None,
                        character_index=None, read_world_start=False, source_sha256=None,read_world_finish=False,
                        observe_world_seconds=0,world_observer=None,tutorial_observer=None):
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError('Expected game login timeout in (0,30]')
    if type(read_character_list) is not bool: raise ValueError('Explicit character-list operation required')
    if world_observer is not None and (not callable(world_observer) or not read_world_finish):
        raise ValueError('World observer requires explicit completion')
    if tutorial_observer is not None and (not callable(tutorial_observer) or not read_world_finish):
        raise ValueError('Tutorial observer requires explicit completion')
    if character_index is not None and (type(character_index) is not int or not 0 <= character_index <= 65535
                                        or not read_character_list):
        raise ValueError('Character index requires an explicit list operation and uint16 index')
    if ping_clock is not None and not isinstance(ping_clock, LobbyPingClock):
        raise TypeError('Expected verified lobby Ping clock')
    if type(read_world_start) is not bool or (read_world_start and
            (character_index is None or source_sha256 != WORLD_SOURCE_SHA256)):
        raise ValueError('World start requires explicit character selection and current source')
    if type(read_world_finish) is not bool or (read_world_finish and not read_world_start):
        raise ValueError('World finish requires explicit world start')
    if (type(observe_world_seconds) not in (int,float) or not math.isfinite(observe_world_seconds)
            or not 0<=observe_world_seconds<=300 or
            (observe_world_seconds and (not read_world_finish or ping_clock is None))):
        raise ValueError('World observation requires explicit finish, clock and duration <=300')
    unknown = []  # Bounded first-packet sample, not a processing limit.
    packet_counts = {}
    other_packet_count = 0
    packet_budget_exceeded = False
    target_tracker = None
    notified_revision = 0
    tutorial_pending=[]
    tutorial_notifications=0
    def ensure_target_tracker():
        nonlocal target_tracker
        if target_tracker is None and world_observer is not None and owner.world_entry is not None:
            world=owner.world_entry
            if world.state=='finish_response':
                target_tracker=CharacterTargetTracker(owner.selection.response,world.target_position,
                    source_sha256=source_sha256)
        return target_tracker
    def observe(packet):
        nonlocal other_packet_count, packet_budget_exceeded, tutorial_notifications
        other_packet_count += 1
        if len(unknown) < 32: unknown.append(packet.packet_id)
        if other_packet_count > 4096 or (packet.packet_id not in packet_counts and len(packet_counts) >= 128):
            packet_budget_exceeded = True
            raise RuntimeError('Other packet budget exceeded')
        packet_counts[packet.packet_id] = packet_counts.get(packet.packet_id, 0) + 1
        if packet.packet_id==307 and world_observer is not None:
            tracker=ensure_target_tracker()
            if tracker is not None:tracker.receive(packet.body)
        if packet.packet_id==9905 and tutorial_observer is not None:
            if len(tutorial_pending)>=64:raise RuntimeError('Tutorial notification budget exceeded')
            tutorial_pending.append(decode_tutorial_update(packet.body,source_sha256=source_sha256,
                max_records=4096,max_payload_size=65536))
            tutorial_notifications+=1
    owner = GameConnection(sock, key_bits=0, sequence=0,
        receive_limits=ReceiveLimits(1048576, 1048576, 1048576, 2097152, 2097152),
        selection_limits=SelectionLimits(1048576, 64, 4096, timeout),
        max_queued_bytes=65536, max_queued_frames=8, on_packet=observe)
    if read_world_start:
        owner.enable_world_start(source_sha256=source_sha256,timeout=timeout,max_payload_size=1048576,
            complete_world=read_world_finish,max_collection_items=4096)
    sent = received = 0
    counts_complete = True
    flow = None
    list_requested = False
    initial_ping_queued = False
    select_requested = False
    list_summary = None
    selection_error = None
    observation_until=None
    def result(status):
        detail = describe_game_login_error(flow.login_result_code) if flow and flow.login_result_code is not None else None
        value = dict(status=status, version_result_code=flow.version_result_code if flow else None,
            login_result_received=flow is not None and flow.login_result_code is not None,
            login_result_code=flow.login_result_code if flow else None,
            login_result_key=detail[0] if detail else None,
            login_error_message=detail[1] if detail else None,
            last_body_size=flow.last_body_size if flow else None,
            bytes_sent=sent, bytes_received=received, other_packet_ids=unknown.copy(),
            other_packet_count=other_packet_count,
            other_packet_counts={str(key):value for key,value in sorted(packet_counts.items())},
            other_packet_sample_truncated=other_packet_count > len(unknown),
            byte_counts_complete=counts_complete,
            error=owner.error, login_error=flow.error if flow else None,
            character_list_sent=list_requested, initial_ping_queued=initial_ping_queued, game_session_ready=False)
        if read_character_list:
            characters = owner.selection.characters
            value.update(character_list_received=characters is not None,
                character_list_result_code=owner.selection.result_code,
                character_count=len(characters.records) if characters is not None else None,
                preferred_character_index=owner.selection.preferred_index if characters is not None else None,
                selection_error=selection_error or owner.selection.error, character_select_sent=select_requested)
            if list_summary is not None:
                value.update(list_summary)
            if character_index is not None:
                response = owner.selection.response
                refused = select_requested and owner.selection.error == 'unsupported_result_code'
                accepted = (select_requested and owner.selection.last_packet_id == 110
                    and owner.selection.result_code == 0 and owner.selection.error is None)
                value.update(character_select_result_received=accepted or refused,
                    character_select_result_code=(response.result_code if response is not None
                        else owner.selection.result_code if accepted or refused else None),
                    character_select_body_size=(owner.selection.last_body_size
                        if owner.selection.last_packet_id == 110 else None),
                    selection_body_fully_decoded=accepted or refused)
        if read_world_start:
            world=owner.world_entry
            value.update(world_entry_state=world.state,world_entry_error=world.error,
                world_reserve_received=world.reserve_result_code is not None,
                world_reserve_result_code=world.reserve_result_code,
                world_reserve_full_body_validated=False,
                world_start_queued=world.request_sent,
                world_start_received=world.start_result_code is not None,
                world_start_result_code=world.start_result_code)
            if read_world_finish:
                value.update(world_finish_queued=world.finish_sent,
                    world_finish_received=world.finish_result_code is not None,
                    world_finish_result_code=world.finish_result_code,
                    server_target_position_received=world.target_position is not None,
                    position_semantics='server_target_before_engine_correction',
                    headless_completion_policy='acknowledge_successful_start_without_3d')
        if observe_world_seconds:
            heartbeat=owner.heartbeat
            value.update(periodic_ping_queued=heartbeat.queued_count-1 if heartbeat else 0,
                ping_results_received=heartbeat.response_count if heartbeat else 0,
                requested_observation_seconds=observe_world_seconds,
                world_observation_completed=status=='world_observation_complete')
        if world_observer is not None:
            value['own_xy_target_updates']=target_tracker.update_count if target_tracker else 0
        if tutorial_observer is not None:value['tutorial_notifications_decoded']=tutorial_notifications
        return value
    try:
        started = time.monotonic()
        owner.start_login(version, login, now=started, timeout=timeout, max_payload_size=1048576)
        if ping_clock is not None:
            initial=ping_clock.initial_ping(utc_millis=time.time_ns() // 1000000)
            owner.queue_ping(initial)
            if observe_world_seconds:
                owner.enable_periodic_ping(ping_clock,initial,source_sha256=source_sha256)
            initial_ping_queued = True
        flow = owner.login
        deadline = started + 2 * timeout
        budget = PumpBudget(32, 8, 8, 16384, 8)
        while owner.active and time.monotonic() < deadline:
            try:
                progress = owner.pump(now=time.monotonic(), budget=budget)
            except RuntimeError:
                counts_complete = False
                return result('other_packet_budget_exceeded' if packet_budget_exceeded else 'connection_processing_failed')
            sent += progress.bytes_sent
            received += progress.bytes_received
            if received > 4194304: return result('receive_budget_exceeded')
            if flow.state == 'login_response':
                if not read_character_list: return result('login_result')
                if not list_requested:
                    # Explicit diagnostic entry permission from the caller, not a UI lifecycle claim.
                    owner.enter_character_list(now=time.monotonic())
                    list_requested = True
                    deadline = time.monotonic() + timeout
                elif owner.selection.state == SelectionState.LIST_AVAILABLE:
                    if character_index is None: return result('character_list_result')
                    list_summary = dict(character_list_received=True,character_list_result_code=0,
                        character_count=len(owner.selection.characters.records),
                        preferred_character_index=owner.selection.preferred_index)
                    if character_index >= len(owner.selection.characters.records):
                        selection_error = 'index_out_of_range'
                        return result('character_selection_not_sent')
                    owner.select_character(character_index, now=time.monotonic())
                    select_requested = True
                    deadline = time.monotonic() + timeout
                elif owner.selection.state == SelectionState.SELECT_RESPONSE:
                    if not read_world_start: return result('character_select_result')
                    world=owner.world_entry
                    world.tick(time.monotonic())
                    if world.state=='start_response':return result('world_start_result')
                    if world.state=='finish_response':
                        while tutorial_pending:
                            tutorial_observer(tutorial_pending.pop(0))
                        tracker=ensure_target_tracker()
                        if tracker is not None and tracker.revision!=notified_revision:
                            world_observer(tracker.position)
                            notified_revision=tracker.revision
                        if not observe_world_seconds:return result('world_finish_result')
                        if observation_until is None:
                            observation_until=time.monotonic()+observe_world_seconds
                            deadline=observation_until
                    if world.error:return result('world_start_failed')
                    if world.deadline is not None: deadline=world.deadline
            if owner.active:
                request_deadline = owner.selection.deadline if list_requested else flow.deadline
                remaining = max(0, min(deadline, request_deadline or deadline) - time.monotonic())
                select.select([sock], [sock] if owner.queued_bytes else [], [], min(0.05, remaining))
        if owner.active and list_requested:
            # The outer deadline may elapse before another pump observes it.
            owner.selection.expire(now=time.monotonic())
            if read_world_start:
                owner.world_entry.tick(time.monotonic())
        return result('connection_closed' if not owner.active else
            'world_observation_complete' if observation_until is not None and time.monotonic()>=observation_until else 'timeout')
    finally:
        owner.close()
        if target_tracker is not None:target_tracker.close()
        tutorial_pending.clear()
        if tutorial_observer is not None:tutorial_observer(None)
        if world_observer is not None:world_observer(None)
