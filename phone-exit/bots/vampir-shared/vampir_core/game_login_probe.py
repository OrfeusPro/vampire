"""Bounded Version -> Login exchange using the runtime socket owner."""
import math
import select
import time

from .game_connection import GameConnection, PumpBudget
from .receive_stream import ReceiveLimits
from .selection_flow import SelectionLimits, SelectionState
from .game_login_error import describe_game_login_error
from .session_clock import LobbyPingClock
from .world_move_start import SOURCE_SHA256 as WORLD_SOURCE_SHA256, WORLD_PROBE_SOURCES
from .character_target import CharacterTargetTracker
from .tutorial_update import decode_tutorial_update


def exchange_game_login(sock, version, login, *, timeout=10, read_character_list=False, ping_clock=None,
                        character_index=None, read_world_start=False, source_sha256=None,read_world_finish=False,
                        observe_world_seconds=0,world_observer=None,tutorial_observer=None,
                        ack_initial_tutorial=False, read_quest_list=False, quest_observer=None,
                        quest_wire_observer=None, expose_character_labels=False, expected_character_key=None,
                        creation_payload=None, creation_factory=None, session_control=None):
    if session_control is not None:
        from .live_session import LiveSession
        if not isinstance(session_control,LiveSession) or not read_world_finish or observe_world_seconds!=300:
            raise ValueError('Persistent session requires explicit world finish, heartbeat and session owner')
    creation_enabled = creation_payload is not None or creation_factory is not None
    if creation_factory is not None and (not callable(creation_factory) or creation_payload is not None):
        raise ValueError('Creation factory must be explicit and exclusive with payload')
    if creation_enabled:
        from .character_create import encode_character_create
        if not read_character_list or character_index is not None or source_sha256 != WORLD_SOURCE_SHA256:
            raise ValueError('Creation requires current source and explicit list operation without selection')
        if creation_payload is not None: encode_character_create(creation_payload, source_sha256=source_sha256)
    if expected_character_key is not None and (type(expected_character_key) is not int or
            not 0 <= expected_character_key <= 0xffffffffffffffff or character_index is None):
        raise ValueError('Expected character key requires explicit selection')
    if type(expose_character_labels) is not bool or (expose_character_labels and not read_character_list):
        raise ValueError('Character labels require an explicit list operation')
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
            (character_index is None or source_sha256 not in WORLD_PROBE_SOURCES)):
        raise ValueError('World start requires explicit character selection and current source')
    if type(read_world_finish) is not bool or (read_world_finish and not read_world_start):
        raise ValueError('World finish requires explicit world start')
    if (type(observe_world_seconds) not in (int,float) or not math.isfinite(observe_world_seconds)
            or not 0<=observe_world_seconds<=300 or
            (observe_world_seconds and (not read_world_finish or ping_clock is None))):
        raise ValueError('World observation requires explicit finish, clock and duration <=300')
    if type(ack_initial_tutorial) is not bool or (ack_initial_tutorial and not observe_world_seconds):
        raise ValueError('Initial tutorial ack requires explicit bounded world observation')
    if type(read_quest_list) is not bool or (read_quest_list and
            (not observe_world_seconds or ack_initial_tutorial)):
        raise ValueError('Quest list diagnostic requires bounded observation without tutorial ack')
    if quest_observer is not None and (not callable(quest_observer) or not read_quest_list):
        raise ValueError('Quest observer requires explicit list diagnostic')
    if quest_wire_observer is not None and (not callable(quest_wire_observer) or not read_quest_list):
        raise ValueError('Quest wire observer requires explicit list diagnostic')
    if session_control is not None:session_control.bind_source(source_sha256)
    unknown = []  # Bounded first-packet sample, not a processing limit.
    packet_counts = {}
    other_packet_count = 0
    packet_budget_exceeded = False
    packet_window=time.monotonic()
    packet_window_count=0
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
        nonlocal other_packet_count, packet_budget_exceeded, tutorial_notifications, packet_window, packet_window_count
        if session_control is not None:
            now=time.monotonic()
            if now-packet_window>=60:packet_window,packet_window_count=now,0
            packet_window_count+=1
            selected=owner.selection.response
            session_control.packet(packet.packet_id,packet.body,
                character_key=selected.player.at(8) if selected is not None else None)
        other_packet_count += 1
        if len(unknown) < 32: unknown.append(packet.packet_id)
        if (packet_window_count if session_control is not None else other_packet_count) > 4096 or (packet.packet_id not in packet_counts and len(packet_counts) >= 128):
            packet_budget_exceeded = True
            raise RuntimeError('Other packet budget exceeded')
        packet_counts[packet.packet_id] = packet_counts.get(packet.packet_id, 0) + 1
        if packet.packet_id == 1802 and quest_wire_observer is not None:
            if packet_counts[1802] > 2 or len(packet.body) > 262144:
                raise BufferError('Quest wire observation budget exceeded')
            quest_wire_observer(packet.body)
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
    if ack_initial_tutorial:
        owner.enable_initial_tutorial_ack(source_sha256=source_sha256, timeout=timeout)
    if read_quest_list:
        owner.enable_quest_list_read(source_sha256=source_sha256, timeout=timeout)
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
            # Creation is a later explicit operation; a refused Login cannot
            # be interpreted as an accepted empty list.
            value['character_entry_state'] = ('login_rejected' if flow and flow.login_result_code not in (None, 0)
                else 'awaiting_list' if characters is None
                else 'empty_list' if not characters.records else 'characters_available')
            value.update(character_list_received=characters is not None,
                character_list_result_code=owner.selection.result_code,
                character_count=len(characters.records) if characters is not None else None,
                preferred_character_index=owner.selection.preferred_index if characters is not None else None,
                selection_error=selection_error or owner.selection.error, character_select_sent=select_requested)
            if list_summary is not None:
                value.update(list_summary)
            if expose_character_labels and characters is not None:
                value['characters'] = [dict(index=index, name=record.strings[0], key=str(record.u64[0]))
                    for index, record in enumerate(characters.records)]
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
        if creation_enabled:
            creation = owner.creation
            if creation is not None and creation.state in ('queued', 'sent'): owner.close()
            outcome = creation.outcome if creation is not None else None
            value.update(character_creation_state=creation.state if creation is not None else 'not_attempted',
                character_creation_result_code=creation.result_code if creation is not None else None,
                character_creation_retry_allowed=False,
                character_creation_refresh_required=creation is not None and creation.state in ('unknown', 'needs_refresh', 'created'),
                character_creation_unmatched_results=creation.unmatched_results if creation is not None else 0)
            if outcome is not None and outcome.status == 'created':
                # Explicit account-console operation may retain labels; ordinary diagnostics do not.
                value['created_character_key'] = str(outcome.character_key)
                if expose_character_labels: value['created_character_name'] = outcome.character_name
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
        if ack_initial_tutorial:
            ack = owner.tutorial_ack
            # A diagnostic exit with a pending command has an unknown outcome.
            if ack.state in ('queued', 'sent'): owner.close()
            value.update(initial_tutorial_ack_state=ack.state,
                initial_tutorial_ack_result_code=ack.result_code,
                initial_tutorial_ack_unmatched_results=ack.unmatched_results,
                initial_tutorial_ack_semantics='server_step_ack_not_quest_panel_click')
            if ack.response is not None:
                response = ack.response
                record = response.record
                value['initial_tutorial_ack_response'] = dict(raw08=record.raw08,
                    raw0c=record.raw0c, raw10=record.raw10, state=record.state,
                    raw30=response.raw30, raw31=response.raw31)
        if read_quest_list:
            quests = owner.quest_list
            if quests.state in ('queued', 'sent'): owner.close()
            response = quests.response
            value.update(quest_list_state=quests.state, quest_list_result_code=quests.result_code,
                quest_list_decode_error=quests.decode_error, quest_list_decode_body_size=quests.decode_body_size,
                quest_list_unmatched_results=quests.unmatched_results,
                quest_list_policy='explicit_native_reset_fields_0_0',
                quest_list_correlation='one_outstanding_same_connection_matching_raw14_after_send')
            if response is not None:
                value.update(quest_count=len(response.quests), quest_asset_count=len(response.assets),
                    quest_item_change_counts=response.item_changes.counts)
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
        byte_window=time.monotonic()
        window_received=0
        while owner.active and time.monotonic() < deadline:
            if session_control is not None and session_control.stop_requested:return result('session_stopped')
            try:
                progress = owner.pump(now=time.monotonic(), budget=budget)
            except RuntimeError:
                counts_complete = False
                return result('other_packet_budget_exceeded' if packet_budget_exceeded else 'connection_processing_failed')
            sent += progress.bytes_sent
            received += progress.bytes_received
            if session_control is not None:
                now=time.monotonic()
                if now-byte_window>=60:byte_window,window_received=now,0
                window_received+=progress.bytes_received
            if (window_received if session_control is not None else received) > 4194304: return result('receive_budget_exceeded')
            if flow.state == 'login_response':
                if not read_character_list: return result('login_result')
                if not list_requested:
                    # Explicit diagnostic entry permission from the caller, not a UI lifecycle claim.
                    owner.enter_character_list(now=time.monotonic())
                    list_requested = True
                    deadline = time.monotonic() + timeout
                elif owner.selection.state == SelectionState.LIST_AVAILABLE:
                    if creation_enabled and not owner.selection.characters.records:
                        if owner.creation is None:
                            if creation_factory is not None:
                                creation_payload = creation_factory(owner.selection.characters)
                            try:
                                owner.queue_character_create(creation_payload, source_sha256=source_sha256,
                                    now=time.monotonic(), timeout=timeout)
                            except BufferError:
                                return result('character_creation_not_queued')
                            deadline = time.monotonic() + timeout
                        if owner.creation.state in ('created', 'rejected', 'needs_refresh'):
                            return result('character_creation_result')
                        if owner.creation.state == 'unknown': return result('character_creation_unknown')
                        # Keep pumping this connection until ID104 or timeout; do not select or repeat Create.
                        remaining = max(0, deadline - time.monotonic())
                        select.select([sock], [sock] if owner.queued_bytes else [], [], min(0.05, remaining))
                        continue
                    if character_index is None: return result('character_list_result')
                    if expected_character_key is not None:
                        matches = [index for index, record in enumerate(owner.selection.characters.records)
                            if record.u64[0] == expected_character_key]
                        if len(matches) != 1:
                            selection_error = 'assigned_character_missing_or_ambiguous'
                            return result('character_selection_not_sent')
                        character_index = matches[0]
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
                        if session_control is not None:
                            session_control.publish(owner)
                            deadline=math.inf
                        while tutorial_pending:
                            tutorial_observer(tutorial_pending.pop(0))
                        tracker=ensure_target_tracker()
                        if tracker is not None and tracker.revision!=notified_revision:
                            world_observer(tracker.position)
                            notified_revision=tracker.revision
                        if not observe_world_seconds:return result('world_finish_result')
                        if observation_until is None and session_control is None:
                            observation_until=time.monotonic()+observe_world_seconds
                            deadline=observation_until
                        if ack_initial_tutorial:
                            ack = owner.tutorial_ack
                            if ack.state == 'eligible':
                                try:
                                    owner.queue_initial_tutorial_ack(now=time.monotonic())
                                except BufferError:
                                    return result('initial_tutorial_ack_not_queued')
                            if ack.state in ('accepted', 'rejected'):
                                return result('initial_tutorial_ack_result')
                        if read_quest_list:
                            quests = owner.quest_list
                            if quests.state == 'waiting_entry':
                                try: owner.queue_quest_list_read(now=time.monotonic())
                                except BufferError: return result('quest_list_not_queued')
                            if quests.state in ('received', 'rejected'):
                                if quest_observer is not None: quest_observer(quests.response)
                                return result('quest_list_result')
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
        if session_control is not None:session_control.close(owner.error)
        owner.close()
        if target_tracker is not None:target_tracker.close()
        tutorial_pending.clear()
        if tutorial_observer is not None:tutorial_observer(None)
        if quest_observer is not None:quest_observer(None)
        if world_observer is not None:world_observer(None)
