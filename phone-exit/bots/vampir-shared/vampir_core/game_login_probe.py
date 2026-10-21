"""Bounded Version -> Login exchange using the runtime socket owner."""
import math
import select
import time

from .game_connection import GameConnection, PumpBudget
from .receive_stream import ReceiveLimits
from .selection_flow import SelectionLimits, SelectionState
from .game_login_error import describe_game_login_error


def exchange_game_login(sock, version, login, *, timeout=10, read_character_list=False):
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError('Expected game login timeout in (0,30]')
    if type(read_character_list) is not bool: raise ValueError('Explicit character-list operation required')
    unknown = []
    def observe(packet):
        unknown.append(packet.packet_id)
        if len(unknown) > 32: raise RuntimeError('Unknown packet budget exceeded')
    owner = GameConnection(sock, key_bits=0, sequence=0,
        receive_limits=ReceiveLimits(1048576, 1048576, 1048576, 2097152, 2097152),
        selection_limits=SelectionLimits(1048576, 64, 4096, timeout),
        max_queued_bytes=65536, max_queued_frames=8, on_packet=observe)
    sent = received = 0
    counts_complete = True
    flow = None
    list_requested = False
    def result(status):
        detail = describe_game_login_error(flow.login_result_code) if flow and flow.login_result_code is not None else None
        value = dict(status=status, version_result_code=flow.version_result_code if flow else None,
            login_result_received=flow is not None and flow.login_result_code is not None,
            login_result_code=flow.login_result_code if flow else None,
            login_result_key=detail[0] if detail else None,
            login_error_message=detail[1] if detail else None,
            last_body_size=flow.last_body_size if flow else None,
            bytes_sent=sent, bytes_received=received, other_packet_ids=unknown.copy(),
            byte_counts_complete=counts_complete,
            error=owner.error, login_error=flow.error if flow else None,
            character_list_sent=list_requested, game_session_ready=False)
        if read_character_list:
            characters = owner.selection.characters
            value.update(character_list_received=characters is not None,
                character_list_result_code=owner.selection.result_code,
                character_count=len(characters.records) if characters is not None else None,
                preferred_character_index=owner.selection.preferred_index if characters is not None else None,
                selection_error=owner.selection.error, character_select_sent=False)
        return value
    try:
        started = time.monotonic()
        owner.start_login(version, login, now=started, timeout=timeout, max_payload_size=1048576)
        flow = owner.login
        deadline = started + 2 * timeout
        budget = PumpBudget(32, 8, 8, 16384, 8)
        while owner.active and time.monotonic() < deadline:
            try:
                progress = owner.pump(now=time.monotonic(), budget=budget)
            except RuntimeError:
                counts_complete = False
                return result('connection_processing_failed')
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
                    return result('character_list_result')
            if owner.active:
                request_deadline = owner.selection.deadline if list_requested else flow.deadline
                remaining = max(0, min(deadline, request_deadline or deadline) - time.monotonic())
                select.select([sock], [sock] if owner.queued_bytes else [], [], min(0.05, remaining))
        return result('connection_closed' if not owner.active else 'timeout')
    finally:
        owner.close()
