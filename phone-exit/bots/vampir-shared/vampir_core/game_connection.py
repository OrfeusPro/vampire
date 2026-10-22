"""Single-owner connected socket pump; auth/bootstrap remain external.

Combines the verified B transport, key-change order and selection codecs.
Does not infer heartbeat timing, Login/Version fields or world readiness.
"""
from dataclasses import dataclass
import math
import time

from .key_change import KeyChangePayload, KEY_CHANGE_NOTIFY_ID
from .outbound import OutboundFrames
from .ping import PingPayload
from .login_flow import LoginFlow
from .receive_stream import ReceiveLimits, ReceiveStream
from .selection_flow import CharacterSelectionFlow, SelectionLimits, SelectionState
from .socket_send import drain_outbound


@dataclass(frozen=True, slots=True)
class PumpBudget:
    max_packets: int
    max_transport_frames_per_packet: int
    max_recv_calls: int
    recv_chunk_size: int
    max_send_calls: int

    def __post_init__(self):
        if any(type(v) is not int or v < 1 for v in (
                self.max_packets, self.max_transport_frames_per_packet, self.max_recv_calls,
                self.recv_chunk_size, self.max_send_calls)):
            raise ValueError('Connection work budgets must be positive integers')


@dataclass(frozen=True, slots=True)
class PumpProgress:
    packets: int
    bytes_received: int
    bytes_sent: int
    active: bool


class GameConnection:
    """Own an already connected socket from construction through close.

    The socket becomes nonblocking. Call pump regularly, even without a new
    read notification: decoded bytes can remain after a work budget expires.
    on_packet(packet) synchronously handles IDs outside 11/102/110, and outside
    2/4 when start_login() is used. It must
    not block or retain unlimited bodies. Exceptions close this connection and
    propagate with a generic error; no raw payload is attached to that error.
    No reconnect or replay is automatic. A new socket requires a new instance.
    """
    def __init__(self, sock, *, key_bits, sequence, receive_limits: ReceiveLimits,
                 selection_limits: SelectionLimits, max_queued_bytes, max_queued_frames,
                 on_packet):
        if not callable(on_packet):
            raise TypeError('Expected a packet handler')
        self._outbound = OutboundFrames(key_bits=key_bits, sequence=sequence,
            max_queued_bytes=max_queued_bytes, max_queued_frames=max_queued_frames)
        self._receiver = ReceiveStream(receive_limits)
        self._selection = CharacterSelectionFlow(self._outbound, selection_limits)
        self._key = key_bits
        self._on_packet = on_packet
        self._socket = sock
        self._active = True
        self._error = None
        self._last_time = None
        self._in_pump = False
        self._login = None
        self._world_entry = None
        self._heartbeat = None
        self._tutorial_ack = None
        try:
            sock.setblocking(False)
        except Exception:
            self.close()
            raise

    def __repr__(self):
        return f'GameConnection(active={self.active}, key=<redacted>)'

    @property
    def active(self): return self._active

    @property
    def error(self): return self._error

    @property
    def selection(self): return self._selection

    @property
    def queued_bytes(self): return self._outbound.queued_bytes

    @property
    def login(self): return self._login

    @property
    def world_entry(self): return self._world_entry

    @property
    def heartbeat(self): return self._heartbeat

    @property
    def tutorial_ack(self): return self._tutorial_ack

    def close(self):
        if self._active:
            self._active = False
            self._receiver.close()
            self._selection.close()
            if self._world_entry is not None: self._world_entry.close()
            if self._heartbeat is not None: self._heartbeat.close()
            if self._login is not None: self._login.close()
            if self._tutorial_ack is not None: self._tutorial_ack.close()
            try:
                self._socket.close()
            finally:
                self._key = 0
                self._on_packet = None

    def _fail(self, reason):
        self._error = reason
        self.close()

    def enter_character_list(self, *, now):
        if not self.active: raise RuntimeError('Connection is inactive')
        if self._login is not None and self._login.state != 'login_response':
            raise RuntimeError('Login response is not available')
        self._selection.enter_list(now=now)

    def start_login(self, version, login, *, now, timeout, max_payload_size):
        if not self.active: raise RuntimeError('Connection is inactive')
        if self._login is not None or self._selection.state != SelectionState.WAITING_ENTRY:
            raise RuntimeError('Connection bootstrap already started')
        flow = LoginFlow(self._outbound, timeout=timeout, max_payload_size=max_payload_size)
        flow.start(version, login, now=now)
        self._login = flow

    def select_character(self, index, *, now):
        if not self.active: raise RuntimeError('Connection is inactive')
        self._selection.select(index, now=now)

    def enable_world_start(self, *, source_sha256, timeout, max_payload_size,
                           complete_world=False,max_collection_items=4096):
        if not self.active or self._world_entry is not None:
            raise RuntimeError('World entry cannot be enabled')
        from .world_entry_flow import WorldEntryFlow
        self._world_entry=WorldEntryFlow(self._selection,self._outbound,
            source_sha256=source_sha256,timeout=timeout,max_payload_size=max_payload_size,
            complete_world=complete_world,max_collection_items=max_collection_items)

    def queue_ping(self, payload: PingPayload):
        """Explicit payload from the owner; no guessed heartbeat schedule."""
        if not self.active: raise RuntimeError('Connection is inactive')
        self._outbound.queue_ping(payload)

    def enable_initial_tutorial_ack(self, *, source_sha256, timeout=10, snapshot_max_age=10):
        """Track this connection's snapshots; enabling sends no game command."""
        if not self.active or self._tutorial_ack is not None:
            raise RuntimeError('Initial tutorial acknowledgement cannot be enabled')
        from .initial_tutorial_ack import InitialTutorialAck
        self._tutorial_ack = InitialTutorialAck(self._outbound, source_sha256=source_sha256,
            timeout=timeout, snapshot_max_age=snapshot_max_age)

    def queue_initial_tutorial_ack(self, *, now):
        """Explicit diagnostic step 2 ack, requiring successful world completion."""
        if (not self.active or self._tutorial_ack is None or self._world_entry is None
                or self._world_entry.state != 'finish_response'
                or self._world_entry.finish_result_code != 0):
            raise RuntimeError('Initial tutorial acknowledgement is unavailable')
        self._tutorial_ack.queue(now=now)

    def enable_periodic_ping(self,clock,initial_ping,*,source_sha256):
        """Initial Ping must already be queued; scheduler starts after ID206."""
        if not self.active or self._heartbeat is not None:
            raise RuntimeError('Heartbeat cannot be enabled')
        from .heartbeat import PeriodicPing
        self._heartbeat=PeriodicPing(clock,initial_ping,source_sha256=source_sha256)

    def pump(self, *, now, budget: PumpBudget):
        if not self.active: raise RuntimeError('Connection is inactive')
        if self._in_pump: raise RuntimeError('Connection pump is not reentrant')
        if not isinstance(budget, PumpBudget): raise TypeError('Expected pump budget')
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
            raise ValueError('Expected finite nonnegative monotonic time')
        if self._last_time is not None and now < self._last_time:
            raise ValueError('Connection clock moved backwards')
        self._last_time = now
        packets = received = sent = reads = 0
        self._in_pump = True
        try:
            if self._login is not None and self._login.state in ('failed', 'closed'):
                self._fail('login_inactive')
                return PumpProgress(0, 0, 0, False)
            if self._login is not None and self._login.expire(now=now):
                self._fail('login_timeout')
                return PumpProgress(0, 0, 0, False)
            if self._selection.state in (SelectionState.FAILED, SelectionState.CLOSED):
                self._fail('selection_inactive')
                return PumpProgress(0, 0, 0, False)
            if self._selection.expire(now=now):
                self._fail('selection_timeout')
                return PumpProgress(0, 0, 0, False)
            if self._world_entry is not None:
                self._world_entry.tick(now)
                if self._world_entry.error:
                    self._fail('world_entry_failed')
                    return PumpProgress(0, 0, 0, False)
            if self._tutorial_ack is not None and self._tutorial_ack.expire(now=now):
                self._fail('initial_tutorial_ack_unknown')
                return PumpProgress(0, 0, 0, False)
            while packets < budget.max_packets and self.active:
                packet = self._receiver.next_packet(key_bits=self._key,
                    max_transport_frames=budget.max_transport_frames_per_packet)
                if packet is not None:
                    packets += 1
                    if packet.packet_id == KEY_CHANGE_NOTIFY_ID:
                        value = KeyChangePayload.decode(packet.body)
                        self._outbound.acknowledge_key_change(value)
                        self._key = value.key_bits
                    elif packet.packet_id==17 and self._heartbeat is not None:
                        self._heartbeat.receive_result(packet.body)
                    elif packet.packet_id in (2, 4) and self._login is not None:
                        self._login.receive(packet.packet_id, packet.body, now=now)
                        if self._login.state == 'failed': self._fail('login_response_failed')
                    elif packet.packet_id in (102, 110):
                        self._selection.receive(packet.packet_id, packet.body, now=now)
                        if self._selection.state == SelectionState.FAILED:
                            self._fail('selection_response_failed')
                    elif self._world_entry is not None and (packet.packet_id in (202,204) or
                            (packet.packet_id==206 and self._world_entry.complete_world)):
                        self._world_entry.receive(packet.packet_id,packet.body,now=now)
                        if self._world_entry.error: self._fail('world_entry_response_failed')
                    else:
                        if self._tutorial_ack is not None and packet.packet_id in (9904, 9905):
                            self._tutorial_ack.receive(packet.packet_id, packet.body, now=now)
                        self._on_packet(packet)
                    continue
                if self._receiver.finished:
                    self.close()
                    break
                if reads == budget.max_recv_calls or not self._receiver.input_capacity:
                    break
                try:
                    chunk = self._socket.recv(min(budget.recv_chunk_size, self._receiver.input_capacity))
                except (BlockingIOError, InterruptedError):
                    break
                reads += 1
                if chunk:
                    received += len(chunk)
                    self._receiver.feed(chunk)
                else:
                    self._receiver.end_input()
            if self.active:
                if self._heartbeat is not None:
                    from .heartbeat import PingRecoveryRequired
                    try:
                        self._heartbeat.queue_due(self._outbound,utc_millis=time.time_ns()//1000000,
                            ready=self._world_entry is not None and self._world_entry.state=='finish_response')
                    except PingRecoveryRequired:
                        self._fail('ping_recovery_required')
                        return PumpProgress(packets,received,0,False)
                sent = drain_outbound(self._socket, self._outbound, max_send_calls=budget.max_send_calls,
                    on_frame_sent=(self._tutorial_ack.frame_sent if self._tutorial_ack is not None else None)).bytes_sent
            return PumpProgress(packets, received, sent, self.active)
        except Exception:
            self._fail('connection_processing_failed')
            raise RuntimeError('Game connection processing failed') from None
        finally:
            self._in_pump = False
