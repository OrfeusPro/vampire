"""Single-owner live state, bounded in memory; no raw packet persistence."""
import copy
import secrets
import re
from threading import Event, Lock
import time


class LiveSession:
    """The socket thread publishes; HTTP readers never operate the connection."""
    def __init__(self, *, bot_id, session_id=None, projection=None):
        if not isinstance(bot_id,str) or not re.fullmatch('[a-zA-Z0-9_-]{1,48}',bot_id):
            raise ValueError('Explicit bot identity required')
        self.bot_id=bot_id
        self.session_id=session_id or secrets.token_hex(16)
        if not isinstance(self.session_id,str) or not re.fullmatch('[a-zA-Z0-9_-]{1,48}',self.session_id):
            raise ValueError('Invalid session identity')
        self.projection=projection
        self._stop=Event()
        self._lock=Lock()
        self._started=time.monotonic()
        self._closed=False
        self._snapshot=dict(schema=2,bot_id=bot_id,session_id=self.session_id,state='connecting',position=None,
            character=None,entities=[],updated_at_ms=None,heartbeat=dict(sent=0,received=0),
            coverage=dict(vitals='not_verified',level='not_verified',entities='not_verified',movement='not_verified'),
            packets={},error=None)

    def request_stop(self):self._stop.set()
    @property
    def stop_requested(self):return self._stop.is_set()

    def packet(self, packet_id, body):
        # Unknown traffic is counted, never retained or mistaken for decoded state.
        with self._lock:
            if self._closed:return
            counts=self._snapshot['packets']
            key=str(packet_id)
            if key in counts or len(counts)<256:counts[key]=min(counts.get(key,0)+1,2**53-1)

    def publish(self, owner):
        world=owner.world_entry
        if world is None or world.state!='finish_response':return
        selection=owner.selection
        key=selection.response.player.at(8)
        matches=[r for r in selection.characters.records if r.u64[0]==key]
        name=matches[0].strings[0] if len(matches)==1 else None
        position=world.target_position
        xyz=position.vector.finite_values()
        projected=None
        if self.projection is not None:
            from dataclasses import asdict
            try:projected=asdict(self.projection.project(position))
            except ValueError:pass
        heartbeat=owner.heartbeat
        with self._lock:
            if self._closed:return
            character=self._snapshot['character']
            if character is None:
                character=dict(key=str(key),name=name,world_id=position.world_id,
                    position=dict(x=xyz[0],y=xyz[1],z=xyz[2],semantics='server_target_before_engine_correction'),
                    level=None,hp=None,max_hp=None,mp=None,max_mp=None)
            self._snapshot.update(state='connected',updated_at_ms=time.time_ns()//1000000,
                position=projected,character=character,
                heartbeat=dict(sent=heartbeat.queued_count if heartbeat else 0,
                    received=heartbeat.response_count if heartbeat else 0))

    def close(self, error=None):
        if error is not None and (not isinstance(error,str) or not re.fullmatch('[a-zA-Z0-9_]{1,96}',error)):
            error='session_failed'
        with self._lock:
            self._closed=True
            self._snapshot.update(state='disconnected',position=None,character=None,entities=[],
                updated_at_ms=time.time_ns()//1000000,error=error or self._snapshot['error'])

    def snapshot(self):
        with self._lock:
            value=copy.deepcopy(self._snapshot)
        value['uptime_seconds']=round(time.monotonic()-self._started,1)
        return value


class LiveSessions:
    """Shared HTTP registry; every bot keeps a distinct model, lock and Stop event."""
    def __init__(self,*,capacity=2):
        if type(capacity) is not int or not 1<=capacity<=50:raise ValueError('Session capacity must be 1..50')
        self.capacity=capacity
        self._lock=Lock()
        self._sessions={}
    def attach(self,session):
        if not isinstance(session,LiveSession):raise TypeError('Expected isolated live session')
        with self._lock:
            if session.bot_id in self._sessions:raise ValueError('Bot already has a session')
            if any(s.session_id==session.session_id for s in self._sessions.values()):raise ValueError('Session identity already attached')
            if len(self._sessions)>=self.capacity:raise BufferError('Session capacity reached')
            self._sessions[session.bot_id]=session
    def get(self,bot_id):
        with self._lock:return self._sessions.get(bot_id)
    def list(self):
        with self._lock:return [dict(bot_id=s.bot_id,session_id=s.session_id,state=s.snapshot()['state']) for s in self._sessions.values()]
    def close(self):
        with self._lock:sessions=list(self._sessions.values())
        for session in sessions:session.request_stop()
