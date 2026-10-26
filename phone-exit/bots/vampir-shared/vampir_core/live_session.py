"""Single-owner live state, bounded in memory; no raw packet persistence."""
import copy
import secrets
import re
import struct
from threading import Event, Lock
import time
from .stat_change import SOURCE_SHA256 as STAT_SOURCE_SHA256,decode_stat_change,decode_character_level_up,initial_stat_values
from .stat_names import STAT_NAMES,SOURCE_SHA256 as STAT_NAMES_SOURCE
from .live_diagnostics import LiveDiagnostics
from .environment import ObservedEnvironment,SOURCE_SHA256 as ENVIRONMENT_SOURCE
import json

STAT_FIELDS={3:'level',4:'hp',5:'max_hp',9:'mp',10:'max_mp'}


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
        self._source=None
        self._stats={}
        self._stats_key=None
        self._stat_errors=0
        self._stats_revision=0
        self._stats_applied=-1
        self._stats_limit=False
        self._initial_stats_seeded=False
        self._diagnostics=LiveDiagnostics()
        self._environment=ObservedEnvironment()
        self._environment_applied=-1
        self._snapshot=dict(schema=2,mode='live',bot_id=bot_id,session_id=self.session_id,state='connecting',position=None,
            character=None,entities=[],updated_at_ms=None,heartbeat=dict(sent=0,received=0),
            coverage=dict(vitals='not_verified',level='not_verified',entities='not_verified',movement='not_verified'),
            packets={},error=None)

    def request_stop(self):
        with self._lock:
            if not self._stop.is_set():self._diagnostics.event('stop_requested')
            self._stop.set()
    @property
    def stop_requested(self):return self._stop.is_set()

    def bind_source(self,source_sha256):
        if not isinstance(source_sha256,str) or not re.fullmatch('[a-f0-9]{64}',source_sha256):raise ValueError('Explicit source SHA required')
        if source_sha256==STAT_SOURCE_SHA256 and STAT_NAMES_SOURCE!=STAT_SOURCE_SHA256:raise ValueError('Stat names source differs')
        with self._lock:
            if self._closed or self._source not in (None,source_sha256):raise ValueError('Session source cannot change')
            if self._source is None:self._diagnostics.event('source_bound',source_sha256=source_sha256)
            self._source=source_sha256
            self._environment_applied=-1

    def _apply_stats(self):
        character=self._snapshot['character']
        if character is None or self._stats_applied==self._stats_revision:return
        changed={}
        for stat,name in STAT_FIELDS.items():
            value=self._stats.get(stat)
            number=value['number'] if value else None
            current=number if type(number) is int and 0<=number<=2**53-1 else None
            if current!=character[name]:changed[name]=current
            character[name]=current
        if changed:self._diagnostics.event('vitals_changed',values=changed)
        character['stats']=[dict(id=stat,name=STAT_NAMES.get(stat),value=str(value['number']),source=value['source']) for stat,value in sorted(self._stats.items())]
        character['stat_unit']='native_integer'
        character['stats_semantics']='wire_stat_i64'
        coverage=self._snapshot['coverage']
        if self._source==STAT_SOURCE_SHA256:
            known=sum(character[name] is not None for name in ('hp','max_hp','mp','max_mp'))
            coverage['vitals']='received' if known==4 else 'partial' if known else 'not_received'
            coverage['level']='received' if character['level'] is not None else 'not_received'
            coverage['stats']='partial' if self._stats_limit else 'received' if self._stats else 'decode_error' if self._stat_errors else 'not_received'
        self._snapshot['stat_decode_errors']=self._stat_errors
        self._stats_applied=self._stats_revision

    def packet(self, packet_id, body, *, character_key=None,world_id=None):
        # Unknown traffic is counted, never retained or mistaken for decoded state.
        with self._lock:
            if self._closed:return
            self._diagnostics.packet(packet_id,body)
            counts=self._snapshot['packets']
            key=str(packet_id)
            if key in counts or len(counts)<256:counts[key]=min(counts.get(key,0)+1,2**53-1)
            if packet_id in (301,302,324) and self._source==ENVIRONMENT_SOURCE:
                event=self._environment.receive(packet_id,body,source_sha256=self._source,world_id=world_id,character_key=character_key)
                if event:self._diagnostics.event(event,packet_id=packet_id)
                self._apply_environment()
            if packet_id not in (321,322) or self._source!=STAT_SOURCE_SHA256 or character_key is None:return
            if len(body)>=8 and struct.unpack_from('<Q',body)[0]!=character_key:return
            decoder=decode_stat_change if packet_id==322 else decode_character_level_up
            try:change=decoder(body,source_sha256=self._source)
            except (ValueError,BufferError):
                self._stat_errors=min(self._stat_errors+1,2**53-1)
                self._diagnostics.event('stat_decode_error',packet_id=packet_id)
                self._stats.clear();self._stats_revision+=1;self._apply_stats();return
            if change.entity_key!=character_key:return
            self._diagnostics.event('stats_received',packet_id=packet_id,records=len(change.values))
            if self._stats_key not in (None,character_key):raise RuntimeError('Character identity changed')
            self._stats_key=character_key
            for value in change.values:
                if value.stat_type in self._stats or len(self._stats)<1024:
                    self._stats[value.stat_type]=dict(number=value.signed_second,source='stat_change' if packet_id==322 else 'level_up')
                else:self._stats_limit=True
            self._stats_revision+=1
            self._apply_stats()

    def _apply_environment(self):
        if self._environment_applied==self._environment.revision:return
        state=self._environment.snapshot()
        self._snapshot['entities']=state['entities'];self._snapshot['environment']=state['summary']
        self._snapshot['coverage']['entities']=state['coverage'] if self._source==ENVIRONMENT_SOURCE else 'not_verified'
        self._environment_applied=self._environment.revision

    def publish(self, owner):
        world=owner.world_entry
        if world is None or world.state!='finish_response':
            with self._lock:
                self._environment.world(None);self._apply_environment()
            return
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
            self._environment.world(position.world_id);self._apply_environment()
            if self._stats_key not in (None,key):raise RuntimeError('Character identity changed')
            self._stats_key=key
            if not self._initial_stats_seeded and self._source==STAT_SOURCE_SHA256:
                self._initial_stats_seeded=True
                try:
                    initial=initial_stat_values(selection.response.player.at(0x1c8),source_sha256=self._source)
                except (KeyError,ValueError):
                    self._stat_errors+=1
                else:
                    for stat,value in dict(initial).items():
                        # ID322 can arrive in the same receive batch before world
                        # finish; those later values must beat the initial list.
                        if stat in self._stats:continue
                        if len(self._stats)<1024:self._stats[stat]=dict(number=value,source='selection')
                        else:self._stats_limit=True
                self._stats_revision+=1
            character=self._snapshot['character']
            if character is None or character['world_id']!=position.world_id:
                self._stats_applied=-1
                self._diagnostics.event('world_ready',world_id=position.world_id)
                character=dict(key=str(key),name=name,world_id=position.world_id,
                    position=dict(x=xyz[0],y=xyz[1],z=xyz[2],semantics='server_target_before_engine_correction'),
                    level=None,hp=None,max_hp=None,mp=None,max_mp=None)
            self._snapshot.update(state='connected',updated_at_ms=time.time_ns()//1000000,
                position=projected,character=character,
                heartbeat=dict(sent=heartbeat.queued_count if heartbeat else 0,
                    received=heartbeat.response_count if heartbeat else 0))
            self._apply_stats()

    def close(self, error=None):
        if error is not None and (not isinstance(error,str) or not re.fullmatch('[a-zA-Z0-9_]{1,96}',error)):
            error='session_failed'
        with self._lock:
            if not self._closed:self._diagnostics.event('session_closed',error=error)
            self._closed=True
            self._diagnostics.close()
            self._stats.clear();self._stats_key=None
            self._environment.world(None);self._apply_environment()
            self._snapshot.update(state='disconnected',position=None,character=None,entities=[],
                updated_at_ms=time.time_ns()//1000000,error=error or self._snapshot['error'])

    def snapshot(self,*,for_api=False,entity_page=0):
        if type(entity_page) is not int or entity_page not in (0,1):raise ValueError('Invalid entity page')
        with self._lock:
            value=copy.deepcopy(self._snapshot)
            if for_api:
                total=len(value['entities']);page=entity_page if total>256 else 0
                value['entities']=value['entities'][page*256:(page+1)*256]
                value.setdefault('environment',{}).update(known_count=total,entity_page=page,page_size=256,shown_count=len(value['entities']))
            self._diagnostics.expire()
            value['journal']=copy.deepcopy(list(self._diagnostics.events)[-32:])
            value['journal_cursor']=self._diagnostics.sequence
            value['analysis']=copy.deepcopy(self._diagnostics.analysis)
            value['trace']=dict(packet_ids=list(self._diagnostics.ids),sample_bytes=self._diagnostics.sample_bytes)
        value['uptime_seconds']=round(time.monotonic()-self._started,1)
        return value

    def journal(self,after=0):
        if type(after) is not int or not 0<=after<=2**53-1:raise ValueError('Invalid event cursor')
        with self._lock:return dict(bot_id=self.bot_id,session_id=self.session_id,**self._diagnostics.journal(after))

    def configure_trace(self,lease,ids):
        with self._lock:
            if self._closed:raise RuntimeError('Session closed')
            return self._diagnostics.trace(lease,ids)

    def samples(self,lease,after=0):
        if type(after) is not int or not 0<=after<=2**53-1:raise ValueError('Invalid sample cursor')
        with self._lock:return dict(bot_id=self.bot_id,session_id=self.session_id,source_sha256=self._source,
            **self._diagnostics.read_samples(lease,after))

    def analysis(self,value):
        # Separate observational output; it never overwrites verified character
        # fields, sends commands or executes code in the socket owner.
        if type(value) is not dict or set(value)!={'revision','values','error'}:raise ValueError('Invalid analysis result')
        if not isinstance(value['revision'],str) or not re.fullmatch('[a-f0-9]{64}',value['revision']):raise ValueError('Invalid analysis revision')
        if type(value['values']) is not dict or (value['error'] is not None and
            (not isinstance(value['error'],str) or not re.fullmatch('[a-zA-Z0-9_]{1,64}',value['error']))):raise ValueError('Invalid analysis values')
        if len(json.dumps(value,allow_nan=False).encode())>16384:raise ValueError('Analysis result too large')
        with self._lock:
            if self._closed:raise RuntimeError('Session closed')
            if value!=self._diagnostics.analysis:
                previous=self._diagnostics.analysis
                if previous is None or previous['revision']!=value['revision'] or previous['error']!=value['error']:
                    self._diagnostics.event('analysis_updated',revision=value['revision'],error=value['error'])
                self._diagnostics.analysis=copy.deepcopy(value)
            self._diagnostics.analysis_until=time.monotonic()+6

    def status(self):
        with self._lock:return dict(bot_id=self.bot_id,session_id=self.session_id,state=self._snapshot['state'])


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
        with self._lock:return [s.status() for s in self._sessions.values()]
    def close(self):
        with self._lock:sessions=list(self._sessions.values())
        for session in sessions:session.request_stop()
