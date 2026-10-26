"""Per-session observed NPC/player subset, not a complete engine visibility model."""
import copy
import time

from .npc_create_event import SOURCE_SHA256 as CREATE_SOURCE,decode_npc_create_notify
from .sight_leave_event import SOURCE_SHA256 as LEAVE_SOURCE,decode_sight_leave_notify
from .sight_enter_event import SOURCE_SHA256 as SIGHT_SOURCE,decode_sight_enter

SOURCE_SHA256='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'


class ObservedEnvironment:
    """Caller holds its session lock; no shared state, disk, network or game commands.

    Entry observations do not imply current engine positions or a complete census.
    Source-confirmed NPC and NnCharacterPC fields stay separate from own vitals.
    """
    def __init__(self,*,max_entities=512):
        if type(max_entities) is not int or not 1<=max_entities<=512:raise ValueError('Environment capacity must be 1..512')
        if any(source!=SOURCE_SHA256 for source in (CREATE_SOURCE,LEAVE_SOURCE,SIGHT_SOURCE)):raise ValueError('Environment decoder sources differ')
        self.capacity=max_entities;self.world_id=None;self.entities={}
        self.revision=0
        self.coverage='not_received';self.errors=0;self.packets=0;self.limited=False
        self.sight_received=False;self.players_received=False;self.other_records={};self.skipped_players=0

    def world(self,world_id):
        if world_id is not None and (type(world_id) is not int or not 0<world_id<=0xffffffff):raise ValueError('Explicit environment world required')
        if self.world_id!=world_id:
            self.world_id=world_id;self.entities.clear();self.coverage='not_received';self.limited=False
            self.sight_received=False;self.players_received=False;self.other_records={};self.skipped_players=0
            self.revision+=1

    def receive(self,packet_id,body,*,source_sha256,world_id,character_key=None):
        if source_sha256!=SOURCE_SHA256:raise ValueError('Environment source differs')
        if packet_id not in (301,302,324):return None
        if world_id is None:return None  # Never attach an event to a guessed world.
        self.world(world_id)
        self.revision+=1
        try:
            if packet_id==301:value=decode_sight_enter(body,source_sha256=source_sha256,max_collection_items=4096)
            elif packet_id==324:value=decode_npc_create_notify(body,source_sha256=source_sha256)
            else:value=decode_sight_leave_notify(body,source_sha256=source_sha256)
        except (ValueError,BufferError,TypeError):
            self.entities.clear();self.errors=min(self.errors+1,2**53-1);self.coverage='decode_error'
            self.sight_received=False;self.players_received=False;self.other_records={};self.skipped_players=0
            return 'environment_decode_error'
        self.packets=min(self.packets+1,2**53-1);self.coverage='partial'
        if packet_id==302:
            for key in value.actor_keys:
                self.entities.pop(str(key),None);self.entities.pop('player:'+str(key),None)
            # QuestVisibleActor triples are not extra actor-removal keys.
            return 'environment_leave_received'
        now=time.time_ns()//1000000
        if packet_id==324:
            return 'environment_create_received' if self._store(self._npc(value.npc,world_id,now,False)) else 'environment_limit_reached'
        self.sight_received=True
        self.other_records={name:len(value.at(offset) or ()) for name,offset in
            (('ground_effects',0x30),('gadgets',0x40),('projectiles',0x50),('tether_effects',0x70))}
        accepted=True
        for record in value.at(0x20):accepted=self._store(self._npc(record.at(8),world_id,now,True)) and accepted
        own_key_known=type(character_key) is int and 0<=character_key<=2**64-1
        self.skipped_players=0 if own_key_known else len(value.at(0x10))
        if own_key_known:
            self.players_received=True
            for record in value.at(0x10):
                if record.at(8)!=character_key:accepted=self._store(self._player(record,world_id,now)) and accepted
        return 'environment_sight_received' if accepted else 'environment_limit_reached'

    @staticmethod
    def _safe(value):return value if type(value) is int and 0<=value<=2**53-1 else None

    @staticmethod
    def _position(vector):
        try:return dict(zip(('x','y','z'),vector.finite_values()))
        except ValueError:return None

    def _npc(self,n,world_id,now,sight):
        return dict(key=str(n.at(8)),kind='npc',name=None,wire_id=n.at(0x10),world_id=world_id,
            hp=self._safe(n.at(0x58)),max_hp=self._safe(n.at(0x60)),level=None,
            stats_semantics='server_sight_stats' if sight else 'server_create_stats',stats_current=False,
            position=self._position(n.at(0x18)),position_semantics='server_sight_position' if sight else 'server_create_position',position_current=False,
            received_at_ms=now,source='sight_enter_notify' if sight else 'npc_create_notify')

    def _player(self,record,world_id,now):
        stats={row.at(8):row.at(0x10) for row in record.at(0xc8)}
        label=record.at(0x20)
        value=dict(key=str(record.at(8)),kind='player',name=label[:32],wire_id=None,world_id=world_id,
            level=self._safe(stats.get(3)),hp=self._safe(stats.get(4)),max_hp=self._safe(stats.get(5)),
            mp=self._safe(stats.get(9)),max_mp=self._safe(stats.get(10)),stats_semantics='server_sight_stats',stats_current=False,
            position=self._position(record.at(0x88)),position_semantics='server_sight_position',position_current=False,
            received_at_ms=now,source='sight_enter_notify')
        if len(label)>32:value['name_truncated']=True
        return value

    def _store(self,value):
        # Preserve the existing NPC key API, while never coalescing different
        # wire record kinds merely because their numeric keys coincide.
        identity=('player:' if value['kind']=='player' else '')+value['key']
        if identity not in self.entities and len(self.entities)>=self.capacity:
            self.limited=True;return False
        self.entities[identity]=value;return True

    def snapshot(self):
        return dict(entities=copy.deepcopy(list(self.entities.values())),coverage=self.coverage,
            summary=dict(world_id=self.world_id,scope='npc_player_create_sight_enter_leave',complete=False,
                decoded_packets=self.packets,decode_errors=self.errors,limit_reached=self.limited,
                movement_applied=False,players_received=self.players_received,sight_received=self.sight_received,
                other_records=copy.deepcopy(self.other_records),skipped_players_without_own_key=self.skipped_players))
