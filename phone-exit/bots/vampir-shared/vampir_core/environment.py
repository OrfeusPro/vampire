"""Per-session observed NPC subset, not a complete engine visibility model."""
import copy
import time

from .npc_create_event import SOURCE_SHA256 as CREATE_SOURCE,decode_npc_create_notify
from .sight_leave_event import SOURCE_SHA256 as LEAVE_SOURCE,decode_sight_leave_notify

SOURCE_SHA256='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'


class ObservedEnvironment:
    """Caller holds its session lock; no shared state, disk, network or game commands.

    Initial SightEnter/player records and movement application remain unverified.
    Consequently coverage can only be partial, never a complete nearby census.
    """
    def __init__(self,*,max_entities=512):
        if type(max_entities) is not int or not 1<=max_entities<=512:raise ValueError('Environment capacity must be 1..512')
        if CREATE_SOURCE!=SOURCE_SHA256 or LEAVE_SOURCE!=SOURCE_SHA256:raise ValueError('Environment decoder sources differ')
        self.capacity=max_entities;self.world_id=None;self.entities={}
        self.revision=0
        self.coverage='not_received';self.errors=0;self.packets=0;self.limited=False

    def world(self,world_id):
        if world_id is not None and (type(world_id) is not int or not 0<world_id<=0xffffffff):raise ValueError('Explicit environment world required')
        if self.world_id!=world_id:
            self.world_id=world_id;self.entities.clear();self.coverage='not_received';self.limited=False
            self.revision+=1

    def receive(self,packet_id,body,*,source_sha256,world_id):
        if source_sha256!=SOURCE_SHA256:raise ValueError('Environment source differs')
        if packet_id not in (302,324):return None
        if world_id is None:return None  # Never attach an event to a guessed world.
        self.world(world_id)
        self.revision+=1
        try:
            value=decode_npc_create_notify(body,source_sha256=source_sha256) if packet_id==324 else decode_sight_leave_notify(body,source_sha256=source_sha256)
        except (ValueError,BufferError,TypeError):
            self.entities.clear();self.errors=min(self.errors+1,2**53-1);self.coverage='decode_error'
            return 'environment_decode_error'
        self.packets=min(self.packets+1,2**53-1);self.coverage='partial'
        if packet_id==302:
            for key in value.actor_keys:self.entities.pop(str(key),None)
            # QuestVisibleActor triples are not extra actor-removal keys.
            return 'environment_leave_received'
        n=value.npc;key=str(n.at(8))
        if key not in self.entities and len(self.entities)>=self.capacity:
            self.limited=True;return 'environment_limit_reached'
        def safe(value):return value if type(value) is int and 0<=value<=2**53-1 else None
        try:xyz=n.at(0x18).finite_values()
        except ValueError:xyz=None
        self.entities[key]=dict(key=key,kind='npc',name=None,wire_id=n.at(0x10),world_id=world_id,
            hp=safe(n.at(0x58)),max_hp=safe(n.at(0x60)),level=None,
            stats_semantics='server_create_stats',stats_current=False,
            position=dict(zip(('x','y','z'),xyz)) if xyz is not None else None,
            position_semantics='server_create_position',position_current=False,
            received_at_ms=time.time_ns()//1000000,source='npc_create_notify')
        return 'environment_create_received'

    def snapshot(self):
        return dict(entities=copy.deepcopy(list(self.entities.values())),coverage=self.coverage,
            summary=dict(world_id=self.world_id,scope='npc_create_and_sight_leave',complete=False,
                decoded_packets=self.packets,decode_errors=self.errors,limit_reached=self.limited,
                movement_applied=False,players_received=False))
