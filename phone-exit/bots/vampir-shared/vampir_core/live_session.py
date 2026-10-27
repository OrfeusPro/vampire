"""Single-owner live state, bounded in memory; no raw packet persistence."""
import copy
import hashlib
import secrets
import re
import struct
from threading import Event, Lock
import time
from .stat_change import SOURCE_SHA256 as STAT_SOURCE_SHA256,decode_stat_change,decode_character_level_up,initial_stat_values
from .stat_names import STAT_NAMES,SOURCE_SHA256 as STAT_NAMES_SOURCE
from .live_diagnostics import LiveDiagnostics
from .environment import ObservedEnvironment,SOURCE_SHA256 as ENVIRONMENT_SOURCE
from .tutorial_update import decode_tutorial_update
from .quest_sync import decode_quest_sync
from .quest_update_result import decode_quest_update_result
from .world_move_start import CURRENT_PROBE_SOURCE
from .action_queue import ActionNotQueued,SessionActionQueue,SCHEMAS,digest,validate_policy
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
        if projection is not None:
            from .map_position import MapProjection
            if not isinstance(projection,MapProjection):raise TypeError('Verified map projection required')
        self.projection=projection
        self._stop=Event()
        self._lock=Lock()
        self._started=time.monotonic()
        self._closed=False
        self._actions=None
        self._action_owner=None
        self._action_connection=None
        self._quest_transport=None
        self._quest_step=None
        self._action_offers=[]
        self._action_scope=None
        self._policy=dict(skip_dialogues=True,auto_quests=False)
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
            character=None,entities=[],quest_update_result=None,quest_result_decode_errors=0,tutorial=None,tutorial_decode_errors=0,quests=[],quest_snapshot=None,quest_decode_errors=0,updated_at_ms=None,heartbeat=dict(sent=0,received=0),
            coverage=dict(vitals='not_verified',level='not_verified',entities='not_verified',movement='not_verified',tutorial='not_verified',quests='not_verified',quest_result='not_verified'),
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
        if self.projection is not None and self.projection.source_sha256!=source_sha256:raise ValueError('Projection and session sources differ')
        with self._lock:
            if self._closed or self._source not in (None,source_sha256):raise ValueError('Session source cannot change')
            if self._source is None:self._diagnostics.event('source_bound',source_sha256=source_sha256)
            self._source=source_sha256
            if source_sha256==CURRENT_PROBE_SOURCE and self._snapshot['coverage']['tutorial']=='not_verified':
                self._snapshot['coverage']['tutorial']='not_received'
            if source_sha256==CURRENT_PROBE_SOURCE and self._snapshot['coverage']['quests']=='not_verified':
                self._snapshot['coverage']['quests']='not_received'
            if source_sha256==CURRENT_PROBE_SOURCE and self._snapshot['coverage']['quest_result']=='not_verified':
                self._snapshot['coverage']['quest_result']='not_received'
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
            self._sync_quest_transport()
            self._diagnostics.packet(packet_id,body)
            counts=self._snapshot['packets']
            key=str(packet_id)
            if key in counts or len(counts)<256:counts[key]=min(counts.get(key,0)+1,2**53-1)
            if packet_id==1811 and self._source==CURRENT_PROBE_SOURCE:
                self._receive_quest_result(body,character_key,world_id)
            if packet_id==1854 and self._source==CURRENT_PROBE_SOURCE:
                if type(character_key) is int and 0<=character_key<2**64 and type(world_id) is int and 0<=world_id<2**32:
                    self._receive_quests(body,character_key,world_id)
            if packet_id==9905 and self._source==CURRENT_PROBE_SOURCE:
                try:
                    update=decode_tutorial_update(body,source_sha256=self._source,max_records=64,max_payload_size=835)
                except (ValueError,BufferError):
                    self._snapshot['tutorial']=None
                    self._snapshot['coverage']['tutorial']='decode_error'
                    self._snapshot['tutorial_decode_errors']=min(self._snapshot['tutorial_decode_errors']+1,2**53-1)
                    self._diagnostics.event('tutorial_decode_error',packet_id=packet_id)
                else:
                    # This is an observation of one message, not the client's
                    # applied tutorial map or permission to advance a task.
                    self._snapshot['tutorial']=dict(semantics='last_received_message',applied_to_local_task=False,
                        flag=update.flag,records=[dict(raw08=r.raw08,raw0c=r.raw0c,raw10=r.raw10,state=r.state) for r in update.records],
                        character_key=str(character_key) if type(character_key) is int and 0<=character_key<2**64 else None,
                        world_id=world_id if type(world_id) is int and 0<=world_id<2**32 else None,
                        received_at_ms=time.time_ns()//1000000)
                    self._snapshot['coverage']['tutorial']='last_received_message'
                    self._diagnostics.event('tutorial_received',packet_id=packet_id,records=len(update.records))
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

    def _sync_quest_transport(self):
        # Connection callback never takes session lock, so HTTP snapshot can
        # inspect a receipt without touching its socket or outbound queue.
        receipt=self._quest_transport
        if receipt is None or self._action_connection is None:return
        state=self._action_connection.quest_send_status(receipt['ticket'])
        if receipt['status']!=state:
            receipt['status']=state
            if state=='socket_accepted':
                receipt['progress_baseline']=self._quest_progress_value(receipt['quest_id'])
            self._diagnostics.event('quest_transport_updated',request_id=receipt['request_id'],status=state)

    def _quest_progress_value(self,quest_id):
        rows=[r for r in self._snapshot['quests'] if r['id']==quest_id]
        if len(rows)!=1:return None
        row=rows[0]
        return dict(state=row['state'],progress=copy.deepcopy(row['progress']))

    def _quest_observation_receipt(self,character_key,world_id):
        receipt=self._quest_transport
        if (receipt is None or receipt['status']!='socket_accepted'
                or time.monotonic()>receipt['_deadline']
                or (receipt['character_key'],receipt['world_id'])!=(str(character_key),world_id)
                or self._scope()!=(str(character_key),world_id)):return None
        return receipt

    def _receive_quest_result(self,body,character_key,world_id):
        # Caller holds session lock. A complete response is an observation, not
        # a receipt for an intent and not a replacement for the ID1854 snapshot.
        character=self._snapshot['character']
        if (character is None or type(character_key) is not int or type(world_id) is not int
                or not 0<=character_key<2**64 or not 0<=world_id<2**32
                or (str(character_key),world_id)!=(character['key'],character['world_id'])):return
        try:result=decode_quest_update_result(body,source_sha256=self._source)
        except ValueError:
            self._snapshot['quest_update_result']=None
            self._snapshot['quest_result_decode_errors']=min(self._snapshot['quest_result_decode_errors']+1,2**53-1)
            self._snapshot['coverage']['quest_result']='decode_error'
            self._diagnostics.event('quest_result_decode_error',packet_id=1811)
            return
        self._snapshot['quest_update_result']=dict(packet_id=1811,result_code=result.result_code,
            quest_id=str(result.quest_id),state=result.state,
            progress=dict(raw08=result.progress.raw08,raw10=str(result.progress.raw10),raw18=str(result.progress.raw18)),
            character_key=str(character_key),world_id=world_id,received_at_ms=time.time_ns()//1000000,
            semantics='last_received_message',applied_to_local_task=False,action_confirmed=False,
            correlation='not_established')
        receipt=self._quest_observation_receipt(character_key,world_id)
        if receipt is not None and receipt['quest_id']==str(result.quest_id):
            observed=dict(result_code=result.result_code,state=result.state,
                task_index=result.progress.raw08,index_matches_sent=result.progress.raw08==receipt['task_index'])
            if receipt['observations']['reply']!=observed:
                receipt['observations']['reply']=observed
                self._diagnostics.event('quest_reply_candidate',request_id=receipt['request_id'],
                    result_code=result.result_code,index_matches_sent=observed['index_matches_sent'])
            self._snapshot['quest_update_result']['correlation']='same_scope_quest_after_socket_acceptance'
            self._snapshot['quest_update_result']['candidate_request_id']=receipt['request_id']
        self._snapshot['coverage']['quest_result']='last_received_message'
        self._diagnostics.event('quest_update_result_received',packet_id=1811,result_code=result.result_code,
            quest_id=str(result.quest_id),state=result.state,task_index=result.progress.raw08)

    def _receive_quests(self,body,character_key,world_id):
        # Called under the owner lock. Keep only a complete bounded message;
        # neither record state nor raw08 is interpreted as an active task.
        character=self._snapshot['character']
        if character and (character['key'],character['world_id'])!=(str(character_key),world_id):return
        try:
            message=decode_quest_sync(body,source_sha256=self._source,
                max_collection_items=128,max_total_items=128,max_payload_size=8192)
        except (ValueError,BufferError):
            self._snapshot.update(quests=[],quest_snapshot=None)
            self._snapshot['quest_decode_errors']=min(self._snapshot['quest_decode_errors']+1,2**53-1)
            self._snapshot['coverage']['quests']='decode_error'
            self._diagnostics.event('quest_decode_error',packet_id=1854)
            return
        rows=[]
        for group_index,group in enumerate(message.groups):
            for record_index,r in enumerate(group.quests):
                rows.append(dict(id=str(r.raw08),title=None,group=group.raw08,group_index=group_index,
                    record_index=record_index,state=r.raw10,progress=dict(raw08=r.progress.raw08,
                    raw10=str(r.progress.raw10),raw18=str(r.progress.raw18)),raw38=r.raw38,
                    raw3c=r.raw3c,raw40=r.raw40,raw44=r.raw44))
        self._snapshot.update(quests=rows,quest_snapshot=dict(semantics='last_received_message',
            applied_to_local_task=False,character_key=str(character_key),world_id=world_id,
            group_types=[g.raw08 for g in message.groups],raw18=str(message.raw18),
            received_at_ms=time.time_ns()//1000000))
        receipt=self._quest_observation_receipt(character_key,world_id)
        if receipt is not None:
            matches=[r for r in rows if r['id']==receipt['quest_id']]
            value=self._quest_progress_value(receipt['quest_id'])
            baseline=receipt['progress_baseline']
            observed=dict(matches=len(matches),baseline_known=baseline is not None,
                changed=bool(baseline is not None and value is not None and value!=baseline),
                current=value)
            if receipt['observations']['progress']!=observed:
                receipt['observations']['progress']=observed
                self._diagnostics.event('quest_progress_candidate',request_id=receipt['request_id'],
                    matches=len(matches),changed=observed['changed'])
        self._snapshot['coverage']['quests']='last_received_message'
        self._diagnostics.event('quests_received',packet_id=1854,records=len(rows),groups=len(message.groups))

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
            quest_context=self._snapshot['quest_snapshot']
            if quest_context and (quest_context['character_key']!=str(key) or quest_context['world_id']!=position.world_id):
                self._snapshot.update(quests=[],quest_snapshot=None)
                self._snapshot['coverage']['quests']='not_received'
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
                self._action_offers=[];self._action_scope=None
                self._snapshot['quest_update_result']=None
                self._snapshot['coverage']['quest_result']='not_received' if self._source==CURRENT_PROBE_SOURCE else 'not_verified'
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
            if self._actions:self._actions.close(self._action_owner)
            if self._quest_transport is not None:
                # Session close does not assert whether its connection sent bytes.
                self._quest_transport=None
            self._action_connection=None
            self._quest_step=None
            self._action_offers=[]
            if not self._closed:self._diagnostics.event('session_closed',error=error)
            self._closed=True
            self._diagnostics.close()
            self._stats.clear();self._stats_key=None
            self._environment.world(None);self._apply_environment()
            self._snapshot.update(state='disconnected',position=None,character=None,entities=[],quest_update_result=None,tutorial=None,quests=[],quest_snapshot=None,
                updated_at_ms=time.time_ns()//1000000,error=error or self._snapshot['error'])
            self._snapshot['coverage']['tutorial']='not_received' if self._source==CURRENT_PROBE_SOURCE else 'not_verified'
            self._snapshot['coverage']['quests']='not_received' if self._source==CURRENT_PROBE_SOURCE else 'not_verified'
            self._snapshot['coverage']['quest_result']='not_received' if self._source==CURRENT_PROBE_SOURCE else 'not_verified'

    def _interaction_view(self,queue):
        """Publish only trusted owner offers; does not invent received prompts."""
        person=self._snapshot['character']
        if self._source!=CURRENT_PROBE_SOURCE or self._snapshot['state']!='connected' or person is None:return None
        ready=self._action_connection is not None and not self._stop.is_set() and not queue['closed']
        busy=queue['blocked'] or any(r['status'] in ('queued','executing','sent') for r in queue['records'])
        actions=[];quests=[];step=self._quest_step
        if step is not None:
            context,_=self._quest_step_context(step['payload'])
            offer=dict(kind='quest_follow',context=step['context'],arguments={'quest_id':str(step['payload'].raw30)})
            valid=context==step['context'] and self._scope()==self._action_scope and offer in self._action_offers
            supported='quest_follow' in queue['capabilities']
            enabled=ready and valid and supported and not busy
            reason=None if enabled else ('Ожидание результата предыдущего действия' if busy else
                'Состояние задания изменилось' if not valid else 'Действие не подключено владельцем')
            action_id='quest-'+str(step['payload'].raw30)+'-'+step['context'][:24]
            actions.append(dict(id=action_id,**offer,enabled=enabled,reason=reason))
            quests.append(dict(quest_id=str(step['payload'].raw30),action_id=action_id))
        view=dict(semantics='owner_action_offers',source_sha256=self._source,character_key=person['key'],
            world_id=person['world_id'],messages_known=False,messages=[],actions_ready=ready,
            actions=actions,quest_actions=quests,action_results=copy.deepcopy(queue['records']),
            automation=dict(state='unknown' if queue['blocked'] else 'idle'))
        view['revision']=hashlib.sha256(json.dumps(view,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
        return view

    def snapshot(self,*,for_api=False,entity_page=0):
        if type(entity_page) is not int or entity_page not in (0,1):raise ValueError('Invalid entity page')
        with self._lock:
            self._sync_quest_transport()
            value=copy.deepcopy(self._snapshot)
            if self._quest_transport is not None:
                value['quest_transport']=copy.deepcopy({k:v for k,v in self._quest_transport.items() if k!='ticket' and not k.startswith('_')})
            if for_api:
                total=len(value['entities']);page=entity_page if total>256 else 0
                value['entities']=value['entities'][page*256:(page+1)*256]
                value.setdefault('environment',{}).update(known_count=total,entity_page=page,page_size=256,shown_count=len(value['entities']))
            self._diagnostics.expire()
            value['journal']=copy.deepcopy(list(self._diagnostics.events)[-32:])
            value['journal_cursor']=self._diagnostics.sequence
            value['analysis']=copy.deepcopy(self._diagnostics.analysis)
            value['trace']=dict(packet_ids=list(self._diagnostics.ids),sample_bytes=self._diagnostics.sample_bytes)
            if self._actions:
                value['action_queue']=self._actions.snapshot()
                interaction=self._interaction_view(value['action_queue'])
                if interaction is not None:value['interaction']=interaction
                value['action_policy']=self._policy.copy()
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

    def install_actions(self,owner_key,*,contracts,connection=None):
        """Explicit owner admission; no contracts or handlers are inferred from UI."""
        with self._lock:
            if self._closed or self._source is None or self._actions is not None:raise RuntimeError('Action owner unavailable')
            if connection is not None:
                from .game_connection import GameConnection
                if type(connection) is not GameConnection or connection.world_entry is None or connection.world_entry.source_sha256!=self._source:
                    raise ValueError('Explicit source-bound game connection required')
            self._actions=SessionActionQueue(bot_id=self.bot_id,session_id=self.session_id,source_sha256=self._source,
                owner_key=owner_key,contracts=contracts)
            self._action_owner=owner_key
            self._action_connection=connection

    def _action_ready(self):
        if self._closed or self._stop.is_set() or self._actions is None or self._snapshot['state']!='connected':
            raise RuntimeError('Action channel unavailable')

    def _scope(self):
        person=self._snapshot['character']
        return (person.get('key'),person.get('world_id')) if person else None

    def offer_actions(self,owner_key,offers):
        """Owner publishes exact intents from its decoder; not an HTTP operation."""
        if type(offers) is not list or len(offers)>48:raise ValueError('Invalid action offers')
        clean=[]
        for offer in offers:
            if type(offer) is not dict or set(offer)!={'kind','context','arguments'}:raise ValueError('Invalid action offer')
            kind=offer['kind'];arguments=offer['arguments'];digest(offer['context'])
            if type(kind) is not str or kind not in SCHEMAS or type(arguments) is not dict or set(arguments)!=SCHEMAS[kind]:
                raise ValueError('Invalid offered arguments')
            if any(type(v) is not str or not re.fullmatch('(?:0|[1-9][0-9]{0,19})',v) or int(v)>0xffffffffffffffff for v in arguments.values()):
                raise ValueError('Invalid offered ID')
            clean.append(copy.deepcopy(offer))
        with self._lock:
            self._action_ready()
            if owner_key is not self._action_owner:raise RuntimeError('Socket owner required')
            self._action_offers=clean;self._action_scope=self._scope();self._quest_step=None

    def _quest_step_context(self,payload):
        rows=[r for r in self._snapshot['quests'] if r['id']==str(payload.raw30)]
        row=rows[0] if len(rows)==1 else None
        context=dict(source=self._source,scope=self._scope(),quest=row,
            vector=payload.vector,target=payload.raw28,index=payload.raw38)
        # Reception time/heartbeat are deliberately excluded. Current wire row
        # and actor/world scope must remain identical until the owner dispatch.
        return hashlib.sha256(json.dumps(context,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest(),row

    def offer_quest_step(self,owner_key,*,payload):
        """Trusted owner binds one already-admitted selected-step payload.

        Does not infer task data, corrected actor position or next step. Caller
        must establish those source-bound conditions before publishing the offer.
        """
        from .quest_update import QuestUpdate,encode_quest_update
        if type(payload) is not QuestUpdate:raise TypeError('Typed selected quest step required')
        encode_quest_update(payload,source_sha256=self._source)
        with self._lock:
            self._action_ready()
            if owner_key is not self._action_owner or self._action_connection is None:raise RuntimeError('Bound socket owner required')
            context,row=self._quest_step_context(payload)
            if (row is None or row['state']!=2 or row['progress']['raw08']!=payload.raw38
                    or self._snapshot['coverage']['quests']!='last_received_message'):
                raise ValueError('Selected quest does not match observed owner state')
            offer=dict(kind='quest_follow',context=context,arguments={'quest_id':str(payload.raw30)})
            self._action_offers=[offer];self._action_scope=self._scope()
            self._quest_step=dict(context=context,payload=payload)
            self._diagnostics.event('quest_step_offered',quest_id=str(payload.raw30),task_index=payload.raw38)
            return copy.deepcopy(offer)

    def pump_quest_actions(self,connection):
        """One owner-loop tick; HTTP never calls this or builds payloads."""
        with self._lock:
            if self._closed or self._stop.is_set() or self._quest_step is None:return None
            if connection is not self._action_connection:raise RuntimeError('Quest pump connection differs')
            step=self._quest_step;key=self._action_owner
            context,_=self._quest_step_context(step['payload'])
            if context!=step['context']:
                self._quest_step=None;self._action_offers=[]
        # Claim checks queued context/scope/policy again. Stale context fails
        # before enqueue; a successfully taken step is consumed even on failure.
        intent=self.claim_action(key,context=context)
        if intent is None:return None
        try:return self.dispatch_quest_action(key,intent['request_id'],context=context,payload=step['payload'])
        finally:
            with self._lock:
                if self._quest_step is step:
                    self._quest_step=None;self._action_offers=[]

    def enqueue_action(self,value):
        if type(value) is not dict or set(value)!={'request_id','kind','context','arguments','policy','origin'}:raise ValueError('Invalid intent')
        with self._lock:
            self._action_ready()
            previous=self._actions.previous(**value)
            if previous is not None:return dict(bot_id=self.bot_id,session_id=self.session_id,**previous)
            # Compare exact owner offers, not merely a client supplied context SHA.
            offer={k:value[k] for k in ('kind','context','arguments')}
            if self._scope()!=self._action_scope or offer not in self._action_offers:raise RuntimeError('Action not currently offered')
            validate_policy(value['policy'])
            if value['origin']=='auto_skip' and not self._policy['skip_dialogues']:raise RuntimeError('Automatic skip disabled')
            result=self._actions.enqueue(bot_id=self.bot_id,session_id=self.session_id,**value)
            self._diagnostics.event('action_intent',request_id=result['request_id'],action_kind=result['kind'],status=result['status'])
            return dict(bot_id=self.bot_id,session_id=self.session_id,**result)

    def configure_policy(self,value):
        policy=validate_policy(value)
        with self._lock:
            self._action_ready();self._policy=policy
            self._diagnostics.event('action_policy_updated',**policy)
            return dict(bot_id=self.bot_id,session_id=self.session_id,status='policy_updated',policy=policy.copy())

    def claim_action(self,owner_key,*,context):
        with self._lock:
            self._action_ready()
            if owner_key is not self._action_owner:raise RuntimeError('Socket owner required')
            intent=self._actions.claim(owner_key,context=context)
            if intent is None:return None
            offered={k:intent[k] for k in ('kind','context','arguments')}
            if self._scope()!=self._action_scope or offered not in self._action_offers or (intent['origin']=='auto_skip' and not self._policy['skip_dialogues']):
                self._actions.resolve(owner_key,intent['request_id'],status='failed');return None
            return dict(intent,current_policy=self._policy.copy())

    def dispatch_quest_action(self,owner_key,request_id,*,context,payload):
        """Owner supplies a source-verified selected-task payload, never HTTP.

        This joins an already claimed intent to its bound connection. It does
        not derive task index/target/vector or infer a server confirmation.
        """
        from .quest_update import QuestUpdate
        with self._lock:
            self._action_ready()
            if owner_key is not self._action_owner:raise RuntimeError('Socket owner required')
            def enqueue(intent):
                offer={k:intent[k] for k in ('kind','context','arguments')}
                if (self._action_connection is None or self._scope()!=self._action_scope
                        or offer not in self._action_offers or intent['kind']!='quest_follow'
                        or intent['origin']!='manual' or type(payload) is not QuestUpdate
                        or payload.raw30!=int(intent['arguments']['quest_id'])):
                    raise ActionNotQueued()
                connection=self._action_connection
                world=connection.world_entry
                if (not connection.active or world is None or world.target_position is None
                        or self._scope()!=(str(connection.selection.response.player.at(8)),world.target_position.world_id)):
                    raise ActionNotQueued()
                self._sync_quest_transport()
                previous=self._quest_transport
                if previous is not None:
                    if previous['status']=='queued':raise ActionNotQueued()
                    connection.release_quest_send(previous['ticket']);self._quest_transport=None
                try:
                    ticket=connection.queue_tracked_quest_update(payload,source_sha256=self._source)
                    self._quest_transport=dict(ticket=ticket,request_id=request_id,quest_id=str(payload.raw30),
                        task_index=payload.raw38,character_key=self._scope()[0],world_id=self._scope()[1],
                        status='queued',semantics='local_transport_only',server_confirmed=False,
                        progress_baseline=None,observations=dict(reply=None,progress=None,causality='not_proven'),
                        _deadline=time.monotonic()+10)
                except (ValueError,TypeError,BufferError,RuntimeError):raise ActionNotQueued() from None
            result=self._actions.queue_claimed(owner_key,request_id,context=context,enqueue=enqueue)
            self._diagnostics.event('action_dispatch',request_id=result['request_id'],action_kind=result['kind'],status=result['status'])
            return dict(bot_id=self.bot_id,session_id=self.session_id,**result)

    def action_sent(self,owner_key,request_id):
        with self._lock:
            self._action_ready();self._actions.sent(owner_key,request_id)

    def resume_actions_after_sync(self,owner_key,*,context):
        with self._lock:
            self._action_ready()
            if owner_key is not self._action_owner:raise RuntimeError('Socket owner required')
            if self._scope()!=self._action_scope or not any(o['context']==context for o in self._action_offers):
                raise RuntimeError('New owner offer required')
            self._actions.resume_after_sync(owner_key,context=context)

    def resolve_action(self,owner_key,request_id,*,status):
        with self._lock:
            if self._actions is None:raise RuntimeError('Action channel unavailable')
            self._actions.resolve(owner_key,request_id,status=status)


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
