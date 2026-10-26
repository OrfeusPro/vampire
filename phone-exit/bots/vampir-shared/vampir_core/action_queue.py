"""Session-bound intents; only the socket owner claims/results, never HTTP sends."""
from collections import deque
import copy
import hashlib
import json
import re
from threading import Lock
import time
from types import MappingProxyType

SCHEMAS=MappingProxyType({
    'quest_follow':frozenset({'quest_id'}),
    'dialogue_select':frozenset({'dialogue_id','choice_id'}),
    'dialogue_skip':frozenset({'dialogue_id'}),
    'tutorial_equip':frozenset({'item_instance_id'}),
})
TERMINAL={'confirmed','failed','unknown'}


def digest(value):
    if type(value) is not str or not re.fullmatch('[a-f0-9]{64}',value):raise ValueError('Explicit state/contract SHA required')
    return value


def validate_policy(value):
    if type(value) is not dict or set(value)!={'skip_dialogues','auto_quests'} or any(type(v) is not bool for v in value.values()):
        raise ValueError('Explicit boolean action policy required')
    return value.copy()


def intent_fingerprint(kind,context,arguments,policy,origin):
    return hashlib.sha256(json.dumps([kind,context,arguments,policy,origin],sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


class ActionNotQueued(Exception):
    """Trusted adapter proved that no outbound frame was accepted."""


class SessionActionQueue:
    def __init__(self,*,bot_id,session_id,source_sha256,owner_key,contracts=None,clock=time.monotonic,
                 capacity=16,history=64,total_limit=4096):
        if not re.fullmatch('[a-zA-Z0-9_-]{1,48}',bot_id) or not re.fullmatch('[a-f0-9]{32}',session_id):
            raise ValueError('Explicit session identity required')
        if owner_key is None:raise ValueError('Private owner key required')
        if any(type(v) is not int for v in (capacity,history,total_limit)) or not 1<=capacity<=16 or not capacity<=history<=64 or not history<=total_limit<=4096:
            raise ValueError('Invalid action budgets')
        contracts=dict(contracts or {})
        if not set(contracts)<=SCHEMAS.keys():raise ValueError('Unknown action contract')
        for value in contracts.values():digest(value)
        self.bot_id,self.session_id,self.source_sha256=bot_id,session_id,digest(source_sha256)
        self._owner_key,self._contracts,self._clock=owner_key,contracts,clock
        self._capacity,self._history,self._total_limit=capacity,history,total_limit
        self._lock=Lock();self._records={};self._seen={};self._pending=deque();self._closed=False
        self._blocked=False;self._fenced_context=None

    def _owner(self,key):
        if key is not self._owner_key:raise RuntimeError('Socket owner required')

    def _summary(self,row):
        return {key:row[key] for key in ('request_id','kind','status','reason')}

    def _set(self,row,status,reason=None):
        row.update(status=status,reason=reason)
        self._seen[row['request_id']]['summary']=self._summary(row)
        if status=='unknown':
            self._blocked=True;self._fenced_context=row['context']
            for pending in self._records.values():
                if pending['status']=='queued':self._set(pending,'failed','prior_action_unconfirmed')

    def _refresh(self):
        now=self._clock()
        for row in self._records.values():
            if row['status'] not in TERMINAL and now>=row['deadline']:
                self._set(row,'failed' if row['status']=='queued' else 'unknown',
                    'expired_before_send' if row['status']=='queued' else 'outcome_unconfirmed')
        self._pending=deque(key for key in self._pending if self._records[key]['status']=='queued')

    def enqueue(self,*,bot_id,session_id,request_id,kind,context,arguments,policy=None,origin='manual'):
        if (bot_id,session_id)!=(self.bot_id,self.session_id):raise ValueError('Action session mismatch')
        if type(request_id) is not str or not re.fullmatch('[a-f0-9]{32}',request_id):raise ValueError('Explicit request ID required')
        if type(kind) is not str or kind not in SCHEMAS:raise ValueError('Unknown action kind')
        digest(context)
        if type(arguments) is not dict or set(arguments)!=SCHEMAS[kind]:raise ValueError('Invalid action arguments')
        if any(type(v) is not str or not re.fullmatch('(?:0|[1-9][0-9]{0,19})',v) or int(v)>0xffffffffffffffff for v in arguments.values()):
            raise ValueError('Bounded decimal action IDs required')
        arguments=arguments.copy()
        policy=validate_policy(policy if policy is not None else dict(skip_dialogues=True,auto_quests=False))
        if origin not in ('manual','auto_skip') or (origin=='auto_skip' and (kind!='dialogue_skip' or not policy['skip_dialogues'])):
            raise ValueError('Invalid action origin')
        fingerprint=intent_fingerprint(kind,context,arguments,policy,origin)
        with self._lock:
            self._refresh()
            prior=self._seen.get(request_id)
            if prior:
                if prior['fingerprint']!=fingerprint:raise ValueError('Request ID reused with different intent')
                return prior['summary'].copy()
            if self._closed:raise RuntimeError('Action queue closed')
            if self._blocked:raise RuntimeError('Authoritative state synchronization required')
            if kind not in self._contracts:raise RuntimeError('Action contract unavailable')
            if len(self._seen)>=self._total_limit:raise BufferError('Action session limit reached')
            if sum(row['status'] not in TERMINAL for row in self._records.values())>=self._capacity:
                raise BufferError('Action queue full')
            while len(self._records)>=self._history:
                retired=next((key for key,row in self._records.items() if row['status'] in TERMINAL),None)
                if retired is None:raise BufferError('Action history full')
                del self._records[retired]
            row=dict(request_id=request_id,kind=kind,context=context,arguments=arguments,status='queued',reason=None,
                contract=self._contracts[kind],policy=policy,origin=origin,deadline=self._clock()+5)
            self._seen[request_id]=dict(fingerprint=fingerprint,summary=self._summary(row))
            self._records[request_id]=row;self._pending.append(request_id)
            return self._summary(row)

    def previous(self,*,request_id,kind,context,arguments,policy,origin):
        """A retired offer may still have a known receipt; this never enqueues."""
        if type(request_id) is not str or not re.fullmatch('[a-f0-9]{32}',request_id):raise ValueError('Explicit request ID required')
        fingerprint=intent_fingerprint(kind,context,arguments,validate_policy(policy),origin)
        with self._lock:
            self._refresh();prior=self._seen.get(request_id)
            if prior is None:return None
            if prior['fingerprint']!=fingerprint:raise ValueError('Request ID reused with different intent')
            return prior['summary'].copy()

    def claim(self,owner_key,*,context):
        self._owner(owner_key);digest(context)
        with self._lock:
            self._refresh()
            if self._blocked:return None
            # One outstanding execution per account; other accounts are independent.
            if any(row['status'] in ('executing','sent') for row in self._records.values()):return None
            while self._pending:
                row=self._records[self._pending.popleft()]
                if row['context']!=context:
                    self._set(row,'failed','state_changed_before_send');continue
                self._set(row,'executing');row['deadline']=self._clock()+10
                return copy.deepcopy({key:row[key] for key in ('request_id','kind','context','arguments','contract','policy','origin')})
            return None

    def queue_claimed(self,owner_key,request_id,*,context,enqueue):
        """Bounded owner enqueue under the execution fence; never socket IO.

        The callback must only append to the owner's nonblocking outbound queue.
        ActionNotQueued proves a pre-enqueue refusal; any other exception has
        unknown outcome and fences further actions. Repeated calls never enqueue.
        """
        self._owner(owner_key);digest(context)
        if not callable(enqueue):raise TypeError('Owner enqueue callback required')
        with self._lock:
            self._refresh();row=self._records[request_id]
            if row['status'] in TERMINAL or row['status']=='sent':return self._summary(row)
            if row['status']!='executing':raise RuntimeError('Claim action before dispatch')
            if row['context']!=context:
                self._set(row,'failed','state_changed_before_send');return self._summary(row)
            intent=copy.deepcopy({key:row[key] for key in ('request_id','kind','context','arguments','contract','policy','origin')})
            try:enqueue(intent)
            except ActionNotQueued:self._set(row,'failed','not_queued')
            except Exception:self._set(row,'unknown','outcome_unconfirmed')
            else:
                self._set(row,'sent');row['deadline']=self._clock()+10
            return self._summary(row)

    def sent(self,owner_key,request_id):
        self._owner(owner_key)
        with self._lock:
            self._refresh();row=self._records[request_id]
            if row['status']!='executing':raise RuntimeError('Action cannot be sent twice')
            self._set(row,'sent');row['deadline']=self._clock()+10

    def resolve(self,owner_key,request_id,*,status):
        self._owner(owner_key)
        if status not in TERMINAL:raise ValueError('Explicit confirmed outcome required')
        with self._lock:
            self._refresh();row=self._records[request_id]
            if row['status'] not in ('executing','sent'):raise RuntimeError('Action is already terminal')
            if status=='confirmed' and row['status']!='sent':raise RuntimeError('Unsent action cannot be confirmed')
            self._set(row,status,'outcome_unconfirmed' if status=='unknown' else None)

    def close(self,owner_key):
        self._owner(owner_key)
        with self._lock:
            self._closed=True
            for row in self._records.values():
                if row['status'] not in TERMINAL:
                    queued=row['status']=='queued'
                    self._set(row,'failed' if queued else 'unknown','session_closed_before_send' if queued else 'outcome_unconfirmed')
            self._pending.clear()

    def resume_after_sync(self,owner_key,*,context):
        """Owner has observed a new authoritative action context, never a UI retry."""
        self._owner(owner_key);digest(context)
        with self._lock:
            if self._closed:raise RuntimeError('Action queue closed')
            if not self._blocked or context==self._fenced_context:raise RuntimeError('New authoritative context required')
            self._blocked=False;self._fenced_context=None

    def snapshot(self):
        with self._lock:
            self._refresh()
            return dict(bot_id=self.bot_id,session_id=self.session_id,source_sha256=self.source_sha256,closed=self._closed,blocked=self._blocked,
                capabilities=sorted(self._contracts),records=[self._summary(row) for row in self._records.values()])
