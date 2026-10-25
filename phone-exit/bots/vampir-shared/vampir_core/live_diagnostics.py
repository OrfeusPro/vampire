"""Bounded per-session journal and explicitly leased world-packet samples."""
import base64
from collections import deque
import copy
import re
import time

# Auth, SDK, lobby, login, selection and world-entry bodies are never sampled.
TRACE_IDS=frozenset((301,302,307,321,322,324,325))


class LiveDiagnostics:
    """Caller holds the session lock. No disk, callbacks or network IO."""
    def __init__(self):
        self.events=deque(maxlen=256)
        self.sequence=0
        self.samples=deque()
        self.sample_bytes=0
        self.sample_sequence=0
        self.lease=None
        self.until=0
        self.ids=()
        self.analysis=None
        self.analysis_until=0
        self.event('session_created')

    def event(self,kind,**fields):
        self.sequence+=1
        self.events.append(dict(seq=self.sequence,time_ms=time.time_ns()//1000000,kind=kind,**fields))

    def journal(self,after=0,limit=128):
        first=self.events[0]['seq'] if self.events else self.sequence+1
        rows=[row for row in self.events if row['seq']>after][:limit]
        return dict(events=copy.deepcopy(rows),cursor=rows[-1]['seq'] if rows else self.sequence,
            gap=after<first-1,oldest=first)

    def expire(self):
        if self.analysis is not None and time.monotonic()>=self.analysis_until:
            self.analysis=None;self.event('analysis_expired')
        if self.lease is not None and time.monotonic()>=self.until:
            self.clear_trace();self.event('trace_expired')
        cutoff=time.monotonic()-60
        while self.samples and self.samples[0][0]<cutoff:
            _,_,body=self.samples.popleft();self.sample_bytes-=len(body)

    def clear_trace(self):
        self.samples.clear();self.sample_bytes=0;self.lease=None;self.until=0;self.ids=()

    def trace(self,lease,ids):
        if not isinstance(lease,str) or not re.fullmatch('[a-f0-9]{32}',lease):raise ValueError('Invalid trace lease')
        if type(ids) is not list or len(ids)>len(TRACE_IDS) or any(type(i) is not int or i not in TRACE_IDS for i in ids):
            raise ValueError('Only explicit world packet IDs may be sampled')
        self.expire()
        if self.lease not in (None,lease):raise RuntimeError('Trace has another owner')
        selected=tuple(sorted(set(ids)))
        if selected!=self.ids:
            self.clear_trace();self.event('trace_configured',packet_ids=list(selected))
        if selected:self.lease=lease;self.ids=selected;self.until=time.monotonic()+60
        else:self.clear_trace()
        return dict(packet_ids=list(self.ids),lease_seconds=60 if selected else 0)

    def packet(self,packet_id,body):
        self.event('packet_received',packet_id=packet_id,size=len(body))
        self.expire()
        if packet_id not in self.ids or len(body)>65536:return
        while len(self.samples)>=128 or self.sample_bytes+len(body)>262144:
            _,_,old=self.samples.popleft();self.sample_bytes-=len(old)
        self.sample_sequence+=1
        self.samples.append((time.monotonic(),dict(seq=self.sample_sequence,packet_id=packet_id),body))
        self.sample_bytes+=len(body)

    def read_samples(self,lease,after):
        self.expire()
        if lease!=self.lease or self.lease is None:raise RuntimeError('Trace lease expired or differs')
        first=self.samples[0][1]['seq'] if self.samples else self.sample_sequence+1
        rows=[dict(meta,body_base64=base64.b64encode(body).decode()) for _,meta,body in self.samples if meta['seq']>after][:32]
        # A single response stays below the API limit even for large bodies.
        while sum(len(row['body_base64']) for row in rows)>131072:rows.pop()
        return dict(samples=rows,cursor=rows[-1]['seq'] if rows else self.sample_sequence,gap=after<first-1)

    def close(self):
        self.clear_trace();self.analysis=None
