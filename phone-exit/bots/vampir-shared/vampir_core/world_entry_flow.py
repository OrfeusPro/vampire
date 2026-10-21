"""One explicit selection -> ID202 envelope -> ID203 -> ID204 transition.

Does not load a world, interpret the ID202 suffix or send completion ID205.
"""
import math

from .selection_flow import SelectionState
from .world_move_start import WorldMoveStartPayload, SOURCE_SHA256
from .world_reserve_context import decode_world_reserve_context
from .world_move_start_result import decode_world_move_start_result


class WorldEntryFlow:
    def __init__(self, selection, outbound, *, source_sha256, timeout, max_payload_size):
        if source_sha256 != SOURCE_SHA256: raise ValueError('Unsupported world entry source')
        if type(timeout) not in (float,int) or not math.isfinite(timeout) or timeout<=0:
            raise ValueError('Invalid world entry timeout')
        if type(max_payload_size) is not int or not 30 <= max_payload_size <= 0xffffff:
            raise ValueError('Invalid world entry byte budget')
        self.selection,self.outbound=selection,outbound
        self.source_sha256,self.timeout,self.max_payload_size=source_sha256,timeout,max_payload_size
        self.state='waiting_selection'
        self.reserve=self.response=None
        self.deadline=None
        self.error=None
        self.request_sent=False
        # Retain only public diagnostics when close discards private bodies.
        self.reserve_result_code=None
        self.start_result_code=None
        self._last_time=None

    def __repr__(self): return f'WorldEntryFlow(state={self.state}, data=<redacted>)'

    def fail(self,error):
        self.error,self.state,self.deadline=error,'failed',None
        self.outbound.close()

    def tick(self,now):
        if type(now) not in (float,int) or not math.isfinite(now) or now<0:
            raise ValueError('Invalid world entry clock')
        if self._last_time is not None and now<self._last_time:
            raise ValueError('World entry clock moved backwards')
        self._last_time=now
        if self.state=='waiting_selection' and self.selection.state==SelectionState.SELECT_RESPONSE:
            self.state,self.deadline='waiting_reserve',now+self.timeout
        if self.deadline is not None and now>=self.deadline:
            self.fail('world_entry_timeout')

    def receive(self,packet_id,body,*,now):
        self.tick(now)
        if self.state=='failed': raise ValueError('World entry is inactive')
        try:
            if packet_id==202:
                if self.state!='waiting_reserve': raise ValueError('Unsolicited reserve response')
                value=decode_world_reserve_context(body,max_payload_size=self.max_payload_size,
                    source_sha256=self.source_sha256)
                self.reserve=value
                self.reserve_result_code=value.result_code
                if value.result_code!=0:
                    self.fail('reserve_result_rejected');return
                # UI/world/cache side effects are deliberately not emulated.
                # This owner explicitly permits the observed code-zero path.
                packet=WorldMoveStartPayload.from_selection(self.selection.response,
                    source_sha256=self.source_sha256)
                self.outbound.queue_world_move_start(packet)
                self.request_sent=True
                self.state,self.deadline='start_pending',now+self.timeout
            elif packet_id==204:
                if self.state!='start_pending':raise ValueError('Unsolicited world start response')
                value=decode_world_move_start_result(body,max_payload_size=self.max_payload_size)
                self.response=value
                self.start_result_code=value.result_code
                if value.result_code!=0:
                    self.fail('start_result_rejected');return
                self.state,self.deadline='start_response',None
            else:raise ValueError('Unexpected world entry packet')
        except (ValueError,BufferError):
            self.fail('invalid_world_entry_response')
            raise ValueError('Invalid world entry response') from None

    def close(self):
        self.reserve=self.response=None
        self.deadline=None
        self.state='closed'
