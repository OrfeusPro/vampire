"""Native receive-B/keyed XOR/bookkeeping/Dispatch to PingResult handler entry."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('receive_b_dispatch',HERE/'build-headless-dispatch.py')
dispatch=importlib.util.module_from_spec(spec);spec.loader.exec_module(dispatch)
native=dispatch.native;x=dispatch.x
WRAPPER,GETTER,TRACK=0x144aacb50,0x144aa7c40,0x144aa8120


class ReceiveBEmulator(dispatch.DispatchEmulator):
    def __init__(self):
        super().__init__()
        self.b_fragments=native.decode_ranges(self.image,
            {self.image.roots[self.image.containing(a)] for a in
             [WRAPPER,TRACK,0x144aa7f40,0x14142eff0,0x144aa7870]})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva'])
                           for f in self.b_fragments)
        off=self.image.offset(GETTER-self.image.pe.base)
        data=self.raw[off:off+8]
        if data[:3]!=bytes.fromhex('488b05') or data[-1]!=0xc3:raise ValueError('Manager getter changed')
        self.getter_proof=dict(address=GETTER,file_offset=off,bytes=data.hex())
        self.global_manager=GETTER+7+struct.unpack_from('<i',data,3)[0]
        self.ranges.append((GETTER,GETTER+8))
        off=self.image.offset(0x14961b8f0-self.image.pe.base)
        data=self.raw[off:off+0x48]
        if struct.unpack_from('<Q',data,0x40)[0]!=WRAPPER:raise ValueError('Receive-B vtable changed')
        self.b_table=dict(address=0x14961b8f0,file_offset=off,bytes=data.hex())
        pages={p for begin,end in self.ranges for p in range(begin&~4095,(end+4095)&~4095,4096)}
        pages.update(a&~4095 for a in [self.global_manager,0x14961b8f0,0x1445bb240])
        regions=list(self.uc.mem_regions())
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in regions):continue
            self.uc.mem_map(page,4096)
            if page==self.global_manager&~4095:
                # Runtime singleton lives in zero-initialized virtual data, not EXE bytes.
                continue
            off=self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page,self.raw[off:off+4096])
        self.uc.mem_write(self.global_manager,struct.pack('<Q',self.scratch+0xa000))

    def hook(self,uc,address,size,user):
        b=self.scratch
        if address==dispatch.listener.START and self.setup_pending:
            super().hook(uc,address,size,user)
            listener=b+0x4000;manager=b+0xa000;entries=b+0xa200
            uc.mem_write(listener,struct.pack('<Q',self.b_table['address']))
            uc.mem_write(listener+0x30,struct.pack('<QQ',0x12345678,b+0x5000))
            uc.mem_write(listener+0x48,struct.pack('<Q',self.test_key))
            uc.mem_write(manager,bytes(0x100))
            if self.manager_mode!='empty':
                uc.mem_write(manager+0x38,struct.pack('<Q',entries))
                uc.mem_write(manager+0x40,struct.pack('<I',1))
                uc.mem_write(manager+0x48,struct.pack('<I',1))  # allocation bit0
                uc.mem_write(manager+0x68,struct.pack('<ii',-1,0))  # first free/count
                uc.mem_write(manager+0x70,struct.pack('<i',0))  # inline hash bucket
                uc.mem_write(manager+0x80,struct.pack('<I',1))
                key=17 if self.manager_mode=='match' else 18
                uc.mem_write(entries,struct.pack('<H',key)+bytes(22)+struct.pack('<ii',-1,0))
            return
        if address==TRACK:
            if uc.reg_read(x.UC_X86_REG_RCX)!=b+0xa000:raise ValueError('Tracker manager changed')
            self.tracked_ids.append(uc.reg_read(x.UC_X86_REG_RDX)&0xffff)
        if address==dispatch.ON_HANDLER:
            # Bookkeeping precedes the final handler, including matching removal.
            free_count=struct.unpack('<I',bytes(uc.mem_read(b+0xa06c,4)))[0]
            if free_count!=int(self.manager_mode=='match'):raise ValueError('Tracker order changed')
        if address==0x1445bb240:
            if (uc.reg_read(x.UC_X86_REG_RCX),uc.reg_read(x.UC_X86_REG_RDX))!=(0,0):
                raise ValueError('Nonempty notification cleanup not supported by fixture')
            self.empty_notifications+=1;self.ret(uc);return
        super().hook(uc,address,size,user)

    def execute_b(self,payload,key=0,mode='empty',packet_id=17):
        from vampir_core.frame_primitives import xor_transform
        if mode not in ('empty','match','miss'):raise ValueError('Unknown manager fixture')
        self.test_key=key;self.manager_mode=mode;self.tracked_ids=[];self.empty_notifications=0
        self.copy_sizes=[];self.io_entries=[];self.handler_events=[];self.unknown_ids=[]
        self.decode_failures=self.cookie_checks=0
        self.call(0x1456d5060,self.scratch+0x7100)
        plain=struct.pack('<H',packet_id)+payload
        frame=(len(plain)+3).to_bytes(3,'little')+xor_transform(plain,key)
        self.setup_pending=True
        case=self.execute_listener(frame)
        current=struct.unpack('<Q',bytes(self.uc.mem_read(self.scratch+0x5048,8)))[0]
        tls=struct.unpack('<Q',bytes(self.uc.mem_read(self.tls_block+0x100cc0,8)))[0]
        if current or tls or self.cookie_checks!=1:raise ValueError('B Dispatch cleanup changed')
        manager=self.scratch+0xa000
        free_count=struct.unpack('<I',bytes(self.uc.mem_read(manager+0x6c,4)))[0]
        if mode=='match' and packet_id==17:
            bucket=struct.unpack('<i',bytes(self.uc.mem_read(manager+0x70,4)))[0]
            allocated=struct.unpack('<I',bytes(self.uc.mem_read(manager+0x48,4)))[0]
            first_free=struct.unpack('<i',bytes(self.uc.mem_read(manager+0x68,4)))[0]
            if (free_count,bucket,allocated,first_free)!=(1,-1,0,0):
                raise ValueError('Native sparse removal state changed')
        return dict(payload_hex=payload.hex(),test_key_bits=key,manager_mode=mode,packet_id=packet_id,
                    handler_events=self.handler_events.copy(),tracked_ids=self.tracked_ids.copy(),
                    free_count=free_count,empty_notifications=self.empty_notifications,
                    decode_failures=self.decode_failures,unknown_ids=self.unknown_ids.copy(),
                    remaining_hex=case['remaining_hex'],context_cleared=True)


def main():
    emulator=ReceiveBEmulator();cases=[]
    for key in [0,1,0x1020304050607080,0xffffffffffffffff]:
        for mode in ['empty','match','miss']:
            for result,value in [(0,0),(0xffffffff,0x1122334455667788)]:
                case=emulator.execute_b(struct.pack('<IQ',result,value),key,mode)
                if case['handler_events']!=[dict(result_bits=result,value_bits=value)] or case['tracked_ids']!=[17]:
                    raise ValueError('Receive-B decoded result differs')
                if case['free_count']!=int(mode=='match') or case['empty_notifications']!=int(mode=='match'):
                    raise ValueError('Native manager bookkeeping differs')
                cases.append(case)
    for size in range(12):
        case=emulator.execute_b(bytes(range(size)),1,'match')
        if case['handler_events'] or case['decode_failures']!=1 or case['free_count']!=1:
            raise ValueError('B short reader/bookkeeping order changed')
        cases.append(case)
    for packet_id in [0,16,65535]:
        case=emulator.execute_b(bytes(12),1,'miss',packet_id)
        if case['unknown_ids']!=[packet_id] or case['tracked_ids']!=[packet_id]:raise ValueError('B unknown-ID flow changed')
        cases.append(case)
    report=dict(schema_version=1,source=emulator.bindings['source'],sha256=emulator.bindings['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fragments=emulator.b_fragments,getter=emulator.getter_proof,receive_table=emulator.b_table,
                cases=cases,statistics=dict(native_receive_b_cases=len(cases)),network_ready=False,
                limitations=['Native B wrapper/XOR/manager lookup/removal/sparse free and Dispatch executed.',
                'Synthetic manager with empty or one-entry inline bucket; notification list empty.',
                'Empty notification-array cleanup shim; native nonempty notifications unverified.',
                'Dispatch/listener fixture and diagnostic/OnHandler capture limits inherited.',
                'Keys are fixed synthetic test bits; no live keys/accounts/network captured.',
                'No CRC in replayed B route; transport/library integrity and server compatibility not proven.'])
    path=native.ROOT/'code-clues/headless-receive-b.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(dict(output=str(path),**report['statistics'],network_ready=False)))


if __name__=='__main__':main()
