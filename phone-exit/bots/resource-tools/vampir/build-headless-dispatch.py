"""Native receive-A to Dispatch/PingResult reader and OnHandler entry replay."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('dispatch_listener',HERE/'build-headless-listener-loop.py')
listener=importlib.util.module_from_spec(spec);spec.loader.exec_module(listener)
native=listener.native;x=listener.x
DISPATCH,ON_HANDLER=0x14679f510,0x1467670c0
COOKIE_CHECK,LOGGER=0x148796040,0x1445da6f0
TLS_SET,WRAPPER=0x144aa6240,0x141535f20


class DispatchEmulator(listener.ListenerEmulator):
    def __init__(self):
        super().__init__()
        self.dispatch_fragments=native.decode_ranges(self.image,
            {self.image.roots[self.image.containing(a)] for a in [DISPATCH,ON_HANDLER]})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva'])
                           for f in self.dispatch_fragments)
        self.dispatch_leaves=[]
        for address,size in [(WRAPPER,7),(TLS_SET,30),(0x144aa62a0,15),
                             (0x144aa58f0,31),(0x144aa6560,15),(0x144aa6520,11),
                             (0x1456d5060,23)]:
            off=self.image.offset(address-self.image.pe.base);data=self.raw[off:off+size]
            self.dispatch_leaves.append(dict(address=address,file_offset=off,bytes=data.hex(),
                                            sha256=hashlib.sha256(data).hexdigest()))
            self.ranges.append((address,address+size))
        if self.dispatch_leaves[0]['bytes']!='488b0148ff6010':raise ValueError('OnHandler wrapper changed')
        if not self.dispatch_leaves[-2]['bytes'].endswith('c3'):raise ValueError('Archive final destructor changed')
        rows={i['address']:i for f in self.dispatch_fragments for i in f['instructions']}
        self.cookie_address=rows[0x14679f51c]['rip_references'][0]
        self.flags_address=rows[0x14679f5db]['rip_references'][0]
        self.cookie=struct.unpack_from('<Q',self.raw,self.image.offset(self.cookie_address-self.image.pe.base))[0]
        self.handler_table=0x149d810f8
        off=self.image.offset(self.handler_table-self.image.pe.base)
        data=self.raw[off:off+24]
        if struct.unpack('<QQQ',data)[1:]!=(WRAPPER,ON_HANDLER):raise ValueError('Ping handler slots changed')
        self.handler_proof=dict(address=self.handler_table,file_offset=off,bytes=data.hex())
        pages={page for begin,end in self.ranges for page in range(begin&~4095,(end+4095)&~4095,4096)}
        pages.update(a&~4095 for a in [COOKIE_CHECK,LOGGER,self.handler_table,self.cookie_address,self.flags_address,0x1498d6718])
        regions=list(self.uc.mem_regions())
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in regions):continue
            self.uc.mem_map(page,4096)
            off=self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page,self.raw[off:off+4096])
        self.uc.mem_write(self.flags_address,struct.pack('<I',0))
        self.tls_block=0x21000000
        self.uc.mem_map(self.tls_block,0x102000)
        self.setup_pending=False

    def hook(self,uc,address,size,user):
        b=self.scratch
        if address==listener.START and self.setup_pending:
            self.setup_pending=False
            dispatcher=b+0x5000;sentinel=b+0x7200;node=b+0x7400
            uc.mem_write(b+0x5100,struct.pack('<QQ',0,DISPATCH))
            uc.mem_write(dispatcher+0x10,struct.pack('<Q',sentinel))
            uc.mem_write(dispatcher+0x20,struct.pack('<Q',b+0x7300))
            uc.mem_write(dispatcher+0x38,struct.pack('<QQQ',0,0,0))
            uc.mem_write(b+0x7300,struct.pack('<QQ',node,node))
            uc.mem_write(node,struct.pack('<QQH',sentinel,sentinel,17)+bytes(6)
                         +struct.pack('<QQ',b+0x7100,b+0x7000))
            uc.mem_write(b+0x7000,struct.pack('<Q',self.handler_table))
            uc.reg_write(x.UC_X86_REG_GS_BASE,b+0x2000)
            uc.mem_write(b+0x2058,struct.pack('<Q',b+0x3000))
            uc.mem_write(b+0x3000,struct.pack('<Q',self.tls_block))
            uc.mem_write(self.tls_block+0x100cc0,struct.pack('<Q',0))
        if address==ON_HANDLER:
            args=tuple(uc.reg_read(reg) for reg in [x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8])
            if args!=(b+0x7000,0x12345678,b+0x7100):raise ValueError('Handler arguments changed')
            current=struct.unpack('<Q',bytes(uc.mem_read(b+0x5048,8)))[0]
            tls=struct.unpack('<Q',bytes(uc.mem_read(self.tls_block+0x100cc0,8)))[0]
            if (current,tls)!=(b+0x7100,b+0x5000):raise ValueError('Active packet/TLS context changed')
            result=struct.unpack('<I',bytes(uc.mem_read(b+0x7110,4)))[0]
            value=struct.unpack('<Q',bytes(uc.mem_read(b+0x7118,8)))[0]
            self.handler_events.append(dict(result_bits=result,value_bits=value))
            self.ret(uc);return
        if address==0x14679f61f:
            # Native packet reader returned false. Omit diagnostic string allocation,
            # then resume the actual TLS reset, archive destructor and function return.
            self.decode_failures+=1
            uc.reg_write(x.UC_X86_REG_RIP,0x14679f694);return
        if address in (COOKIE_CHECK,LOGGER):
            if address==COOKIE_CHECK:
                if uc.reg_read(x.UC_X86_REG_RCX)!=self.cookie:raise ValueError('Cookie mismatch')
                self.cookie_checks+=1
            else:self.unknown_ids.append(uc.reg_read(x.UC_X86_REG_R9)&0xffff)
            self.ret(uc);return
        super().hook(uc,address,size,user)

    def execute_dispatch(self,payload,packet_id=17):
        from vampir_core.frame_primitives import xor_transform
        self.copy_sizes=[];self.io_entries=[];self.handler_events=[];self.unknown_ids=[]
        self.decode_failures=self.cookie_checks=0
        self.call(0x1456d5060,self.scratch+0x7100)
        plain=struct.pack('<H',packet_id)+payload
        frame=(len(plain)+3).to_bytes(3,'little')+xor_transform(plain)
        self.setup_pending=True
        case=self.execute_listener(frame)
        current=struct.unpack('<Q',bytes(self.uc.mem_read(self.scratch+0x5048,8)))[0]
        tls=struct.unpack('<Q',bytes(self.uc.mem_read(self.tls_block+0x100cc0,8)))[0]
        if current or tls or self.cookie_checks!=1:raise ValueError('Dispatch cleanup changed')
        return dict(payload_hex=payload.hex(),packet_id=packet_id,handler_events=self.handler_events.copy(),
                    decode_failures=self.decode_failures,unknown_ids=self.unknown_ids.copy(),
                    remaining_hex=case['remaining_hex'],context_cleared=True)


def main():
    emulator=DispatchEmulator();cases=[]
    for result,value in [(0,0),(1,1),(0xffffffff,0xffffffffffffffff),(0x12345678,0x1020304050607080)]:
        payload=struct.pack('<IQ',result,value)
        for extra in [b'',b'extra']:
            case=emulator.execute_dispatch(payload+extra)
            if case['handler_events']!=[dict(result_bits=result,value_bits=value)]:raise ValueError('Decoded handler event differs')
            cases.append(case)
    for size in range(12):
        case=emulator.execute_dispatch(bytes(range(size)))
        if case['handler_events'] or case['decode_failures']!=1:raise ValueError('Short payload reached handler')
        cases.append(case)
    for packet_id in [0,16,18,0xffff]:
        case=emulator.execute_dispatch(bytes(12),packet_id)
        if case['handler_events'] or case['unknown_ids']!=[packet_id]:raise ValueError('Unknown ID reached handler')
        cases.append(case)
    report=dict(schema_version=1,source=emulator.bindings['source'],sha256=emulator.bindings['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fragments=emulator.dispatch_fragments,leaves=emulator.dispatch_leaves,
                handler_table=emulator.handler_proof,cases=cases,statistics=dict(native_dispatch_cases=len(cases)),
                network_ready=False,limitations=['Native receive-A/listener loop and full Dispatch executed with synthetic one-bucket registration.',
                'Native PingResult constructor/reader, archive lifecycle, TLS setter and handler wrapper executed.',
                'Actual OnHandler entry captured and returned; gameplay side effects excluded.',
                'Container lifetime fixtures inherited; unknown-ID logger and cookie check shimmed with checked arguments.',
                'Reader-failure diagnostic formatting skipped; native cleanup resumed.',
                'Synthetic TLS index0/archive flags0; no live transport, CRC or authentication proof.'])
    path=native.ROOT/'code-clues/headless-dispatch.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(dict(output=str(path),**report['statistics'],network_ready=False)))


if __name__=='__main__':main()
