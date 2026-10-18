"""Native receive length probe and XOR-wrapper-to-callback evidence, no sockets."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('receive_helpers',HERE/'build-headless-frame-primitives.py')
helpers=importlib.util.module_from_spec(spec);spec.loader.exec_module(helpers)
native=helpers.native
from unicorn import x86_const as x

PROBE=0x144aa9a90
WRAPPER=0x144aa9c00
CALLBACK=0x144aa9c42


class ReceiveEnvelopeEmulator(helpers.FramePrimitiveEmulator):
    def __init__(self):
        super().__init__()
        self.receive_fragments=native.decode_ranges(self.image,
            {self.image.roots[self.image.containing(a)] for a in
             (0x144aa8ac0,0x144aab540,WRAPPER,0x144aacb50,0x1467aa0e0,0x14678ec40)})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva'])
                           for f in self.receive_fragments)
        self.ranges.append((PROBE,0x144aa9abc))
        regions=list(self.uc.mem_regions())
        pages={a&~4095 for a in [PROBE,WRAPPER]}
        for page in pages:
            if any(lo<=page<=hi for lo,hi,_ in regions):continue
            self.uc.mem_map(page,4096)
            offset=self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page,self.raw[offset:offset+4096])
            self.uc.mem_protect(page,4096,helpers.unicorn.UC_PROT_READ|helpers.unicorn.UC_PROT_EXEC)
        offset=self.image.offset(PROBE-self.image.pe.base)
        content=self.raw[offset:offset+0x2c]
        self.probe_body=dict(address=PROBE,file_offset=offset,bytes=content.hex(),
                             sha256=hashlib.sha256(content).hexdigest())
        rows={i['address']:i for f in self.receive_fragments for i in f['instructions']}
        # Game-peer construction creates the H02 dispatcher and installs it through a leaf setter.
        for address,target in [(0x1467aa2ae,0x14678ec40),(0x1467aa2bc,0x144aab300)]:
            if not helpers.calls.checked_call(rows.get(address),target):
                raise ValueError('Dispatcher assignment caller changed')
        for address,mnemonic,operands in [
                (0x1467aa2b3,'mov','rdi, rax'),
                (0x1467aa2b6,'mov','rdx, rdi'),(0x1467aa2b9,'mov','rcx, rbx'),
                (0x144aacb9c,'mov','rcx, qword ptr [rsi + 0x38]'),
                (0x144aacbaa,'mov','rax, qword ptr [rcx]'),
                (0x144aacbad,'call','qword ptr [rax + 8]')]:
            if (rows[address]['mnemonic'],rows[address]['operands'])!=(mnemonic,operands):
                raise ValueError('Callback linkage changed')
        self.connection_proofs=[]
        for address,size,expected in [(0x144aab300,12,'488b411048899038020000c3')]:
            offset=self.image.offset(address-self.image.pe.base)
            content=self.raw[offset:offset+size]
            if content.hex()!=expected:raise ValueError('Dispatcher setter changed')
            self.connection_proofs.append(dict(address=address,file_offset=offset,bytes=content.hex()))
        ctor=rows[0x14678ec4f]
        if ctor['rip_references']!=[0x149d80538]:raise ValueError('Dispatcher vtable changed')
        if (rows[0x14678ec59]['mnemonic'],rows[0x14678ec59]['operands'])!=('mov','qword ptr [rcx], rax'):
            raise ValueError('Dispatcher vptr store changed')
        offset=self.image.offset(0x149d80538-self.image.pe.base)
        content=self.raw[offset:offset+16]
        if struct.unpack_from('<Q',content,8)[0]!=0x14679f510:
            raise ValueError('Dispatch callback slot changed')
        self.connection_proofs.append(dict(address=0x149d80538,file_offset=offset,bytes=content.hex()))
        self.table_proofs=[]
        for lea,store,table in [(0x144aa8b65,0x144aa8b6c,0x14961af58),
                               (0x144aab5bf,0x144aab5c6,0x14961b8f0)]:
            if rows[lea]['rip_references']!=[table]:raise ValueError('Receive vtable LEA changed')
            if rows[store]['mnemonic']!='mov':raise ValueError('Receive vptr store changed')
            offset=self.image.offset(table-self.image.pe.base)
            content=self.raw[offset:offset+0x48]
            if struct.unpack_from('<Q',content,0x38)[0]!=PROBE:
                raise ValueError('Length probe slot changed')
            expected=WRAPPER if table==0x14961af58 else 0x144aacb50
            if struct.unpack_from('<Q',content,0x40)[0]!=expected:
                raise ValueError('Receive wrapper slot changed')
            self.table_proofs.append(dict(table=table,file_offset=offset,bytes=content.hex(),
                constructor_lea=rows[lea],constructor_store=rows[store],length_slot=0x38,receive_slot=0x40))
        self.uc.hook_add(helpers.unicorn.UC_HOOK_MEM_READ,self.observe_read)

    def observe_read(self,uc,access,address,size,value,user):
        if self.watch_input<=address<self.watch_input+self.watch_size:
            self.input_reads.append(dict(offset=address-self.watch_input,size=size))

    def probe(self,declared,available):
        pointer=self.base+0x8000
        self.uc.mem_write(pointer,declared.to_bytes(3,'little')+b'\xee'*32)
        self.watch_input=pointer;self.watch_size=35;self.input_reads=[]
        value=self.call(PROBE,0,0,pointer,available)
        return dict(declared=declared,available=available,result=value,input_reads=self.input_reads.copy())

    def unwrap(self,frame):
        if len(frame)>512:raise ValueError('Scratch bound')
        uc=self.uc;b=self.base;owner=b+0x1000;callback_obj=b+0x2000
        callback_vtable=b+0x3000;pointer=b+0x8000
        uc.mem_write(pointer,frame or b'\0')
        uc.mem_write(owner,b'\0'*64)
        uc.mem_write(owner+0x18,struct.pack('<QQ',0x12345678,callback_obj))
        uc.mem_write(callback_obj,struct.pack('<Q',callback_vtable))
        # Virtual target is not executed; stop at the original indirect-call instruction.
        uc.mem_write(callback_vtable,b'\0'*16)
        stack=b+0x1e000;stop=b+0x1f000
        uc.mem_write(stack,struct.pack('<Q',stop))
        self.watch_input=pointer;self.watch_size=max(len(frame),1);self.input_reads=[]
        for reg,value in [(x.UC_X86_REG_RCX,owner),(x.UC_X86_REG_RDX,0),
                          (x.UC_X86_REG_R8,pointer),(x.UC_X86_REG_R9,len(frame)),
                          (x.UC_X86_REG_RSP,stack)]:uc.reg_write(reg,value)
        terminal=[]
        def stop_at_callback(uc,address,size,user):
            if address==CALLBACK:
                terminal.append(dict(rcx=uc.reg_read(x.UC_X86_REG_RCX),rdx=uc.reg_read(x.UC_X86_REG_RDX),
                                     r8=uc.reg_read(x.UC_X86_REG_R8),r9=uc.reg_read(x.UC_X86_REG_R9)))
                uc.emu_stop()
        hook=uc.hook_add(helpers.unicorn.UC_HOOK_CODE,stop_at_callback)
        try:uc.emu_start(WRAPPER,stop,count=20000)
        finally:uc.hook_del(hook)
        if not terminal and uc.reg_read(x.UC_X86_REG_RIP)!=stop:
            raise ValueError('Receive wrapper budget exceeded')
        if terminal and terminal[0]!=dict(rcx=callback_obj,rdx=0x12345678,r8=pointer,r9=len(frame)):
            raise ValueError('Callback argument flow changed')
        return dict(frame_hex=frame.hex(),output_hex=bytes(uc.mem_read(pointer,len(frame))).hex(),
                    callback_reached=bool(terminal),callback_size=len(frame) if terminal else None)


def main():
    emulator=ReceiveEnvelopeEmulator();emulator.watch_input=0;emulator.watch_size=0;emulator.input_reads=[]
    probe_cases=[];wrapper_cases=[]
    for declared in [0,1,2,3,4,5,6,17,255,256,65535,65536,0xffffff]:
        for available in [0,1,2,3,4,5,6,16,17,256,65536,0xffffff]:
            case=emulator.probe(declared,available)
            expected=declared if available>=5 and declared<=available else 0
            if case['result']!=expected:raise ValueError('Length probe behavior differs')
            if available<5 and case['input_reads']:raise ValueError('Probe read before minimum available')
            probe_cases.append(case)
    for size in [0,1,2,3,4,5,7,8,9,17,27,256,512]:
        frame=bytes((i*17+9)&255 for i in range(size))
        case=emulator.unwrap(frame)
        expected=frame[:3]+bytes(v^helpers.FALLBACK.to_bytes(8,'little')[i&7]
                                 for i,v in enumerate(frame[3:]))
        if case['output_hex']!=expected.hex() or case['callback_reached']!=(size>=3):
            raise ValueError('Native receive envelope differs')
        wrapper_cases.append(case)
    report=dict(schema_version=1,source=emulator.source['source'],sha256=emulator.source['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fragments=emulator.receive_fragments,probe_body=emulator.probe_body,
                receive_tables=emulator.table_proofs,connection_proofs=emulator.connection_proofs,
                probe_cases=probe_cases,wrapper_cases=wrapper_cases,
                statistics=dict(probe_cases=len(probe_cases),wrapper_cases=len(wrapper_cases)),
                full_receive_verified=False,game_callback_target_statically_verified=True,network_ready=False,
                limitations=['Length probe and receive-A wrapper/XOR executed with explicit buffers.',
                             'Stop before virtual callback; callback object and context are synthetic.',
                             'Probe available count is explicit; socket buffer ownership/maximum not reconstructed.',
                             'Probe returns encoded lengths1..4 if available>=5; no lower-size rejection inferred.',
                             'No CRC checks occur in these executed routines; broader receive validation unknown.',
                             'Game wrapper callback-to-Dispatch linked statically; full wrapper-to-dispatch execution not replayed.',
                             'Session-key source and transport receive integrity validation remain unresolved.'])
    path=native.ROOT/'code-clues/headless-receive-envelope.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(dict(output=str(path),**report['statistics'],network_ready=False)))


if __name__=='__main__':main()
