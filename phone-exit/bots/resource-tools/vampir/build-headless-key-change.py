"""Bind key-change Notify/ack and replay native acknowledgement-before-key-update flow."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('key_ping',HERE/'build-headless-ping-codec.py')
ping=importlib.util.module_from_spec(spec);spec.loader.exec_module(ping)
native=ping.native
from unicorn import x86_const as x

PACKETS={
    'notify':dict(name='PktKeyChangeNotify',packet_id=11,vtable=0x1498d5f58,
                  constructor=0x1456d4c00,writer=0x1456b6770,reader=0x1456b3360,
                  id_getter=0x1421dbdf0,name_getter=0x1456e3320),
    'ack':dict(name='PktKeyChanged',packet_id=12,vtable=0x1498d5e90,
               constructor=0x1456d4c20,writer=0x1456e5740,reader=0x1456d92f0,
               id_getter=0x1414f51d0,name_getter=0x1456e3350),
}
HANDLER=0x146765050
SETTER=0x144aab330
GLOBAL=0x14b520d90
FLOW_START,FLOW_END=0x1467650c1,0x146765113


class KeyChangeEmulator(ping.PingEmulator):
    def __init__(self):
        super().__init__()
        entries=[HANDLER,0x1467a79e0,0x14678ec40]
        entries += [p[s] for p in PACKETS.values() for s in ('writer','reader','name_getter')]
        self.key_fragments=native.decode_ranges(self.image,
            {self.image.roots[self.image.containing(a)] for a in entries})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva'])
                           for f in self.key_fragments)
        spans=[(0x1456d4c00,0x1456d4c1b),(0x1456d4c20,0x1456d4c3a),
               (SETTER,SETTER+15),(0x144aaa9d0,0x144aaa9d8),
               (0x1421dbdf0,0x1421dbdf6),(0x1414f51d0,0x1414f51d6)]
        self.ranges.extend(spans)
        self.key_anchors=[]
        pages={0x1498d5000,0x149d84000}
        for begin,end in self.ranges:
            pages.update(range(begin&~4095,(end+4095)&~4095,4096))
        regions=list(self.uc.mem_regions())
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in regions):continue
            self.uc.mem_map(page,4096)
            offset=self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page,self.raw[offset:offset+4096])
            self.uc.mem_protect(page,4096,ping.unicorn.UC_PROT_READ|ping.unicorn.UC_PROT_EXEC)
        # Explicit synthetic singleton; no live global or key is read.
        self.uc.mem_map(GLOBAL&~4095,4096)
        for begin,end in spans:self.anchor(begin,end-begin)
        self.rows={i['address']:i for f in self.key_fragments for i in f['instructions']}
        for address,mnemonic,operands in [
                (0x146765060,'lea','r8, [rip + 0x3604bb9]'),
                (0x1467650c6,'call','0x1456d4c20'),
                (0x1467650cb,'mov','rax, qword ptr [rbx + 0x10]'),
                (0x1467650cf,'mov','qword ptr [rsp + 0x50], rax'),
                (0x1467650e4,'call','qword ptr [r8 + 0x38]'),
                (0x1467650f8,'mov','r8, qword ptr [rcx + 0x40]'),
                (0x1467650fc,'mov','rcx, qword ptr [rbx + 0x10]'),
                (0x146765100,'mov','qword ptr [rsp + 0x80], rcx'),
                (0x14676510b,'call','r8'),
                (0x1467a7acb,'mov','qword ptr [rbx], rax'),
                (0x14678ee5e,'call','0x1456d4c00'),
                (0x14678ee71,'call','0x1467a7250')]:
            row=self.rows[address]
            if (row['mnemonic'],row['operands'])!=(mnemonic,operands):
                raise ValueError('Key-flow instruction changed '+hex(address))
        diagnostic='PktKeyChangeNotifyHandler::OnHandler()'
        address=self.rows[0x146765060]['rip_references'][0]
        content=(diagnostic+'\0').encode('utf-16le')
        if self.raw[self.image.offset(address-self.image.pe.base):][:len(content)]!=content:
            raise ValueError('Handler diagnostic changed')
        self.anchor(address,len(content))
        if self.rows[0x1467a7ac4]['rip_references']!=[0x149d84e50]:
            raise ValueError('Derived peer table changed')
        for table in [0x14961b740,0x149d84e50]:
            offset=self.image.offset(table-self.image.pe.base)
            if struct.unpack_from('<Q',self.raw,offset+0x40)[0]!=SETTER:
                raise ValueError('Key setter slot changed')
            self.anchor(table,0x48)
        for kind,p in PACKETS.items():
            offset=self.image.offset(p['vtable']-self.image.pe.base)
            for slot,key in [(0x10,'writer'),(0x20,'reader'),(0x28,'id_getter'),(0x38,'name_getter')]:
                if struct.unpack_from('<Q',self.raw,offset+slot)[0]!=p[key]:
                    raise ValueError('Key packet table changed')
            self.anchor(p['vtable'],0x40)
            ref=next(i for i in self.rows.values() if i['address']==p['name_getter']+9)
            target=ref['rip_references'][0]
            name=(p['name']+'\0').encode('ascii')
            if self.raw[self.image.offset(target-self.image.pe.base):][:len(name)]!=name:
                raise ValueError('Packet name changed')
            self.anchor(target,len(name))
        table=self.rows[0x14678ee3d]['rip_references'][0]
        offset=self.image.offset(table-self.image.pe.base)
        if struct.unpack_from('<Q',self.raw,offset+16)[0]!=HANDLER:
            raise ValueError('Notify handler registration changed')
        self.handler_table=table;self.anchor(table,24)
        # Alias primitive slots used by ack: same real u64 implementation as Ping.
        for table,slot,target in [(ping.READ_TABLE,0x48,0x144aa5bc0),(ping.WRITE_TABLE,0xb0,0x144aa61e0)]:
            offset=self.image.offset(table+slot-self.image.pe.base)
            if struct.unpack_from('<Q',self.raw,offset)[0]!=target:raise ValueError('Ack primitive changed')
            self.anchor(table+slot,8)

    def anchor(self,address,size):
        offset=self.image.offset(address-self.image.pe.base);content=self.raw[offset:offset+size]
        self.key_anchors.append(dict(address=address,file_offset=offset,bytes=content.hex(),
                                    sha256=hashlib.sha256(content).hexdigest()))

    def hook(self,uc,address,size,user):
        if address==self.scratch+0x3d000:
            packet=uc.reg_read(x.UC_X86_REG_RDX)
            self.flow_events.append(dict(event='send_ack',key_at_send=struct.unpack('<Q',bytes(
                uc.mem_read(self.flow_peer+0x248,8)))[0],ack_bits=struct.unpack('<Q',bytes(uc.mem_read(packet+0x10,8)))[0]))
            stack=uc.reg_read(x.UC_X86_REG_RSP)
            ret=struct.unpack('<Q',bytes(uc.mem_read(stack,8)))[0]
            uc.reg_write(x.UC_X86_REG_RAX,int(self.send_result))
            uc.reg_write(x.UC_X86_REG_RSP,stack+8);uc.reg_write(x.UC_X86_REG_RIP,ret)
            return
        if address==SETTER:
            self.flow_events.append(dict(event='set_key'))
        super().hook(uc,address,size,user)

    def payload(self,kind,bits,truncate=None):
        p=PACKETS[kind];uc=self.uc;b=self.scratch;obj=b+0x1000;archive=b+0x2000;buffer=b+0x8000
        self.copy_sizes=[];self.io_entries=[]
        uc.mem_write(obj,b'\0'*32)
        self.call(p['constructor'],obj)
        uc.mem_write(obj+0x10,struct.pack('<Q',bits))
        self.call(0x144aa62f0,archive,1)
        uc.mem_write(archive+0x18,struct.pack('<QQQ',buffer,buffer,buffer+256))
        uc.mem_write(archive+0x30,struct.pack('<III',256,0,0))
        write_success=self.call(p['writer'],obj,archive)
        size=struct.unpack('<I',bytes(uc.mem_read(archive+0x38,4)))[0]
        output=bytes(uc.mem_read(buffer,size))
        length=size if truncate is None else truncate
        self.call(0x144aa6260,archive,buffer,length,1,0)
        uc.mem_write(obj+0x10,b'\xa5'*8)
        read_success=self.call(p['reader'],obj,archive)
        decoded=struct.unpack('<Q',bytes(uc.mem_read(obj+0x10,8)))[0]
        packet_id=self.call(p['id_getter'],obj)
        # call() returns bool(AL); read EAX separately for real ID validation.
        packet_id=uc.reg_read(x.UC_X86_REG_RAX)
        if packet_id!=p['packet_id']:raise ValueError('Native ID differs')
        return dict(kind=kind,bits=bits,payload_hex=output.hex(),read_length=length,
                    write_success=write_success,read_success=read_success,decoded=decoded,packet_id=packet_id)

    def flow(self,old_key,new_key,send_result):
        uc=self.uc;b=self.scratch;incoming=b+0x1000;handle=b+0x4000;peer=b+0x5000;table=b+0x6000
        self.copy_sizes=[];self.io_entries=[];self.flow_events=[];self.send_result=send_result;self.flow_peer=peer
        uc.mem_write(incoming,b'\0'*32);uc.mem_write(incoming+0x10,struct.pack('<Q',new_key))
        uc.mem_write(handle,struct.pack('<Q',table));uc.mem_write(handle+0x10,struct.pack('<Q',peer))
        uc.mem_write(peer+0x248,struct.pack('<Q',old_key));uc.mem_write(GLOBAL,struct.pack('<Q',handle))
        uc.mem_write(table+0x38,struct.pack('<Q',b+0x3d000));uc.mem_write(table+0x40,struct.pack('<Q',SETTER))
        # Actual singleton getter, ack constructor and key setter; send transport is a capture shim.
        stack=b+0x20000
        uc.reg_write(x.UC_X86_REG_RSP,stack);uc.reg_write(x.UC_X86_REG_RBX,incoming)
        uc.emu_start(FLOW_START,FLOW_END,count=4096)
        if uc.reg_read(x.UC_X86_REG_RIP)!=FLOW_END:raise ValueError('Handler slice budget')
        final=struct.unpack('<Q',bytes(uc.mem_read(peer+0x248,8)))[0]
        return dict(old_key=old_key,new_key=new_key,send_result=send_result,events=self.flow_events.copy(),final_key=final)


def main():
    emulator=KeyChangeEmulator();payload_cases=[];short_cases=[];flow_cases=[]
    values=[0,1,0x0102030405060708,2**53+1,2**64-1]
    for kind in PACKETS:
        for bits in values:
            case=emulator.payload(kind,bits)
            if case['payload_hex']!=struct.pack('<Q',bits).hex() or not case['read_success'] or case['decoded']!=bits:
                raise ValueError('Key payload failed')
            payload_cases.append(case)
        for length in range(8):
            case=emulator.payload(kind,values[2],length)
            if case['read_success']:raise ValueError('Short key payload accepted')
            short_cases.append(case)
    for old_key in [0,0x1122334455667788]:
        for new_key in values:
            for send_result in [False,True]:
                case=emulator.flow(old_key,new_key,send_result)
                if case['events']!=[dict(event='send_ack',key_at_send=old_key,ack_bits=new_key),dict(event='set_key')] or case['final_key']!=new_key:
                    raise ValueError('Native key update ordering differs')
                flow_cases.append(case)
    report=dict(schema_version=1,source=emulator.bindings['source'],sha256=emulator.bindings['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fragments=emulator.key_fragments,data_anchors=emulator.key_anchors,packets=PACKETS,
                handler_table=emulator.handler_table,payload_cases=payload_cases,short_cases=short_cases,flow_cases=flow_cases,
                statistics=dict(payload_roundtrips=len(payload_cases),short_cases=len(short_cases),handler_slice_cases=len(flow_cases)),
                network_ready=False,limitations=[
                    'Notify and ack raw64 payloads executed via real IO; only external memcpy shimmed.',
                    'Handler logging/cleanup excluded; singleton/vtable/object graph are explicit synthetic inputs.',
                    'Virtual send replaced by capture/return-value shim, no frame or socket emitted.',
                    'Source of key is Notify object field+0x10; server key generation/initial auth/receive integrity unknown.',
                    'Send occurs before setter even for synthetic false return; this does not prove successful network delivery.'])
    path=native.ROOT/'code-clues/headless-key-change.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(dict(output=str(path),**report['statistics'],network_ready=False)))


if __name__=='__main__':main()
