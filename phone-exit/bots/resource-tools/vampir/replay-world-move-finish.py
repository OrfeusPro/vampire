"""Native world-move completion handler to selection lifecycle, no wire IO."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('world_finish_base',HERE/'replay-selection-status-consumer.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
HANDLER,RECV,VIRTUAL78=0x1467a5d30,0x145dbef80,0x145dbcbe0
OTHER58,OTHER68,POST=0x3000f050,0x3000f060,0x3000f070
TABLE=0x149919eb8


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        manifest=json.loads((native.ROOT/'ghidra/entry-manifest.json').read_text('utf-8'))
        names={'WorldMoveFinishResult_Handler','SelectionService_RecvWorldMoveFinishResult','SelectionLifecycle_Virtual78'}
        functions=[f for f in manifest['functions'] if f['name'] in names]
        if len(functions)!=len(names):raise ValueError('Incomplete world-move sources')
        self.world_ranges=[r for f in functions for r in f['ranges']]
        for r in self.world_ranges:
            lo,hi=int(r['start'],16),int(r['end_exclusive'],16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset']+hi-lo]).hexdigest()!=r['sha256']:
                raise ValueError('World-move source changed')
            self.ranges.append((lo,hi))
            for page in range(lo & ~4095,(hi+4095)&~4095,4096):self.map_source_page(page)
        self.constructor_ranges=[r for f in manifest['functions'] if f['name']=='WorldMoveFinishResult_Construct' for r in f['ranges']]
        for r in self.constructor_ranges:
            lo,hi=int(r['start'],16),int(r['end_exclusive'],16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset']+hi-lo]).hexdigest()!=r['sha256']:
                raise ValueError('Constructor source changed')
        off=self.image.offset(TABLE+0x28-self.image.pe.base)
        self.id_getter=struct.unpack_from('<Q',self.raw,off)[0]
        off=self.image.offset(self.id_getter-self.image.pe.base);data=self.raw[off:off+6]
        if data[0]!=0xb8 or data[-1]!=0xc3:raise ValueError('Packet ID getter shape')
        self.packet_id=int.from_bytes(data[1:5],'little')
        self.id_leaf=dict(address=self.id_getter,file_offset=off,bytes=data.hex())
        off=self.image.offset(TABLE+0x38-self.image.pe.base)
        name_getter=struct.unpack_from('<Q',self.raw,off)[0]
        name_root=self.image.roots[self.image.containing(name_getter)]
        self.name_fragments=native.decode_ranges(self.image,{name_root},
            [r for r in self.image.ranges if self.image.roots[r]==name_root])
        rows=[r for f in self.name_fragments for r in f['instructions'] if r['address']==0x14584c139]
        if len(rows)!=1 or rows[0]['mnemonic']!='lea' or len(rows[0]['rip_references'])!=1:
            raise ValueError('Packet name reference changed')
        name_address=rows[0]['rip_references'][0]
        off_name=self.image.offset(name_address-self.image.pe.base)
        name=self.raw[off_name:off_name+128].split(b'\0',1)[0]
        if name!=b'PktWorldMoveFinishResult':raise ValueError('Packet name mismatch')
        self.name_reference=dict(address=name_getter,instruction=rows[0],
            literal_address=name_address,literal_file_offset=off_name,literal_hex=(name+b'\0').hex())
        anchors=(0x14678f87e,0x14678f89f,0x14678f8b2)
        self.registration=[row for f in self.bindings['fragments'] for row in f['instructions'] if row['address'] in anchors]
        if len(self.registration)!=3:raise ValueError('Registration evidence missing')
        for row in self.registration:
            data=bytes.fromhex(row['bytes'])
            if self.raw[row['file_offset']:row['file_offset']+len(data)]!=data:raise ValueError('Registration source changed')
        if self.registration[0]['rip_references']!=[0x149d7fc88] or self.registration[1]['direct_target']!=0x1458428a0 or self.registration[2]['direct_target']!=0x1467a7250:
            raise ValueError('Registration binding changed')
        self.table_bindings=[]
        for address,target in ((0x149d7fc98,HANDLER),(0x1499f1268,VIRTUAL78)):
            off=self.image.offset(address-self.image.pe.base);data=self.raw[off:off+8]
            if int.from_bytes(data,'little')!=target:raise ValueError('Handler/service table changed')
            self.table_bindings.append(dict(address=address,file_offset=off,bytes=data.hex(),target=target))
        self.diagnostics=[]
        for address,expected in ((0x149d7fca0,'PktWorldMoveFinishResultHandler::OnHandler()'),
            (0x1499f2370,'FRdWorldMoveManager::RecvWorldMoveFinishResult()')):
            off=self.image.offset(address-self.image.pe.base);data=(expected+'\0').encode('utf-16le')
            if self.raw[off:off+len(data)]!=data:raise ValueError('Diagnostic identity changed')
            self.diagnostics.append(dict(address=address,file_offset=off,bytes=data.hex(),text=expected))
        predicate=0x145db8ab0;off=self.image.offset(predicate-self.image.pe.base);data=self.raw[off:off+8]
        if data!=bytes.fromhex('807958150f94c0c3'):raise ValueError('Service predicate leaf changed')
        self.predicate_leaf=dict(address=predicate,file_offset=off,bytes=data.hex())
        self.ranges.append((predicate,predicate+8));self.map_source_page(predicate & ~4095)
        self.ranges.append((self.id_getter,self.id_getter+6))
        self.map_source_page(self.id_getter & ~4095);self.map_source_page(TABLE & ~4095)
        self.world_hooks={0x145604890,0x145d5f1f0,0x145690b80,0x14550e2e0,0x14550bc60,0x14567e800,
            0x1423051f0,0x1455af3b0,0x144a717e0,0x145dac1f0,0x1466fa250,0x1455e1480,
            0x1467aa300,0x145cb2f00,0x1445f5330,0x145cdf240,0x145ce79f0,0x14558ee10,
            0x145ce79c0,0x144aaaab0,OTHER58,OTHER68,POST,
            0x14879656c,0x148796500}
        for a in self.world_hooks:self.map_source_page(a & ~4095)
        # Explicit already-initialized TLS environment, as used by the existing
        # native Recast scenarios. Do not skip application instructions.
        self.teb,self.tls=0x24000000,0x25000000
        self.uc.mem_map(self.teb,0x2000);self.uc.mem_map(self.tls,0x102000)
        self.uc.mem_write(self.teb+0x58,struct.pack('<Q',self.teb+0x1000))
        self.uc.mem_write(self.teb+0x1000,struct.pack('<Q',self.tls))
        self.uc.reg_write(x.UC_X86_REG_GS_BASE,self.teb)

    def hook(self,uc,address,size,user):
        if self.handler_phase and address==RECV:self.events.append(dict(action='native_world_finish_recv'))
        if self.handler_phase and address==VIRTUAL78:
            self.events.append(dict(action='native_virtual78',raw_type=uc.reg_read(x.UC_X86_REG_RDX) & 255,
                raw20=uc.reg_read(x.UC_X86_REG_R8D),raw119=uc.reg_read(x.UC_X86_REG_R9) & 255))
        if self.handler_phase and address in self.world_hooks:
            a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
            ctx=self.context;result=0
            if address in (0x14879656c,0x148796500):raise ValueError('Unexpected CRT static initialization')
            if address==0x145604890:result=ctx+0x1a000
            elif address==0x145690b80:result=1
            elif address==0x14550e2e0:result=ctx+0x15000
            elif address==0x14567e800:
                self.events.append(dict(action='actor_creation_capture',vector_hex=bytes(uc.mem_read(b,24)).hex()))
            elif address==0x1423051f0:self.events.append(dict(action='world_delegate_capture',raw20=b & 0xffffffff))
            elif address==0x1455e1480:result=ctx+0x1b000
            elif address in (0x145cb2f00,0x145cdf240,0x14558ee10):result=ctx+0x15000
            elif address==0x144aaaab0:result=1
            elif address==0x1466fa250:self.events.append(dict(action='result_rejected_capture'))
            elif address==OTHER58:self.events.append(dict(action='other_virtual58_capture',raw_type=b & 255,raw20=c & 0xffffffff))
            elif address in (0x145d5f1f0,0x144a717e0,0x145dac1f0,0x1467aa300,0x1445f5330,
                0x145ce79f0,0x145ce79c0,OTHER68,POST):
                self.events.append(dict(action='world_backend_capture',address=address))
            self.finish(result);return
        return super().hook(uc,address,size,user)

    def execute_world(self,code,gate_state,raw20,raw_type,raw119,player_raw8_nonzero=True):
        # Decode/apply a real fixture ID110 body first, preserving that player
        # and service for the next handler. The next packet is a native-object
        # fixture: its wire reader is deliberately not claimed here.
        profile=base.base.base.base.profile_body('',0)
        body=bytearray(profile);body[201]=0
        fixture=dict(gate_state=0,metadata=False,platform=False,ui_present=False,ui_same=False,service_flag=0,code=0)
        selected=self.execute(bytes(body),fixture);ctx=self.context
        self.events=[];self.gate_return=None
        self.uc.mem_write(ctx+0x4008,bytes([gate_state]))
        self.uc.mem_write(ctx+0x5078,bytes(2));self.uc.mem_write(ctx+0x5050,struct.pack('<Q',2))
        self.uc.mem_write(ctx+0x5878,struct.pack('<Q',VIRTUAL78))
        self.uc.mem_write(ctx+0x58a0,struct.pack('<Q',0x145db8ab0))
        self.uc.mem_write(ctx+0x1a000,struct.pack('<Q',ctx+0x1a800))
        self.uc.mem_write(ctx+0x1a858,struct.pack('<Q',OTHER58));self.uc.mem_write(ctx+0x1a868,struct.pack('<Q',OTHER68))
        self.uc.mem_write(ctx+0x1b000,struct.pack('<Q',ctx+0x1b800));self.uc.mem_write(ctx+0x1b838,struct.pack('<Q',POST))
        if not player_raw8_nonzero:self.uc.mem_write(ctx+0x1008,bytes(8))
        packet=ctx+0x18000;self.uc.mem_write(packet,bytes(0x120));self.uc.mem_write(packet,struct.pack('<Q',TABLE))
        for offset,fmt,value in ((0x10,'I',code),(0x18,'Q',0x123456789abcdef),(0x20,'I',raw20),
            (0x24,'I',0x89abcdef),(0x29,'B',raw_type),(0x110,'Q',7),(0x118,'B',1),(0x119,'B',raw119)):
            self.uc.mem_write(packet+offset,struct.pack('<'+fmt,value))
        self.uc.mem_write(packet+0x30,struct.pack('<ddd',10.,-20.,30.))
        self.uc.mem_write(packet+0x58,struct.pack('<ddd',1.,0.,0.))
        for a in (0x14b57ffd4,0x14b6313f0):
            self.map_source_page(a & ~4095);self.uc.mem_write(a,bytes(4))
        self.uc.mem_write(self.tls+0x101184,bytes(4))
        stack,stop=self.scratch+0x30000,self.scratch+0x3f000;self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,ctx),(x.UC_X86_REG_RDX,0x12345678),(x.UC_X86_REG_R8,packet)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(HANDLER,stop,count=500000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('World finish instruction budget')
        return dict(code=code,gate_state=gate_state,raw20=raw20,raw_type=raw_type,raw119=raw119,player_raw8_nonzero=player_raw8_nonzero,
            after_select=selected['state'],events=self.events.copy(),state=dict(
                status30=ucbyte(self.uc,ctx+0x5030),raw38=int.from_bytes(self.uc.mem_read(ctx+0x5038,8),'little'),
                raw40=int.from_bytes(self.uc.mem_read(ctx+0x5040,4),'little'),raw48=int.from_bytes(self.uc.mem_read(ctx+0x5048,4),'little'),
                raw50=int.from_bytes(self.uc.mem_read(ctx+0x5050,8),'little'),raw58=ucbyte(self.uc,ctx+0x5058),
                rawf1=ucbyte(self.uc,ctx+0x50f1),player1f8=int.from_bytes(self.uc.mem_read(ctx+0x11f8,4),'little'),
                refs=int.from_bytes(self.uc.mem_read(ctx+0x2008,4),'little')))


def ucbyte(uc,address):return uc.mem_read(address,1)[0]


def build():
    em=Emulator();cases=[]
    for gate_state in (0,1):
        for code in (0,1,0x1197):
            cases.append(em.execute_world(code,gate_state,12345,3,0))
    for raw20,raw_type,raw119 in ((0,0,0),(0xffffffff,0x15,1),(77,255,255)):
        cases.append(em.execute_world(0,0,raw20,raw_type,raw119))
    cases.append(em.execute_world(0,0,1,1,0,False))
    for case in cases:
        accepted=case['player_raw8_nonzero'] and (case['code']==0 or (case['code']==0x1197 and case['gate_state']==0))
        if case['state']['status30']!=(6 if accepted else 1):raise ValueError('World finish status transition mismatch')
        calls=[e for e in case['events'] if e['action']=='native_virtual78']
        expected=[dict(action='native_virtual78',raw_type=case['raw_type'],raw20=case['raw20'],raw119=case['raw119'])] if accepted else []
        if calls!=expected or case['state']['refs']!=2:raise ValueError('World finish arguments/reference balance mismatch')
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256=hashlib.sha256((HERE/'replay-selection-status-consumer.py').read_bytes()).hexdigest(),
        world_ranges=em.world_ranges,constructor_ranges=em.constructor_ranges,
        registration=em.registration,table_bindings=em.table_bindings,diagnostics=em.diagnostics,
        id_leaf=em.id_leaf,name_reference=em.name_reference,name_fragments=em.name_fragments,predicate_leaf=em.predicate_leaf,
        packet_table=TABLE,packet_id=em.packet_id,
        cases=cases,native_execution=True,wire_reader_executed=False,network_ready=False,
        limitations=['Actual ID110 pipeline precedes a separate world-move-finish result handler, service receive, derived virtual78, base78 and status setter.',
            'World result is a native object fixture, not a decoded wire body. No packet arrival, lifecycle trigger after ID110 or socket IO proved.',
            'World/actor/UI lookups absent, actor creation returns null, vector check and initialized TLS are fixtures, callbacks/arrays empty.',
            'SDK disabled; special world ID 10010, initial-move/flag1a8 branches, existing actor relocation and nested data applications untested.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/world-move-finish-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']),packet_id=report['packet_id'])))
