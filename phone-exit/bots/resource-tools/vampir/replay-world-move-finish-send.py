"""Native finish guard/request, empty body and independently composed send queue."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,HERE/filename)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


base=module('finish_send_base','replay-selection-status-consumer.py')
send=module('finish_send_frame','replay-version-send-path.py')
native,x=base.native,base.x
REQUEST,GUARD,CTOR,TABLE=0x145dc2930,0x145619bf0,0x145842880,0x149919e68
CAPTURE,LABEL=0x3000f080,0x3000f090


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        manifest=json.loads((native.ROOT/'ghidra/entry-manifest.json').read_text('utf-8'))
        names={'SelectionLifecycle_Virtual70','WorldMoveFinish_Guard','WorldMoveFinish_Construct','SelectionService_SetState'}
        functions=[f for f in manifest['functions'] if f['name'] in names]
        if len(functions)!=len(names):raise ValueError('Missing finish request sources')
        self.request_ranges=[r for f in functions for r in f['ranges']]
        for r in self.request_ranges:
            lo,hi=int(r['start'],16),int(r['end_exclusive'],16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset']+hi-lo]).hexdigest()!=r['sha256']:
                raise ValueError('Finish request source changed')
            self.ranges.append((lo,hi))
            for page in range(lo & ~4095,(hi+4095)&~4095,4096):self.map_source_page(page)
        off=self.image.offset(TABLE-self.image.pe.base)
        self.table_bytes=self.raw[off:off+0x40]
        self.writer,self.id_getter,self.name_getter=[struct.unpack_from('<Q',self.table_bytes,n)[0] for n in (0x10,0x28,0x38)]
        self.leaves=[]
        for a,size in ((self.writer,3),(self.id_getter,6)):
            off=self.image.offset(a-self.image.pe.base);data=self.raw[off:off+size]
            self.leaves.append(dict(address=a,file_offset=off,bytes=data.hex()))
            self.ranges.append((a,a+size));self.map_source_page(a & ~4095)
        if self.leaves[0]['bytes']!='b001c3' or self.leaves[1]['bytes']!='b8cd000000c3':raise ValueError('Empty body/ID205 leaf changed')
        off=self.image.offset(0x14898d130-self.image.pe.base);data=self.raw[off:off+4]
        self.minimum=dict(address=0x14898d130,file_offset=off,bytes=data.hex(),value=struct.unpack('<f',data)[0])
        self.finish_hooks={0x145940db0,0x145670b80,CAPTURE,LABEL}
        for a in self.finish_hooks:self.map_source_page(a & ~4095)

    def hook(self,uc,address,size,user):
        if self.handler_phase and address in self.finish_hooks:
            a,b=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
            result=0
            if address==0x145940db0:result=self.context+0x17000
            elif address==0x145670b80:uc.mem_write(a,bytes(16));result=a
            elif address==LABEL:
                self.events.append(dict(action='pending_label_capture',raw=uc.reg_read(x.UC_X86_REG_R8D)))
                uc.mem_write(b,bytes(16));result=b
            elif address==CAPTURE:
                if a!=self.context+0x14000:raise ValueError('Finish wrapper receiver changed')
                packet=bytes(uc.mem_read(b,16))
                if int.from_bytes(packet[:8],'little')!=TABLE or packet[10]!=1:raise ValueError('Finish constructor binding')
                self.events.append(dict(action='finish_packet_capture',packet_hex=packet.hex()))
            self.finish(result);return
        return super().hook(uc,address,size,user)

    def execute_request(self,status,pending=0,config=0):
        self.setup_consumer(status);ctx=self.context
        self.uc.mem_write(ctx+0x5000,struct.pack('<Q',ctx+0x5800))
        self.uc.mem_write(ctx+0x58c8,struct.pack('<Q',LABEL))
        self.uc.mem_write(ctx+0x50c1,bytes([pending]))
        self.uc.mem_write(ctx+0x5044,struct.pack('<I',37))
        self.uc.mem_write(ctx+0x5150,struct.pack('<IfI',23,9.5,41))
        self.uc.mem_write(ctx+0x17000+0x238,struct.pack('<q',config))
        self.uc.mem_write(ctx+0x14000,struct.pack('<Q',ctx+0x14800))
        self.uc.mem_write(ctx+0x14838,struct.pack('<Q',CAPTURE))
        self.call_source(REQUEST);returned=self.uc.reg_read(x.UC_X86_REG_AL)
        state=dict(status30=self.uc.mem_read(ctx+0x5030,1)[0],pending=self.uc.mem_read(ctx+0x50c1,1)[0],
            raw150=int.from_bytes(self.uc.mem_read(ctx+0x5150,4),'little'),
            raw154_hex=bytes(self.uc.mem_read(ctx+0x5154,4)).hex(),raw158=int.from_bytes(self.uc.mem_read(ctx+0x5158,4),'little'))
        first_events=self.events.copy();self.events=[];self.call_source(REQUEST)
        return dict(status=status,pending=pending,config=config,returned=returned,state=state,
            events=first_events,repeat_events=self.events.copy(),repeat_return=self.uc.reg_read(x.UC_X86_REG_AL))


class FrameEmulator(send.Emulator):
    def __init__(self,request):
        super().__init__();self.packet=bytes.fromhex(request['packet_hex'])
        self.packet_leaves=[]
        off=self.image.offset(TABLE-self.image.pe.base);table=self.raw[off:off+0x40]
        for offset,size in ((0x10,3),(0x28,6)):
            a=struct.unpack_from('<Q',table,offset)[0];off=self.image.offset(a-self.image.pe.base)
            self.packet_leaves.append(dict(address=a,file_offset=off,bytes=self.raw[off:off+size].hex()))
            self.ranges.append((a,a+size))
        name=struct.unpack_from('<Q',table,0x38)[0];root=self.image.roots[self.image.containing(name)]
        self.name_fragments=native.decode_ranges(self.image,{root},[r for r in self.image.ranges if self.image.roots[r]==root])
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.name_fragments)
        refs=[a for f in self.name_fragments for r in f['instructions'] for a in r['rip_references']]
        for a in (*refs,TABLE,*[r['address'] for r in self.packet_leaves]):
            page=a & ~4095
            if not any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):
                self.uc.mem_map(page,4096);off=self.image.offset(page-self.image.pe.base);self.uc.mem_write(page,self.raw[off:off+4096])
        for lo,hi in self.ranges:
            for page in range(lo & ~4095,(hi+4095)&~4095,4096):
                if any(a<=page<=b for a,b,_ in self.uc.mem_regions()):continue
                self.uc.mem_map(page,4096);off=self.image.offset(page-self.image.pe.base);self.uc.mem_write(page,self.raw[off:off+4096])

    def hook(self,uc,address,size,user):
        if address==send.WRAPPER:
            # Explicit composition boundary between two native executions.
            # Replace the parent's Version setup with the captured real header.
            uc.mem_write(uc.reg_read(x.UC_X86_REG_RDX),self.packet)
        if address==0x141420f70:
            a,b=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
            literal=b'PktWorldMoveFinish\0'
            if bytes(uc.mem_read(b,len(literal)))!=literal:raise ValueError('Finish packet name changed')
            data=literal.decode('ascii').encode('utf-16le');p=self.alloc(len(data));uc.mem_write(p,data)
            uc.mem_write(a,struct.pack('<QII',p,len(data)//2,len(data)//2))
            self.events.append(dict(action='packet_name_constructor_fixture',name='PktWorldMoveFinish'))
            uc.reg_write(x.UC_X86_REG_RAX,a);sp=uc.reg_read(x.UC_X86_REG_RSP)
            uc.reg_write(x.UC_X86_REG_RIP,int.from_bytes(uc.mem_read(sp,8),'little'));uc.reg_write(x.UC_X86_REG_RSP,sp+8);return
        return super().hook(uc,address,size,user)


def build():
    em=Emulator();matrix=[em.execute_request(status) for status in range(256)]
    extra=[em.execute_request(status,pending=1) for status in (1,2,3,4,5)]
    extra.extend(em.execute_request(2,config=value) for value in (-1,1,2**40,-2**63,2**63-1))
    for case in matrix+extra:
        accepted=not case['pending'] and case['status'] in (2,3,4)
        packets=[e for e in case['events'] if e['action']=='finish_packet_capture']
        if len(packets)!=int(accepted) or case['returned']!=int(accepted):raise ValueError('Finish guard acceptance mismatch')
        state=case['state']
        if accepted:
            expected=struct.pack('<f',max(float(case['config']),em.minimum['value'])).hex()
            if (state['status30'],state['raw150'],state['raw154_hex'],state['raw158'])!=(5,0,expected,1):
                raise ValueError('Finish timer/status stores mismatch')
            if case['repeat_events'] or case['repeat_return']:raise ValueError('Finish repeat should be gated by status 5')
        elif case['pending']:
            if state['status30']!=3 or state['pending']!=1:raise ValueError('Pending state preparation mismatch')
        elif state['status30']!=case['status']:raise ValueError('Rejected guard changed status')
    header=next(e for e in matrix[2]['events'] if e['action']=='finish_packet_capture')
    frame_em=FrameEmulator(header);frames=[]
    fixture=dict(sequence=0,key=0,wake=False,metadata_present=False,metadata_byte=7,disabled=False,raw_mode=0,special=False,already_flag=False)
    for sequence,key in ((0,0),(1,0x1020304050607080),(65535,0),(65535,0x1020304050607080)):
        f=dict(fixture,sequence=sequence,key=key,wake=bool(key));c=frame_em.execute(dict(strings=[],integers=[0,0,0]),f)
        c.pop('packet_fields');frames.append(c)
        if c['queue_calls']!=1 or not c['frame_hex']:raise ValueError('Finish frame missing')
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('replay-selection-status-consumer.py','replay-version-send-path.py')},
        request_ranges=em.request_ranges,leaves=em.leaves,table=dict(address=TABLE,bytes=em.table_bytes.hex()),minimum=em.minimum,
        frame_sources=frame_em.extra+frame_em.send_fragments+frame_em.name_fragments,frame_leaves=frame_em.packet_leaves,
        matrix=matrix,extra=extra,frames=frames,native_execution=True,network_ready=False,
        limitations=['Actual service virtual70/guard/status setter/constructor execute; configuration, label, world/UI and first send are bounded captures.',
            'Pending branch executes actual SetState with absent UI; label lookup/text conversion captured. Trigger after ID110 remains unproved.',
            'Captured 16-byte native header is transferred to a separate native wrapper/send-B/empty-writer/frame/queue scenario; this is an explicit composition boundary.',
            'Queue allocation/metadata/name/wake/cleanup fixtures inherited from Version send; no queue growth, drain, socket, real timeout scheduling or server response.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/world-move-finish-send-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),matrix=len(report['matrix']),frames=len(report['frames']))))
