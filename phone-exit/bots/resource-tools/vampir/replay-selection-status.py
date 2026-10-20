"""Execute selection status writes; distinguish diagnostics from notifications."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('selection_status_base',HERE/'replay-character-select-handler.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
SET=0x1456140f0


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        manifest=json.loads((native.ROOT/'ghidra/entry-manifest.json').read_text('utf-8'))
        self.status_ranges=[r for f in manifest['functions'] if f['name']=='SelectionStatus_Set' for r in f['ranges']]
        if not self.status_ranges:raise ValueError('Missing status source')
        for r in self.status_ranges:
            lo,hi=int(r['start'],16),int(r['end_exclusive'],16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset']+hi-lo]).hexdigest()!=r['sha256']:
                raise ValueError('Status source changed')
            self.ranges.append((lo,hi))
            for page in range(lo & ~4095,(hi+4095)&~4095,4096):self.map_source_page(page)
        self.handler_hooks.remove(SET)
        self.actions.remove(SET)
        self.status_hooks={0x141425c40,0x141435320,0x1443fca20,0x14563d980,0x145636eb0,0x148796040}
        for a in self.status_hooks:self.map_source_page(a & ~4095)

    def hook(self,uc,address,size,user):
        if self.handler_phase and address==SET:
            a=uc.reg_read(x.UC_X86_REG_RCX);b=uc.reg_read(x.UC_X86_REG_RDX)
            self.events.append(dict(action='native_status_set',receiver=a,old=uc.mem_read(a+0x30,1)[0],value=b & 255))
        if self.handler_phase and address in self.status_hooks:
            a,b=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
            result=0
            if address==0x141425c40:uc.mem_write(a,bytes(16));result=a
            elif address==0x141435320:uc.mem_write(a,bytes(128));result=a
            elif address==0x14563d980:result=self.context+0x11000
            elif address==0x145636eb0:
                self.events.append(dict(action='text_sink_capture',receiver=a,status=uc.mem_read(self.context+0x5030,1)[0]))
            elif address==0x148796040:
                # Security-cookie validation is outside the scenario, never a
                # guessed replacement for application control flow.
                self.events.append(dict(action='security_cookie_capture'))
            self.finish(result);return
        return super().hook(uc,address,size,user)

    def direct(self,old,value,nonempty=False):
        self.handler_phase=True;self.events=[];ctx=self.context
        self.uc.mem_write(ctx,bytes(0x20000));self.uc.mem_write(ctx+0x5030,bytes([old]))
        text='diagnostic'.encode('utf-16le')+bytes(2) if nonempty else b''
        self.uc.mem_write(ctx+0x12000,struct.pack('<QII',ctx+0x12100 if nonempty else 0,len(text)//2,len(text)//2))
        if text:self.uc.mem_write(ctx+0x12100,text)
        stack,stop=self.scratch+0x30000,self.scratch+0x3f000
        self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,v in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,ctx+0x5000),(x.UC_X86_REG_RDX,value),(x.UC_X86_REG_R8,ctx+0x12000)):
            self.uc.reg_write(reg,v)
        self.uc.emu_start(SET,stop,count=50000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('Status instruction budget')
        status=self.uc.mem_read(ctx+0x5030,1)[0]
        if status!=value & 255:raise ValueError('Native status write mismatch')
        return dict(old=old,argument=value,nonempty=nonempty,status=status,events=self.events.copy())


def build():
    em=Emulator();cases=[]
    for old in (0,1,6,255):
        for value in (0,1,2,3,5,6,255,0x12340001):
            for nonempty in (False,True):cases.append(em.direct(old,value,nonempty))
    pipeline=[]
    fixture=dict(gate_state=0,metadata=False,platform=False,ui_present=False,ui_same=False,service_flag=0)
    for code in (0,1,0x26,0x3c,0x1197,0x24b9):
        c=em.execute(base.base.profile_body('',code),dict(fixture,code=code))
        c['state']['status30']=em.uc.mem_read(em.context+0x5030,1)[0]
        expected=int(code in (0,0x1197))
        if c['state']['status30']!=expected:raise ValueError('ID110 status mismatch')
        if len([e for e in c['events'] if e['action']=='native_status_set'])!=expected:raise ValueError('ID110 setter path mismatch')
        pipeline.append(c)
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256=hashlib.sha256((HERE/'replay-character-select-handler.py').read_bytes()).hexdigest(),
        status_ranges=em.status_ranges,cases=cases,pipeline=pipeline,native_execution=True,network_ready=False,
        limitations=['Actual ID110 reader/handler/service result/status setter execute; manager/player/UI boundaries inherited from handler replay.',
            'Formatting, diagnostic output, security cookie and final text sink are captures; no allocation lifetime or notification subscribers proved.',
            'Raw service byte is not a proven session-ready state; no world position, engine lifecycle, game launch or live login.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/selection-status-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']),pipeline=len(report['pipeline']))))
