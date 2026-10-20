"""Constructed owner slot7b0 -> service80 -> guarded ID205 preparation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('world_finish_owner_base',HERE/'replay-world-move-finish-send.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
CALLER,BASE80,POLICY=0x1468f1e90,0x14560dc10,0x141408bc0
CALLBACK=0x143642370
OWNERS=((0x1468e2aa0,0x149e0f1f0),(0x1468e2a20,0x149e0fc10),(0x1468e2a60,0x149e10630))


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        manifest=json.loads((native.ROOT/'ghidra/entry-manifest.json').read_text('utf-8'))
        names={'SelectionOwner_FinishRequestCaller','SelectionOwner_WorldConstructA',
            'SelectionOwner_WorldConstructB','SelectionOwner_WorldConstructC','SelectionLifecycle_Base80',
            'WorldFinish_DeferredPrepare'}
        self.owner_ranges=[r for f in manifest['functions'] if f['name'] in names for r in f['ranges']]
        for r in self.owner_ranges:
            lo,hi=int(r['start'],16),int(r['end_exclusive'],16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset']+hi-lo]).hexdigest()!=r['sha256']:
                raise ValueError('Owner source changed')
            self.ranges.append((lo,hi))
            for page in range(lo & ~4095,(hi+4095)&~4095,4096):self.map_source_page(page)
        off=self.image.offset(POLICY-self.image.pe.base);data=self.raw[off:off+3]
        if data!=b'\xb0\x03\xc3':raise ValueError('World owner policy changed')
        self.policy_leaf=dict(address=POLICY,file_offset=off,bytes=data.hex())
        self.ranges.append((POLICY,POLICY+3));self.map_source_page(POLICY & ~4095)
        off=self.image.offset(CALLBACK-self.image.pe.base);data=self.raw[off:off+10]
        if data!=bytes.fromhex('488b09488b0148ff6070'):raise ValueError('Deferred finish callback changed')
        self.callback_leaf=dict(address=CALLBACK,file_offset=off,bytes=data.hex())
        self.ranges.append((CALLBACK,CALLBACK+10));self.map_source_page(CALLBACK & ~4095)
        self.tables=[]
        for table in [t for _,t in OWNERS]+[0x1499f11f0]:
            length=0xa20 if table!=0x1499f11f0 else 0xd0
            off=self.image.offset(table-self.image.pe.base);data=self.raw[off:off+length]
            slots=((0x7b0,CALLER),(0xa18,POLICY)) if table!=0x1499f11f0 else ((0x80,BASE80),(0x70,base.REQUEST))
            for slot,target in slots:
                if struct.unpack_from('<Q',data,slot)[0]!=target:raise ValueError('Owner/service dispatch slot changed')
            self.tables.append(dict(address=table,file_offset=off,bytes=data.hex()))
            for page in range(table & ~4095,(table+length+4095)&~4095,4096):self.map_source_page(page)
        self.owner_hooks={0x1454fc6f0,0x145516a30,0x1456979a0,0x1454de4b0,0x1454e1d50,
            0x145651230,0x145c95430,0x1468f3ba0,0x144aa7510,0x1468e14c0,0x1445cc770,
            0x144319a00,0x14561b390,0x14141c190}
        for a in (*self.owner_hooks,0x14b571319,0x14b580020):self.map_source_page(a & ~4095)

    def hook(self,uc,address,size,user):
        if address in (CALLER,BASE80,base.REQUEST,base.GUARD):
            self.events.append(dict(action='native_finish_entry',address=address))
        if address==0x14561b390 and self.run_deferred:
            self.events.append(dict(action='native_deferred_prepare'))
            return super().hook(uc,address,size,user)
        if address not in self.owner_hooks:return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0;ctx=self.context
        if address in (0x1454de4b0,0x1445cc770):result=ctx+0x15000
        elif address==0x144aa7510:result=ctx+0x1c000
        elif address==0x144319a00:result=ctx+0x1e000 if self.fixture_world_present else 0
        elif address==0x1468e14c0:
            if a!=ctx+0x1c030 or c!=ctx+0x19000 or d!=0x1468eb140:raise ValueError('Owner delegate registration mismatch')
            uc.mem_write(b,struct.pack('<Q',0x12345678));result=b
            self.events.append(dict(action='owner_delegate_capture',callback=d))
        elif address==0x14561b390:
            callback=int.from_bytes(uc.mem_read(c,8),'little')
            if a!=ctx+0x5000 or b!=a+0x60 or callback!=0x143642370:raise ValueError('World present delegate boundary mismatch')
            self.events.append(dict(action='world_present_deferred_capture',callback=callback))
        elif address==0x14141c190:self.events.append(dict(action='delegate_cleanup_capture'))
        else:self.events.append(dict(action='owner_helper_capture',address=address))
        self.finish(result)

    def call_owner(self,address,receiver):
        stack,stop=self.scratch+0x30000,self.scratch+0x3f000;self.uc.mem_write(stack,struct.pack('<Q',stop))
        self.uc.reg_write(x.UC_X86_REG_RSP,stack);self.uc.reg_write(x.UC_X86_REG_RCX,receiver)
        self.uc.emu_start(address,stop,count=100000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('Owner instruction budget')

    def execute_owner(self,constructor,table,status,world_present=False,pending=0,run_deferred=False):
        self.setup_consumer(status);ctx=self.context;self.fixture_world_present=world_present;self.run_deferred=run_deferred
        self.uc.mem_write(ctx+0x5000,struct.pack('<Q',ctx+0x5800))
        self.uc.mem_write(ctx+0x5800,bytes.fromhex(self.tables[-1]['bytes']))
        self.uc.mem_write(ctx+0x58c8,struct.pack('<Q',base.LABEL))
        self.uc.mem_write(ctx+0x50c1,bytes([pending]));self.uc.mem_write(ctx+0x5044,struct.pack('<I',37))
        self.uc.mem_write(ctx+0x5150,struct.pack('<IfI',23,9.5,41))
        self.uc.mem_write(ctx+0x14000,struct.pack('<Q',ctx+0x14800))
        self.uc.mem_write(ctx+0x14838,struct.pack('<Q',base.CAPTURE))
        self.uc.mem_write(ctx+0x1d000,struct.pack('<Q',ctx+0x19000))
        self.uc.mem_write(0x14b571319,bytes(1));self.uc.mem_write(0x14b580020,struct.pack('<Q',ctx+0x15000))
        self.call_owner(constructor,ctx+0x1d000)
        observed=int.from_bytes(self.uc.mem_read(ctx+0x19000,8),'little')
        if observed!=table:raise ValueError('Constructed owner table mismatch')
        target=int.from_bytes(self.uc.mem_read(table+0xa18,8),'little');self.call_owner(target,ctx+0x19000)
        policy=self.uc.reg_read(x.UC_X86_REG_AL)
        target=int.from_bytes(self.uc.mem_read(table+0x7b0,8),'little');self.call_owner(target,ctx+0x19000)
        return dict(constructor=constructor,table=observed,status=status,world_present=world_present,pending=pending,policy=policy,
            events=self.events.copy(),state=dict(status30=self.uc.mem_read(ctx+0x5030,1)[0],
                flag=self.uc.mem_read(0x14b571319,1)[0],handle=int.from_bytes(self.uc.mem_read(ctx+0x193e0,8),'little')))


def build():
    em=Emulator();cases=[]
    for ctor,table in OWNERS:
        for status in (1,2,3,4,5,6):
            for present in (False,True):cases.append(em.execute_owner(ctor,table,status,present))
        cases.append(em.execute_owner(ctor,table,2,pending=1))
    for case in cases:
        expected=not case['world_present'] and not case['pending'] and case['status'] in (2,3,4)
        sends=[e for e in case['events'] if e['action']=='finish_packet_capture']
        if len(sends)!=int(expected):raise ValueError('Owner to finish guard mismatch')
        status=3 if case['pending'] else 5 if expected else case['status']
        if case['policy']!=3 or case['state']!=dict(status30=status,flag=1,handle=0x12345678):
            raise ValueError('Owner final state mismatch')
    callbacks=[]
    for status in (1,2,3,4,5,6):
        em.execute_owner(*OWNERS[0],status,world_present=True)
        em.events=[];em.uc.mem_write(em.context+0x1f000,struct.pack('<Q',em.context+0x5000))
        em.call_owner(CALLBACK,em.context+0x1f000)
        sends=[e for e in em.events if e['action']=='finish_packet_capture']
        expected=status in (2,3,4)
        after=em.uc.mem_read(em.context+0x5030,1)[0]
        if len(sends)!=int(expected) or after!=(5 if expected else status):raise ValueError('Deferred callback status guard mismatch')
        callbacks.append(dict(status=status,after=after,events=em.events.copy()))
    prepared=[]
    for status in (1,2,3,4,5,6):
        case=em.execute_owner(*OWNERS[0],status,world_present=True,run_deferred=True)
        if case['state']['status30']!=4:raise ValueError('Actual deferred helper failed to write state 4')
        before=case['events'];em.events=[]
        em.uc.mem_write(em.context+0x1f000,struct.pack('<Q',em.context+0x5000))
        em.call_owner(CALLBACK,em.context+0x1f000)
        sends=[e for e in em.events if e['action']=='finish_packet_capture']
        after=em.uc.mem_read(em.context+0x5030,1)[0]
        if len(sends)!=1 or after!=5:raise ValueError('Actual preparation then explicit callback mismatch')
        prepared.append(dict(status=status,prepare_state=4,prepare_events=before,callback_events=em.events.copy(),after=after))
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256=hashlib.sha256((HERE/'replay-world-move-finish-send.py').read_bytes()).hexdigest(),
        ranges=em.owner_ranges,tables=em.tables,policy_leaf=em.policy_leaf,callback_leaf=em.callback_leaf,
        cases=cases,callbacks=callbacks,prepared=prepared,native_execution=True,network_ready=False,
        limitations=['Actual owner constructors install tables; policy3 and slot7b0/service80/service70/guard/ID205 constructor execute.',
            'Owner base initialization, UI/helpers, delegate storage and packet send captured; primary world-present matrix captures helper14561b390.',
            'Six additional cases execute actual helper14561b390 with actor lookup absent, then explicitly invoke the callback; actor movement/scheduler not executed.',
            'State values supplied explicitly. Callback body executes separately with explicit closure receiver; scheduler/closure lifetime not executed.',
            'No engine invocation of owner slot7b0 or live packet exchange proved. State1-to4 is local helper execution, not proof of actual server/engine timing.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/world-finish-owner-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
