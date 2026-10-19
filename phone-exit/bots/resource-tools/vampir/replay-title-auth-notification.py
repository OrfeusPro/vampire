"""Native manager-child gates and source-bound title auth-success notification."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('notify_broadcast',HERE/'replay-game-success-broadcast.py')
broadcast=importlib.util.module_from_spec(spec);spec.loader.exec_module(broadcast)
native,x=broadcast.native,broadcast.x
SUCCESS,ACTION8,ACTION18=0x14641d560,0x141423088,0x1445c018c


class Replay(broadcast.Replay):
    def __init__(self,raw,image,fragments,leaves,fixture):
        super().__init__(raw,image,fragments,leaves,dict(name='notification',subscribers=['live'],window_present=False))
        self.notification_fixture=fixture
        roots=(0x14560f740,0x14560eef0,0x14560f3c0,0x14452aa80)
        rows=[r for f in fragments if f['root_begin_rva']+image.pe.base in roots for r in f['instructions']]
        rows += [r for l in leaves if l['address'] in (ACTION8,ACTION18,0x14452b050) for r in l['instructions']]
        self.allowed.update(r['address'] for r in rows)
        self.notification_targets={0x1444aab90,0x1444aacb0,0x1444725a0,0x14563d960,0x144521af0,
            0x145603e20,0x145606660,0x14143c260,0x14563d980,0x145644b00,0x1445f3a50,
            0x14560a160,0x14452adb0,0x145606ca0,0x145619550,SUCCESS,0x146418830}
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in self.notification_targets)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.module_class,self.settings_class=self.allocate(0x120),self.allocate(0x120)
        self.module,self.settings=self.allocate(0x280),self.allocate(0x710)
        self.environment=self.allocate(0x200)
        self.uc.mem_write(self.module_class+0x110,struct.pack('<Q',self.module))
        self.uc.mem_write(self.settings_class+0x110,struct.pack('<Q',self.settings))
        self.uc.mem_write(self.manager+0x38,struct.pack('<Q',self.settings if fixture['manager_auth'] else 0))
        self.uc.mem_write(self.module+0x88,bytes([fixture['module_channel']]))
        self.uc.mem_write(self.module+0x220,bytes([fixture['policy_220']]))
        # Environment+0x1d5 stays zero; its extra branch is outside this subset.
        self.events=[]

    def hook(self,uc,address,size,user):
        if address in self.allowed:return super().hook(uc,address,size,user)
        if address not in getattr(self,'notification_targets',()):return super().hook(uc,address,size,user)
        a,b,c=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
        result=0
        if address==0x1444aab90:result=self.module_class
        elif address==0x1444aacb0:result=self.settings_class
        elif address==0x1444725a0:
            result=self.notification_fixture['idp_count']
            self.events.append(dict(action='idp_count_fixture',value=result))
        elif address==0x14563d960:result=self.environment
        elif address==0x144521af0:
            result=self.notification_fixture['nid_channel']
            self.events.append(dict(action='nid_channel_getter_fixture',value=result))
        elif address in (0x145603e20,0x145644b00,0x14560a160,0x145606ca0,0x145619550):
            self.events.append(dict(action='notification_continuation_capture',target=address))
        elif address==0x145606660:
            descriptor=self.allocate(16);self.uc.mem_write(descriptor,b'\0'*16);result=descriptor
        elif address==0x14143c260:
            self.uc.mem_write(a,bytes(uc.mem_read(b,16)))
            self.events.append(dict(action='player_string_assignment_fixture'))
        elif address==0x14563d980:result=self.environment
        elif address==0x1445f3a50:result=0xffffffff  # No matching list entry fixture; removal not executed.
        elif address==0x14452adb0:result=int(self.notification_fixture['policy_adb0'])
        elif address in (SUCCESS,0x146418830):
            if a not in self.subscribers:raise ValueError('Title notification receiver changed')
            self.events.append(dict(action='title_notification_capture',target=address))
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture(self):
        result=super().capture();result['fixture']=self.notification_fixture
        return result


def build():
    path=native.ROOT/'code-clues/game-success-broadcast-replay.json'
    prior=json.loads(path.read_text('utf-8'));raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Notification source changed')
    image=native.Image(raw)
    addresses=(0x14560f740,0x14560eef0,0x14560f3c0,0x14452aa80,0x144521af0,SUCCESS)
    fragments=prior['fragments']+native.decode_ranges(image,{image.roots[image.containing(a)] for a in addresses})
    cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
    leaves=list(prior['leaves'])
    for address in (ACTION8,ACTION18,0x14452b050):
        off=image.offset(address-image.pe.base);rows=[]
        for i in cs.disasm(raw[off:off+32],address):
            rows.append(dict(address=i.address,bytes=bytes(i.bytes).hex(),mnemonic=i.mnemonic,operands=i.op_str,rip_references=[]))
            if i.mnemonic in ('ret','jmp'):break
        content=b''.join(bytes.fromhex(r['bytes']) for r in rows)
        leaves.append(dict(address=address,file_offset=off,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest(),instructions=rows))
    offset=image.offset(broadcast.TITLE_TABLE-image.pe.base);table=raw[offset:offset+56]
    if struct.unpack_from('<Q',table,8)[0]!=SUCCESS:raise ValueError('Title success slot changed')
    literals=[]
    for fragment in fragments:
        if fragment['root_begin_rva']+image.pe.base not in (SUCCESS,0x144521af0):continue
        for row in fragment['instructions']:
            for ref in row['rip_references']:
                lit=broadcast.silent.dispatch.completion.gates.fields.lifecycle.guid.source.config.read_literal(raw,image,ref)
                if lit:literals.append(dict(instruction=row['address'],**lit))
    base=dict(manager_auth=True,module_channel=100,idp_count=0,nid_channel=33,policy_220=False,policy_adb0=False)
    profiles=[dict(base,name='notify-success'),dict(base,name='channel100',nid_channel=100),
              dict(base,name='policy220',module_channel=33,policy_220=True),
              dict(base,name='policy-adb0',module_channel=33,policy_adb0=True),
              dict(base,name='policy-default',module_channel=33),
              dict(base,name='no-manager-auth',manager_auth=False),
              dict(base,name='idp-present',idp_count=1,policy_220=True)]
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),fragments=fragments,leaves=leaves,
                title_vtable=prior['title_vtable'],literals=literals,cases=[Replay(raw,image,fragments,leaves,f).capture() for f in profiles],
                native_execution=True,network_ready=False,limitations=[
                    'Native manager-child/router/raw module predicate and subscriber broadcast execute in full silent/game chain.',
                    'Source title slot8 reaches OnSuccessNetmarbleSDKAuth entry capture; its UI body is not executed.',
                    'Module/settings CDO and independent field values are fixtures, not active account state or consistency proof.',
                    'NID channel getter, idp count, strings/policy-adb0 and continuation effects are fixtures/captures.',
                    'Environment+0x1d5 extra branch and matching-list removal path are not covered.',
                    'Subscriber array/registration, scheduler, lifetime and real game Login remain unverified.',
                    'No game launch/process memory/profile/credentials/HTTP used.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/title-auth-notification-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
