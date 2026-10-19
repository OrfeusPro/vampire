"""Native idpInfo/channel/SetSignIn/final result call site with explicit callbacks."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('completion_gates', HERE / 'replay-sdk-sign-in-response-gates.py')
gates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gates)
native, x = gates.native, gates.x
END = 0x1444ccd56


class Replay(gates.Replay):
    def __init__(self, raw, image, base_report, fragments, ctor, evidence, crt, fixture, extra):
        super().__init__(raw, image, base_report, fragments, ctor, evidence, crt, fixture)
        self.completion_events = []
        self.callback_seen = False
        self.credential = self.base + 0xe000
        self.service = self.base + 0xf000
        self.uc.mem_write(self.callback + 0x18, struct.pack('<Q', self.settings))
        self.uc.mem_write(self.callback + 0x30, struct.pack('<Q', self.service))
        if fixture['credential_code'] is not None:
            self.uc.mem_write(self.callback + 0x20, struct.pack('<Q', self.credential))
            self.uc.mem_write(self.credential + 0x50, bytes([fixture['credential_code']]))
        self.uc.mem_write(self.module + 0x88, b'\x01')
        self.objects[self.module + 0x90] = ['old-idp-fixture']
        rows = [r for f in fragments for r in f['instructions'] if
                f['root_begin_rva'] == 0x44cc1a0 and gates.fields.BEGIN <= r['address'] < END]
        rows += [r for f in extra if f['root_begin_rva'] == 0x454c3d0 for r in f['instructions']]
        self.allowed.update(r['address'] for r in rows)
        pages = {r['address'] & ~4095 for r in rows}
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        hooks = (0x144475e80,0x14446ace0,0x14444b5e0,0x14141ccb0,0x14453c5b0,
                 0x144531780,0x1414400e0,0x144524800,0x144524d70,0x144548ca0,
                 0x1445250f0,0x14453a5f0,0x141420f70,0x14454bc40,0x1444dff20)
        pages.update(a & ~4095 for a in hooks)
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page,4096)
            try:
                offset=image.offset(page-image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page,raw[offset:offset+4096])

    def hook(self,uc,address,size,user):
        # These used to be research stop boundaries; now execute their real continuation.
        if address in (0x1444ccc62,0x1444ccc4e,0x1444ccb61):
            return
        if address in self.allowed:
            # Preserve the parent's error stop boundaries even when their pages are mapped.
            if address in gates.EARLY_STOPS or address == 0x1444ccd5f:
                return super().hook(uc,address,size,user)
            return
        a,b,c=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
        result=0
        if address==0x144524d80:
            self.string(b,self.response_fixture['old_player'])
            result=b
        elif address==0x144475e80:
            value=self.objects[a][self.text(c)]
            if not isinstance(value,list):
                raise ValueError('Completion idpInfo fixture requires an array')
            self.objects[b]=value
            self.uc.mem_write(b,struct.pack('<QII',self.allocate(max(16,len(value)*16)),len(value),len(value)))
            result=b
        elif address==0x14446ace0:
            self.objects[a]=self.objects[b]
            result=a
        elif address==0x14444b5e0:
            self.objects[a]=self.objects[b]
            self.completion_events.append(dict(action='idpInfo_assignment_capture',value=self.objects[a]))
            result=a
        elif address in (0x14141ccb0,0x14453c5b0,0x144548ca0,0x14453a5f0,0x1414400e0):
            self.completion_events.append(dict(action='post_response_capture',target=address))
        elif address in (0x144531780,0x144524800,0x144524d70,0x1445250f0):
            result=self.service+0x100
            self.completion_events.append(dict(action='service_getter_capture',target=address))
        elif address==0x141420f70:
            data=bytearray()
            for n in range(128):
                value=bytes(uc.mem_read(b+n,1))
                if value==b'\0':break
                data.extend(value)
            else:raise ValueError('Completion literal fixture bound')
            self.string(a,data.decode('ascii'))
            result=a
        elif address==0x14454bc40:
            self.completion_events.append(dict(action='changed_player_followup_capture',target=address,value=self.text(b)))
        elif address==0x1444dff20:
            if a!=self.auth or b!=self.shared:
                raise ValueError('Completion result callback arguments changed')
            self.callback_seen=True
            self.completion_events.append(dict(action='result_dispatch_capture',original_response_shared=True))
        else:
            return super().hook(uc,address,size,user)
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP)
        target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8)
        uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture_completion(self):
        self.uc.mem_write(self.stack,struct.pack('<Q',self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP,self.stack)
        self.uc.reg_write(x.UC_X86_REG_RCX,self.auth)
        self.uc.emu_start(0x1444bc380,self.stop,count=1024)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=self.stop:raise ValueError('Completion ctor budget exceeded')
        rbp=self.stack+0x100
        self.uc.mem_write(rbp+0x308,struct.pack('<Q',self.shared))
        for register,value in ((x.UC_X86_REG_RSP,self.stack),(x.UC_X86_REG_RBP,rbp),
                (x.UC_X86_REG_RDI,self.callback),(x.UC_X86_REG_RDX,self.shared),
                (x.UC_X86_REG_R13,self.shared),(x.UC_X86_REG_RBX,0),
                (x.UC_X86_REG_R15,0),(x.UC_X86_REG_R14,0xffffffff)):
            self.uc.reg_write(register,value)
        self.uc.emu_start(0x1444cc2e9,END,count=32768)
        rip=self.uc.reg_read(x.UC_X86_REG_RIP)
        if rip!=END and rip not in gates.EARLY_STOPS and rip!=0x1444ccd5f:
            raise ValueError('Completion slice budget exceeded at '+hex(rip))
        return dict(fixture=self.response_fixture,callback_seen=self.callback_seen,
                    stop_address=rip,
                    sign_in_byte=int.from_bytes(self.uc.mem_read(self.settings+0x400,1),'little'),
                    channel_byte=int.from_bytes(self.uc.mem_read(self.module+0x88,1),'little'),
                    idp_info=self.objects[self.module+0x90],sdk_access_token=self.text(self.module+0x78),
                    events=self.completion_events,field_events=self.response_events)


def build():
    root=native.ROOT
    gate_path=root/'code-clues/sdk-sign-in-response-gates-replay.json'
    gate_report=json.loads(gate_path.read_text('utf-8'))
    prior=json.loads((root/'code-clues/sdk-sign-in-response-fields-replay.json').read_text('utf-8'))
    base_report=json.loads((root/'code-clues/headless-device-identity.json').read_text('utf-8'))
    raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Completion source changed')
    image=native.Image(raw)
    extra=native.decode_ranges(image,{image.roots[image.containing(a)] for a in
                (0x14454c3d0,0x1444dff20,0x144531780,0x1445250f0)})
    literals=[]
    for f in extra:
        for row in f['instructions']:
            if row['mnemonic']=='lea':
                for ref in row['rip_references']:
                    if lit:=gates.fields.lifecycle.guid.source.config.read_literal(raw,image,ref):
                        literals.append(dict(instruction=row['address'],**lit))
    crt_path=Path(gate_report['evidence']['crt']['path'])
    if hashlib.sha256(crt_path.read_bytes()).hexdigest()!=gate_report['evidence']['crt']['sha256']:
        raise ValueError('Completion CRT changed')
    crt=gates.ctypes.CDLL(str(crt_path));crt._wtoi.argtypes=[gates.ctypes.c_wchar_p];crt._wtoi.restype=gates.ctypes.c_int
    full=dict(resultData=dict(accessToken='sdk-token-fixture',playerInfo=dict(
        player=dict(playerId='new-player-fixture'),idpInfo=[{'channelCode':33} ])))
    cases=[]
    for missing in (None,'resultData','playerInfo','player','idpInfo','accessToken'):
        body=json.loads(json.dumps(full))
        if missing=='resultData':body={}
        elif missing in ('playerInfo','accessToken'):del body['resultData'][missing]
        elif missing:del body['resultData']['playerInfo'][missing]
        for credential in (None,33):
            fixture=dict(name='missing-'+str(missing)+'-credential-'+str(credential),field_4=0,field_20=0,
                         status=200,json_text=json.dumps(body),credential_code=credential,old_player='old-player-fixture')
            cases.append(Replay(raw,image,base_report,prior['fragments'],prior['constructor_leaf'],gate_report['evidence'],crt,fixture,extra).capture_completion())
    for old in ('new-player-fixture','NEW-PLAYER-FIXTURE'):
        fixture=dict(name='old-player-'+old,field_4=0,field_20=0,status=200,json_text=json.dumps(full),
                     credential_code=33,old_player=old)
        cases.append(Replay(raw,image,base_report,prior['fragments'],prior['constructor_leaf'],gate_report['evidence'],crt,fixture,extra).capture_completion())
    for status,code in ((500,None),(200,'1')):
        body=dict(full)
        if code is not None:body['errorCode']=code
        fixture=dict(name='reject-'+str(status)+'-'+str(code),field_4=0,field_20=0,status=status,
                     json_text=json.dumps(body),credential_code=33,old_player='old-player-fixture')
        cases.append(Replay(raw,image,base_report,prior['fragments'],prior['constructor_leaf'],gate_report['evidence'],crt,fixture,extra).capture_completion())
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                gate_report_sha256=hashlib.sha256(gate_path.read_bytes()).hexdigest(),
                extra_fragments=extra,literals=literals,cases=cases,native_execution=True,network_ready=False,
                limitations=[
                    'Native response gates/field/idpInfo-presence/channel/changed-player/final result call site and SetSignIn body execute.',
                    'JSON arrays/wrapping/module assignment, service getters/post-response actions and result dispatch are captures.',
                    'Actual player-update multicast/push/background actions and delegate recipients do not execute.',
                    'SetSignIn byte is internal client state only, not real account/server or game session proof.',
                    'Error dispatch/owner-lifetime gates/actual parser and final shared-object cleanup remain outside scope.',
                    'No real credentials, HTTP, Saved/registry or process memory used.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/sdk-sign-in-completion-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
