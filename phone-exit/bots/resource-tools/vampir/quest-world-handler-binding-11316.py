"""Explicit ID204 registration window and handler/common-gate adapter for native replay."""
import hashlib
import importlib.util
from pathlib import Path
import struct
from types import SimpleNamespace


def install(h):
    uc,x,b=h.uc,h.x,h.scratch
    table=0x149dc56b8;packet_table=0x14996b7a8
    start=0x1467b5853
    encoded='488d055efe6003488907eb03488bfbb940000000e8e43015004885c0740a488bc8e8877109ffeb03488bc34c8bc7488bd0488bcee8345e0100'
    # Keep the exact source window; no whole dispatcher export or live registration claim.
    data=bytes.fromhex(encoded);off=h.image.offset(start-h.image.pe.base)
    if h.raw[off:off+len(data)]!=data:raise ValueError('ID204 registration window differs')
    spec=importlib.util.spec_from_file_location('handler_entry_native',Path(__file__).with_name('build-native-entry-code.py'))
    native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
    decoded=list(decoder.disasm(data,start))
    if sum(i.size for i in decoded)!=len(data):raise ValueError('ID204 registration window has decode gaps')
    for entry in (0x1467ca790,0x1467cd7b0):
        exported=next(f for f in h.fragments if int(f['address'],16)==entry)
        part=h.image.containing(entry)
        actual={r['address']:r['bytes'] for f in native.decode_ranges(h.image,{h.image.roots[part]}) for r in f['instructions']}
        supplied={int(r['address'],16):r['bytes'] for r in exported['instructions']}
        if entry==0x1467cd7b0:
            # Legacy export omitted this direct branch target. The pinned four-byte
            # instruction completes the executable prefix; post-RET tables are data.
            supplied[0x1467cdab2]='488b4d47'
            actual={at:data for at,data in actual.items() if at<0x1467cdbc7}
            if actual.get(0x1467cdbc6)!='c3' or len(actual)!=251:
                raise ValueError('ID204 gate code-prefix boundary differs')
        if supplied!=actual:
            raise ValueError('ID204 handler/gate whole ranges differ')
    slots=struct.unpack_from('<3Q',h.raw,h.image.offset(table-h.image.pe.base))
    if slots!=(0x1414096c0,0x14153b9d0,0x1467ca790):raise ValueError('ID204 handler table differs')
    if struct.unpack_from('<Q',h.raw,h.image.offset(packet_table+0x28-h.image.pe.base))[0]!=0x145757ec0:
        raise ValueError('ID204 packet virtual ID binding differs')
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,n,size=8):uc.mem_write(at,int(n).to_bytes(size,'little'))
    def get(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    state={};events=[];setting=b+0x2d000;test_packet=b+0x2e000
    uc.mem_write(test_packet,b'\xa5'*0x50)
    if h.call(0x14584ca00,test_packet)!=test_packet or get(test_packet)!=packet_table:
        raise ValueError('ID204 constructor/vptr differs')
    if h.call(0x145757ec0,test_packet)!=204:raise ValueError('ID204 getter differs')
    old_format=h.fixtures[0x141433340];old_notice=h.fixtures[0x145639100]
    def formatter(machine):
        if not state.get('logging'):return old_format(machine)
        if reg('RDX')!=0x149dc56d0 or reg('R8')&0xffffffff!=state['code'] or reg('R9')&0xffffffff!=get(state['packet']+0x14,4):
            raise ValueError('ID204 diagnostic field arguments differ')
        uc.mem_write(reg('RCX'),bytes(16));events.append('diagnostic-format');h.finish(reg('RCX'))
    def notice(machine):
        if not state.get('logging'):return old_notice(machine)
        if get(reg('RDX'))!=0:raise ValueError('ID204 diagnostic is not empty fixture')
        state['logging']=False;events.append('diagnostic');h.finish()
    def error(machine):
        if reg('RCX')&0xffffffff!=state['code'] or reg('RDX')&0xffffffff!=0:
            raise ValueError('ID204 result error arguments differ')
        events.append('error');h.finish()
    def reject(machine):events.append('rejected-tail');h.finish()
    for at,fn in {0x141433340:formatter,0x145639100:notice,0x145594db0:lambda machine:h.finish(setting),
                  0x145fd3ee0:error,0x146750120:reject}.items():h.add_fixture(at,fn)
    accepted_count=0
    def prepare(packet):put(packet,packet_table)
    def dispatch(packet,code,special):
        nonlocal accepted_count
        events.clear();state.clear();state.update(packet=packet,code=code,logging=True)
        uc.mem_write(setting,bytes(16));put(setting+8,int(special),1);put(packet+0x10,code,4)
        uc.reg_write(x.UC_X86_REG_RDX,0);uc.reg_write(x.UC_X86_REG_R8,packet)
        h.call(0x1467ca790,b+0x2f000,budget=100000)
        if state['logging']:raise ValueError('ID204 diagnostic handoff missing')
        accepted=code==0 or (code==0x1197 and not special)
        if ('rejected-tail' in events)==accepted:raise ValueError('ID204 gate/receiver branch differs')
        if accepted:accepted_count+=1
        return events.copy()
    def verify_rejections(packet,environment):
        rows=[]
        for code in (10,0xffffffff,0x1197):
         for special in (False,True):
            if code==0x1197 and not special:continue
            before=bytes(uc.mem_read(environment,0x200));actual=dispatch(packet,code,special)
            expected=['diagnostic-format','diagnostic']+([] if special else ['error'])+['rejected-tail']
            if actual!=expected or bytes(uc.mem_read(environment,0x200))!=before:
                raise ValueError('Rejected ID204 changed environment or error ordering')
            rows.append(dict(code=code,special=special,events=actual))
        return dict(helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            handler_ranges_and_gate_code_prefix_checked=True,
            registration_start=hex(start),registration_bytes=data.hex(),handler_table=hex(table),
            handler_slots=[hex(v) for v in slots],packet_table=hex(packet_table),packet_id=204,
            accepted_receiver_cases=accepted_count,rejected=rows,
            limits=['Registration window is static; huge dispatcher body and active dispatcher are not executed.',
                'Native input is synthetic; reader is not composed here. Setting/diagnostics/error presentation/rejection tail are fixtures.',
                'Receiver A8=true remains an explicit fixture; derived environment vtable and phase completion are unknown.'])
    return SimpleNamespace(prepare=prepare,dispatch=dispatch,verify_rejections=verify_rejections)
