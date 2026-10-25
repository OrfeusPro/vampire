"""Execute current Ping producer/gates with bounded clock/send fixtures."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
SHA = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
PRODUCER, READY_CORE = 0x1467cf680, 0x144ab2280
READY, GET, CTOR, ID = 0x144ab0d10, 0x1445cd3c0, 0x1456d7870, 0x14140d380
TABLE, PACKET, GLOBAL, SCALE, FLAG = 0x149dc9320, 0x149926a38, 0x14b564a40, 0x148a08758, 0x14b592026
SEND, RECOVER, MODE, CONTEXT, BASE, CLEAN = 0x1467cf3e0, 0x144ab10f0, 0x144210b70, 0x144ab0c40, 0x144ab1710, 0x1456b66c0


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'),HERE/(name+'.py'))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m


def verify(exports):
    h = load('native-request-harness-11316').make_harness(exports,{PRODUCER,READY_CORE},leaves={
        READY:'488b4910e967150000', GET:'488b057976f906c3',
        CTOR:'488d05c1f1240448890133c0488941104889411888410a488bc1c3', ID:'b810000000c3'})
    uc, x = h.uc, h.x
    def data(at,size):
        off = h.image.offset(at-h.image.pe.base); return h.raw[off:off+size]
    if struct.unpack('<Q',data(TABLE+0x38,8))[0] != SEND or struct.unpack('<Q',data(PACKET+0x28,8))[0] != ID:
        raise ValueError('Ping virtual table targets differ')
    if data(SCALE,8).hex() != '2d431cebe2361a3f': raise ValueError('Ping scale differs')
    # Producer's virtual send table must be mapped; source pages are local emulator memory.
    page = TABLE & ~4095
    if not any(lo <= page <= hi for lo,hi,_ in uc.mem_regions()):
        uc.mem_map(page,4096); uc.mem_write(page,data(page,4096))
    base, context, peer, other, clock = [h.scratch+n for n in (0x10000,0x11000,0x12000,0x13000,0x14000)]
    param, state, sent, events = base+8, {}, [], []
    def fixture(machine, at):
        a,b = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
        result = 0
        if at == CONTEXT: result = context
        elif at == MODE: result = state['mode']
        elif at == SEND:
            if a != base or not h.scratch <= b <= h.scratch+0x40000-32:
                raise ValueError('Ping send capture bounds')
            if int.from_bytes(machine.mem_read(b,8),'little') != PACKET:
                raise ValueError('Ping constructor vptr differs')
            sent.append(struct.unpack('<qq',bytes(machine.mem_read(b+16,16))))
            result = 1
        elif at == RECOVER and a != base: raise ValueError('Recovery receiver differs')
        events.append(at); h.finish(result)
    for at in (SEND,RECOVER,MODE,CONTEXT,BASE,CLEAN):
        h.add_fixture(at,lambda machine,at=at:fixture(machine,at))
    if h.call(ID) != 16: raise ValueError('Ping ID differs')
    inputs = [('first',50010000,0,0,0,0,0,0),('boundary',50000000,0,0,0,0,0,0),
        ('fractional',50019999,0,0,0,0,0,0),('delta-boundary',150000000,10000,0,0,0,0,0),
        ('delta-send',150010000,10000,0,0,0,0,0),('clock-before-last',10000000,2000,0,0,0,0,0),
        ('mode-two',50010000,0,0,0,2,0,0),('context-special',50010000,0,0,0,0,1,0),
        ('wrapper-special',50010000,0,0,0,0,0,1),('five-outstanding',50010000,0,5,0,0,0,0),
        ('six-outstanding',50010000,0,6,0,0,0,0),('override-six',50010000,0,6,1,0,0,0)]
    cases = []
    for index in (0,1,3):
        for name,ticks,last,outstanding,override,mode,special_context,special_wrapper in inputs:
            uc.mem_write(base,b'\0'*0x5000); uc.mem_write(base,struct.pack('<Q',TABLE))
            uc.mem_write(base+16,struct.pack('<Q',peer)); uc.mem_write(context+16,struct.pack('<Q',other))
            uc.mem_write(peer+0x2a5,bytes((special_wrapper,))); uc.mem_write(other+0x2a5,bytes((special_context,)))
            uc.mem_write(clock+16,struct.pack('<q',ticks)); uc.mem_write(GLOBAL,struct.pack('<Q',clock))
            uc.mem_write(FLAG,bytes((override,))); uc.mem_write(param+0x158,struct.pack('<qii',last,index,outstanding))
            uc.mem_write(param+0x110,b'\xff'); state['mode'] = mode; sent.clear(); events.clear()
            h.call(PRODUCER,param)
            now = int(float(ticks)*0.0001)
            eligible = mode != 2 and not special_context and not special_wrapper and now-last>5000
            recovery = eligible and not override and outstanding>=6
            expected = [(now,now-last)] if eligible and not recovery else []
            if sent != expected or events.count(RECOVER) != int(recovery):
                raise ValueError('Ping producer branch differs')
            actual = struct.unpack('<qii',bytes(uc.mem_read(param+0x158,16)))
            if actual != (now if expected else last,index,0 if recovery else outstanding+bool(expected)):
                raise ValueError('Ping tracking state differs')
            for slot in range(4):
                value = int.from_bytes(uc.mem_read(param+0x170+slot*8,8),'little')
                if value != (now if expected and slot==index else 0): raise ValueError('Ping tracking slot differs')
            cases.append(dict(name=name,index=index,sent=list(sent),recovery=bool(recovery)))
    report = dict(source_sha256=SHA,exports=h.evidence,cases=cases,packet_id=16,network_used=False,profile_activated=False,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        limits=['Actual producer, two readiness gates, pointer getter, constructor and ID execute.',
            'Clock cache, context/mode, base update, send/recovery and cleanup are fixtures.',
            'Float timer disabled; no server requirement, transport delivery or Login success established.'])
    p = load('audit-client-release').save_snapshot(ROOT/'code-clues/login-ping-11316',report)
    return dict(report=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),cases=len(cases))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exports',type=Path,required=True)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.exports.read_text('utf-8')))))
