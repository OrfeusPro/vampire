"""Bounded 1.13.16 UTC clock replay for the initial Ping investigation."""
import argparse
import calendar
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
SHA = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
INIT, SET, REFRESH, TICK = 0x1445d3d50, 0x1445d7bc0, 0x1445d9ed0, 0x1445d7cb0
UTC, PLATFORM, DATE = 0x14156acd0, 0x1415da870, 0x1415482f0
SYSTEM_CALL, IAT = 0x1415da8c1, 0x14899a928
ADDEND = 0x14b564700
LOBBY_HANDLER, GET, GLOBAL = 0x1467ab7a0, 0x1445cd3c0, 0x14b564a40


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def verify(exports):
    harness = load('native-request-harness-11316')
    native = load('build-native-entry-code')
    source = ROOT/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA: raise ValueError('Clock source differs')
    image = native.Image(raw)
    def data(address, size):
        off = image.offset(address-image.pe.base)
        return raw[off:off+size]
    # Explicit leaf boundaries: init tail jumps to REFRESH; setter returns at +0x6e.
    leaves = {INIT:data(INIT,20).hex(), SET:data(SET,111).hex(),GET:'488b057976f906c3'}
    if bytes.fromhex(leaves[INIT])[-5:] != bytes.fromhex('e96c610000'):
        raise ValueError('Clock initialize tail differs')
    if bytes.fromhex(leaves[SET])[-1:] != b'\xc3': raise ValueError('Setter return differs')
    h = harness.make_harness(exports, {REFRESH,TICK,UTC,PLATFORM,DATE,LOBBY_HANDLER}, leaves=leaves)
    uc, x = h.uc, h.x
    imports = load('build-object-zero-init-code')
    imported = imports.import_at(raw,image,IAT)
    if (imported['dll'].lower(),imported['name']) != ('kernel32.dll','GetSystemTime'):
        raise ValueError('Expected UTC OS API')
    if data(SYSTEM_CALL,6) != bytes.fromhex('ff1561003c07'):
        raise ValueError('SystemTime callsite differs')
    clock, state, events = h.scratch+0x10000, {}, []
    def os_time(machine):
        target = machine.reg_read(x.UC_X86_REG_RCX)
        if not h.scratch <= target <= h.scratch+0x40000-16: raise ValueError('SYSTEMTIME fixture bounds')
        dt = state['utc']
        machine.mem_write(target,struct.pack('<8H',dt.year,dt.month,(dt.weekday()+1)%7,
            dt.day,dt.hour,dt.minute,dt.second,dt.microsecond//1000))
        events.append('GetSystemTime')
        machine.reg_write(x.UC_X86_REG_RIP,SYSTEM_CALL+6)
    h.fixtures[SYSTEM_CALL] = os_time
    def month(machine):
        year, number = (machine.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX))
        h.finish(calendar.monthrange(year,number)[1])
    h.add_fixture(0x1415535f0,month)
    h.add_fixture(0x1445cf1e0,lambda machine:h.finish(state['local_ticks']))
    # Security-cookie backend is a boundary fixture, never a host process patch.
    h.add_fixture(0x1487e8ce0,lambda machine:h.finish())
    cases = []
    for dt in (datetime(1970,1,1),datetime(2000,2,29,23,59,59,999000),datetime(2026,10,25,17,28,11,284000)):
        delta = dt-datetime(1970,1,1)
        unix_ms = delta.days*86400000+delta.seconds*1000+delta.microseconds//1000
        delta = dt-datetime(1,1,1)
        calendar_ticks = (delta.days*86400+delta.seconds)*10000000+dt.microsecond*10
        for minutes in (-720,0,540,840):
            for local_minutes in (0,180):
                uc.mem_write(clock-16,b'\xa5'*16+b'\0'*80+b'\xa5'*16)
                uc.mem_write(ADDEND,b'\0'*8)
                state.update(utc=dt,local_ticks=local_minutes*600000000)
                events.clear(); h.call(INIT,clock)
                if struct.unpack('<qq',bytes(uc.mem_read(clock+16,16))) != (unix_ms*10000,unix_ms*10000+state['local_ticks']):
                    raise ValueError('Clock epoch/cache differs')
                if int.from_bytes(uc.mem_read(clock+64,8),'little') != calendar_ticks:
                    raise ValueError('Calendar constructor differs')
                sample = unix_ms+12345
                uc.reg_write(x.UC_X86_REG_RDX,sample)
                uc.reg_write(x.UC_X86_REG_R8,minutes & 65535)
                h.call(SET,clock)
                uc.reg_write(x.UC_X86_REG_XMM1,struct.unpack('<I',struct.pack('<f',0.016))[0])
                h.call(TICK,clock+8)
                actual = struct.unpack('<4q',bytes(uc.mem_read(clock+16,32)))
                expected = ((unix_ms+minutes*60000)*10000,unix_ms*10000+state['local_ticks'],sample*10000,sample*10000)
                if actual != expected: raise ValueError('Offset/server caches differ')
                if struct.unpack('<q',bytes(uc.mem_read(ADDEND,8)))[0] != minutes*600000000:
                    raise ValueError('Signed offset differs')
                if events != ['GetSystemTime','GetSystemTime']: raise ValueError('UTC acquisition differs')
                if bytes(uc.mem_read(clock-16,16)) != b'\xa5'*16 or bytes(uc.mem_read(clock+80,16)) != b'\xa5'*16:
                    raise ValueError('Clock guard overwritten')
                cases.append(dict(utc=dt.isoformat(),offset_minutes=minutes,local_minutes=local_minutes,
                    raw_ticks=actual[0],ping_ms=int(float(actual[0])*0.0001)))
    # Route synthetic decoded lobby fields through the actual current handler.
    packet, manager = h.scratch+0x12000, h.scratch+0x13000
    h.add_fixture(0x144aaf160,lambda machine:h.finish(manager))
    h.add_fixture(0x145d4d410,lambda machine:h.finish(manager))
    forwarded = []
    def tail(machine):
        forwarded.append((machine.reg_read(x.UC_X86_REG_RCX),machine.reg_read(x.UC_X86_REG_RDX)))
        h.finish()
    h.add_fixture(0x145d5d010,tail)
    uc.mem_write(manager+0x28,struct.pack('<I',2))
    uc.mem_write(GLOBAL,struct.pack('<Q',clock))
    lobby_cases = []
    for minutes in (-32768,-180,0,540,32767):
        for flag in (0,1):
            uc.mem_write(clock,b'\0'*80); uc.mem_write(packet,b'\0'*64)
            uc.mem_write(packet+0x14,bytes((flag,)))
            uc.mem_write(packet+0x20,struct.pack('<Q',1234))
            uc.mem_write(packet+0x30,struct.pack('<q',1792600142863))
            uc.mem_write(packet+0x38,struct.pack('<h',minutes))
            uc.reg_write(x.UC_X86_REG_R8,packet); forwarded.clear()
            h.call(LOBBY_HANDLER)
            if struct.unpack('<q',bytes(uc.mem_read(ADDEND,8)))[0] != minutes*600000000:
                raise ValueError('Lobby handler signed clock offset differs')
            if forwarded != [(manager,1234)]: raise ValueError('Lobby tail fixture differs')
            lobby_cases.append(dict(offset_minutes=minutes,flag=flag))
    report = dict(source_sha256=SHA,exports=h.evidence,leaves={hex(k):v for k,v in leaves.items()},
        functions=[hex(a) for a in (REFRESH,TICK,UTC,PLATFORM,DATE)],system_import=imported,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),cases=cases,lobby_cases=lobby_cases,
        network_used=False,profile_activated=False,
        limits=['Actual initialize, refresh, setter, secondary tick, UTC adapter and calendar constructor.',
                'GetSystemTime, valid month length, local offset cache and cookie backend are explicit fixtures.',
                'Lobby handler receives a synthetic decoded packet; maintenance/manager/tail are fixtures.',
                'No full lobby reader/dispatch, active factory, server requirement, Login success or live session proved.'])
    target = load('audit-client-release').save_snapshot(ROOT/'code-clues/login-clock-11316',report)
    return dict(report=str(target),sha256=hashlib.sha256(target.read_bytes()).hexdigest(),cases=len(cases),lobby_cases=len(lobby_cases))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exports',type=Path,required=True,help='JSON map of current request-export runs to SHA256')
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.exports.read_text('utf-8')))))
