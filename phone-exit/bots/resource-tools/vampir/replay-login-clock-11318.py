"""Bounded 1.13.18 UTC clock replay for the initial Ping investigation."""
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
SHA = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
INIT, SET, REFRESH, TICK = (5441929296, 5441945280, 5441954256, 5441945520)
UTC, PLATFORM, DATE = (5391166672, 5391624304, 5391024880)
SYSTEM_CALL, IAT = (5391624385, 5512997160)
ADDEND = 5558920960
LOBBY_HANDLER, GET, GLOBAL = (5477416048, 5441902272, 5558921792)

def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def verify(exports):
    harness = load('native-request-harness-11316')
    native = load('build-native-entry-code')
    source = ROOT / 'client-code-snapshots' / SHA / 'ProjectRED-Win64-Shipping.exe'
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('Clock source differs')
    image = native.Image(raw)

    def data(address, size):
        off = image.offset(address - image.pe.base)
        return raw[off:off + size]
    leaves = {INIT: data(INIT, 20).hex(), SET: data(SET, 111).hex(), GET: '488b057993f906c3'}
    if bytes.fromhex(leaves[INIT])[-5:] != bytes.fromhex('e96c610000'):
        raise ValueError('Clock initialize tail differs')
    if bytes.fromhex(leaves[SET])[-1:] != b'\xc3':
        raise ValueError('Setter return differs')
    h = harness.make_harness(exports, {REFRESH, TICK, UTC, PLATFORM, DATE, LOBBY_HANDLER}, leaves=leaves, source_sha256=SHA, copy_thunk=5511274713)
    load('verify-clock-replay-source-11318').verify(h)
    uc, x = (h.uc, h.x)
    imports = load('build-object-zero-init-code')
    imported = imports.import_at(raw, image, IAT)
    if (imported['dll'].lower(), imported['name']) != ('kernel32.dll', 'GetSystemTime'):
        raise ValueError('Expected UTC OS API')
    if data(SYSTEM_CALL, 6) != bytes.fromhex('ff1561003c07'):
        raise ValueError('SystemTime callsite differs')
    clock, state, events = (h.scratch + 65536, {}, [])

    def os_time(machine):
        target = machine.reg_read(x.UC_X86_REG_RCX)
        if not h.scratch <= target <= h.scratch + 262144 - 16:
            raise ValueError('SYSTEMTIME fixture bounds')
        dt = state['utc']
        machine.mem_write(target, struct.pack('<8H', dt.year, dt.month, (dt.weekday() + 1) % 7, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond // 1000))
        events.append('GetSystemTime')
        machine.reg_write(x.UC_X86_REG_RIP, SYSTEM_CALL + 6)
    h.fixtures[SYSTEM_CALL] = os_time

    def month(machine):
        year, number = (machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX))
        h.finish(calendar.monthrange(year, number)[1])
    h.add_fixture(5391070704, month)
    h.add_fixture(5441909984, lambda machine: h.finish(state['local_ticks']))
    h.add_fixture(5511222016, lambda machine: h.finish())
    cases = []
    for dt in (datetime(1970, 1, 1), datetime(2000, 2, 29, 23, 59, 59, 999000), datetime(2026, 10, 25, 17, 28, 11, 284000)):
        delta = dt - datetime(1970, 1, 1)
        unix_ms = delta.days * 86400000 + delta.seconds * 1000 + delta.microseconds // 1000
        delta = dt - datetime(1, 1, 1)
        calendar_ticks = (delta.days * 86400 + delta.seconds) * 10000000 + dt.microsecond * 10
        for minutes in (-720, 0, 540, 840):
            for local_minutes in (0, 180):
                uc.mem_write(clock - 16, b'\xa5' * 16 + b'\x00' * 80 + b'\xa5' * 16)
                uc.mem_write(ADDEND, b'\x00' * 8)
                state.update(utc=dt, local_ticks=local_minutes * 600000000)
                events.clear()
                h.call(INIT, clock)
                if struct.unpack('<qq', bytes(uc.mem_read(clock + 16, 16))) != (unix_ms * 10000, unix_ms * 10000 + state['local_ticks']):
                    raise ValueError('Clock epoch/cache differs')
                if int.from_bytes(uc.mem_read(clock + 64, 8), 'little') != calendar_ticks:
                    raise ValueError('Calendar constructor differs')
                sample = unix_ms + 12345
                uc.reg_write(x.UC_X86_REG_RDX, sample)
                uc.reg_write(x.UC_X86_REG_R8, minutes & 65535)
                h.call(SET, clock)
                uc.reg_write(x.UC_X86_REG_XMM1, struct.unpack('<I', struct.pack('<f', 0.016))[0])
                h.call(TICK, clock + 8)
                actual = struct.unpack('<4q', bytes(uc.mem_read(clock + 16, 32)))
                expected = ((unix_ms + minutes * 60000) * 10000, unix_ms * 10000 + state['local_ticks'], sample * 10000, sample * 10000)
                if actual != expected:
                    raise ValueError('Offset/server caches differ')
                if struct.unpack('<q', bytes(uc.mem_read(ADDEND, 8)))[0] != minutes * 600000000:
                    raise ValueError('Signed offset differs')
                if events != ['GetSystemTime', 'GetSystemTime']:
                    raise ValueError('UTC acquisition differs')
                if bytes(uc.mem_read(clock - 16, 16)) != b'\xa5' * 16 or bytes(uc.mem_read(clock + 80, 16)) != b'\xa5' * 16:
                    raise ValueError('Clock guard overwritten')
                cases.append(dict(utc=dt.isoformat(), offset_minutes=minutes, local_minutes=local_minutes, raw_ticks=actual[0], ping_ms=int(float(actual[0]) * 0.0001)))
    packet, manager = (h.scratch + 73728, h.scratch + 77824)
    h.add_fixture(5447021664, lambda machine: h.finish(manager))
    h.add_fixture(5466544304, lambda machine: h.finish(manager))
    forwarded = []

    def tail(machine):
        forwarded.append((machine.reg_read(x.UC_X86_REG_RCX), machine.reg_read(x.UC_X86_REG_RDX)))
        h.finish()
    h.add_fixture(5466608816, tail)
    uc.mem_write(manager + 40, struct.pack('<I', 2))
    uc.mem_write(GLOBAL, struct.pack('<Q', clock))
    lobby_cases = []
    for minutes in (-32768, -180, 0, 540, 32767):
        for flag in (0, 1):
            uc.mem_write(clock, b'\x00' * 80)
            uc.mem_write(packet, b'\x00' * 64)
            uc.mem_write(packet + 20, bytes((flag,)))
            uc.mem_write(packet + 32, struct.pack('<Q', 1234))
            uc.mem_write(packet + 48, struct.pack('<q', 1792600142863))
            uc.mem_write(packet + 56, struct.pack('<h', minutes))
            uc.reg_write(x.UC_X86_REG_R8, packet)
            forwarded.clear()
            h.call(LOBBY_HANDLER)
            if struct.unpack('<q', bytes(uc.mem_read(ADDEND, 8)))[0] != minutes * 600000000:
                raise ValueError('Lobby handler signed clock offset differs')
            if forwarded != [(manager, 1234)]:
                raise ValueError('Lobby tail fixture differs')
            lobby_cases.append(dict(offset_minutes=minutes, flag=flag))
    report = dict(dependencies={n: hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in (Path(__file__).name, 'native-request-harness-11316.py', 'build-native-entry-code.py', 'build-object-zero-init-code.py', 'verify-clock-replay-source-11318.py', 'knowledge/native-contexts/clock-replays-11318.json')}, source_sha256=SHA, exports=h.evidence, leaves={hex(k): v for k, v in leaves.items()}, functions=[hex(a) for a in (REFRESH, TICK, UTC, PLATFORM, DATE)], system_import=imported, tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), cases=cases, lobby_cases=lobby_cases, network_used=False, profile_activated=False, limits=['Actual initialize, refresh, setter, secondary tick, UTC adapter and calendar constructor.', 'GetSystemTime, valid month length, local offset cache and cookie backend are explicit fixtures.', 'Lobby handler receives a synthetic decoded packet; maintenance/manager/tail are fixtures.', 'No full lobby reader/dispatch, active factory, server requirement, Login success or live session proved.'])
    target = load('audit-client-release').save_snapshot(ROOT / 'code-clues/login-clock-11318', report)
    return dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(), cases=len(cases), lobby_cases=len(lobby_cases))
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exports', type=Path, required=True, help='JSON map of current request-export runs to SHA256')
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.exports.read_text('utf-8')))))
