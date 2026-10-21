"""Native clock initialize -> server offset setter -> tick, with a UTC OS fixture."""
import calendar
from datetime import datetime
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
INIT, REFRESH, SET, TICK = 0x1445d4bc0, 0x1445dad40, 0x1445d8a30, 0x1445d8b20
UTC, PLATFORM, DATE = 0x14156ae00, 0x1415da9a0, 0x1415483d0
ADDEND, SYSTEM_CALL, IAT = 0x14b567700, 0x1415da9f1, 0x14899c928


def main():
    spec = importlib.util.spec_from_file_location('clock_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec);spec.loader.exec_module(archive)
    # API callsite is intercepted before CALL; the surrounding platform code runs.
    hooks = {a: None for a in (SYSTEM_CALL, 0x141553720, 0x1445d0050, 0x1487eac40)}
    h = archive.make_harness(extra_addresses=(REFRESH, TICK, UTC, PLATFORM, DATE), fixtures=hooks)
    evidence = h.comparison / 'bootstrap/run-1ffad6459713/export/bootstrap.json'
    if h.audit.sha256(evidence) != '5da074763b362b2d05d3adfac4ec200ee9f221e34c469fbd2fb1fec9878a7bbb':
        raise ValueError('Clock Ghidra evidence changed')
    functions = {int(f['address'], 16): f for f in json.loads(evidence.read_text('utf-8'))['functions']}
    uc, x = h.uc, h.x
    def source(address, count):
        off = h.image.offset(address - h.image.pe.base)
        return h.raw[off:off + count]
    decoder = h.native.capstone.Cs(h.native.capstone.CS_ARCH_X86, h.native.capstone.CS_MODE_64)
    decoder.detail = True
    for address in (INIT, SET):
        rows = functions[address]['instructions'];end = address;data_pages = set()
        for row in rows:
            at, raw = int(row['address'], 16), bytes.fromhex(row['bytes'])
            if at != end or source(at, len(raw)) != raw:
                raise ValueError('Clock leaf source/boundary differs')
            decoded = list(decoder.disasm(raw, at))
            if len(decoded) != 1 or decoded[0].size != len(raw):
                raise ValueError('Clock leaf decoder boundary differs')
            for operand in decoded[0].operands:
                if operand.type == h.native.X86_OP_MEM and operand.mem.base == h.native.X86_REG_RIP:
                    data_pages.add((at + len(raw) + operand.mem.disp) & ~4095)
            end += len(raw)
        h.ranges.append((address, end))
        for page in sorted(data_pages | set(range(address & ~4095, (end + 4095) & ~4095, 4096))):
            if not any(lo <= page <= hi for lo, hi, permissions in uc.mem_regions()):
                uc.mem_map(page, 4096)
                try:uc.mem_write(page, source(page, 4096))
                except ValueError:pass  # PE zero-fill globals have no file bytes.
    api_row = next(r for r in functions[PLATFORM]['instructions'] if int(r['address'], 16) == SYSTEM_CALL)
    if api_row['text'] != 'CALL qword ptr [0x14899c928]' or source(SYSTEM_CALL, 6).hex() != api_row['bytes']:
        raise ValueError('UTC platform API callsite differs')
    system_import = h.imports.import_at(h.raw, h.image, IAT)
    if (system_import['dll'].lower(), system_import['name']) != ('kernel32.dll', 'GetSystemTime'):
        raise ValueError('Expected UTC SystemTime import')
    clock, current, events = h.scratch + 0x10000, {}, []
    def fixture(machine):
        address = machine.reg_read(x.UC_X86_REG_RIP)
        a, b = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX)]
        result = 0
        if address == SYSTEM_CALL:
            if not h.scratch <= a <= h.scratch + 0x40000 - 16:
                raise ValueError('UTC SYSTEMTIME fixture outside stack')
            dt = current['utc']
            machine.mem_write(a, struct.pack('<8H', dt.year, dt.month, (dt.weekday()+1)%7,
                dt.day, dt.hour, dt.minute, dt.second, dt.microsecond//1000))
            events.append('GetSystemTime')
            machine.reg_write(x.UC_X86_REG_RIP, address + 6)
            return
        if address == 0x141553720:
            result = calendar.monthrange(a, b)[1]  # Valid OS dates only; validation backend fixture.
        elif address == 0x1445d0050:
            result = current['local_ticks'] & ((1 << 64)-1)
        elif address == 0x1487eac40:
            cookie = int.from_bytes(machine.mem_read(0x14b274780, 8), 'little')
            if a != cookie:
                raise ValueError('Native clock stack cookie differs')
        else:
            raise ValueError('Unexpected clock fixture')
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX, result)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)
    for address in hooks:
        hooks[address] = fixture
    epoch = datetime(1970, 1, 1)
    cases = []
    for utc in (epoch, datetime(2000, 2, 29, 23, 59, 59, 999000), datetime(2026, 10, 21, 16, 29, 2, 863000)):
        delta = utc - epoch
        unix_ms = delta.days*86400000 + delta.seconds*1000 + delta.microseconds//1000
        ticks_delta = utc - datetime(1, 1, 1)
        datetime_ticks = (ticks_delta.days*86400 + ticks_delta.seconds)*10000000 + utc.microsecond*10
        for minutes in (-720, 0, 540, 840):
            for local_minutes in (0, 180):
                uc.mem_write(clock - 16, b'\xa5'*16 + b'\0'*80 + b'\xa5'*16)
                uc.mem_write(ADDEND, b'\0'*8)
                current.update(utc=utc, local_ticks=local_minutes*600000000)
                events.clear()
                h.call(INIT, clock, budget=16384)
                before = struct.unpack('<qq', bytes(uc.mem_read(clock + 16, 16)))
                if before != (unix_ms*10000, unix_ms*10000 + current['local_ticks']):
                    raise ValueError('Native clock Unix epoch conversion differs')
                if int.from_bytes(uc.mem_read(clock + 64, 8), 'little') != datetime_ticks:
                    raise ValueError('Actual UTC calendar constructor differs')
                # Deliberately differs from local UTC: server sample is a separate field.
                server_ms = unix_ms + 12345
                h.call(SET, clock, server_ms, minutes & 65535, budget=16384)
                uc.reg_write(x.UC_X86_REG_XMM1, struct.unpack('<I', struct.pack('<f', 0.016))[0])
                h.call(TICK, clock + 8, budget=16384)
                raw, local, server, baseline = struct.unpack('<4q', bytes(uc.mem_read(clock + 16, 32)))
                if (raw, local, server, baseline) != ((unix_ms+minutes*60000)*10000,
                        unix_ms*10000+current['local_ticks'], server_ms*10000, server_ms*10000):
                    raise ValueError('Native clock offset/server fields differ')
                addend = struct.unpack('<q', bytes(uc.mem_read(ADDEND, 8)))[0]
                if addend != minutes*600000000 or bytes(uc.mem_read(clock + 48, 1)) != b'\x01' or bytes(uc.mem_read(clock + 56, 1)) != b'\0':
                    raise ValueError('Native clock synchronization state differs')
                if events != ['GetSystemTime', 'GetSystemTime']:
                    raise ValueError('Expected initialize and tick UTC acquisitions')
                if bytes(uc.mem_read(clock - 16, 16)) != b'\xa5'*16 or bytes(uc.mem_read(clock + 80, 16)) != b'\xa5'*16:
                    raise ValueError('Native clock crossed object guards')
                cases.append(dict(utc=utc.isoformat(), offset_minutes=minutes, local_minutes=local_minutes,
                    unix_ms=unix_ms, raw_ticks=raw, local_ticks=local, server_ticks=server,
                    ping_clock_ms=int(float(raw)*0.0001), system_time_calls=len(events)))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        evidence_sha256=h.audit.sha256(evidence), system_import=system_import, cases=cases, network_used=False,
        helper_sha256={name:h.audit.sha256(HERE/name) for name in ('replay-release-archive-input.py','build-native-entry-code.py')},
        fragments=[f for f in h.fragments if f['root_begin_rva']+h.image.pe.base in (REFRESH,TICK,UTC,PLATFORM,DATE)],
        leaf_instructions={hex(a):functions[a]['instructions'] for a in (INIT,SET)},
        limits=['Actual initialize, refresh, signed-minute setter, tick, UTC platform adapter and calendar constructor execute.',
            'OS GetSystemTime, valid-date validation, local UTC offset cache and cookie backend are fixtures.',
            'No host clock mutation, server session, first-packet role or active factory override established.'])
    target = h.audit.save_snapshot(h.comparison/'clock-replay', report)
    print(json.dumps(dict(report=str(target), sha256=h.audit.sha256(target), cases=len(cases))))


if __name__ == '__main__':
    main()
