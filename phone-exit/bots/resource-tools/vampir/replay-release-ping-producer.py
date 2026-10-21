"""Execute current Ping producer, readiness gates, constructor and ID getter offline."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
PRODUCER, READY, READY_CORE, CTOR, ID = 0x1467d0d10, 0x144ab2060, 0x144ab35d0, 0x1456d8b40, 0x14140d460
CLOCK, CLOCK_GLOBAL, SCALE, FLAG = 0x1445ce230, 0x14b567a40, 0x148a0a758, 0x14b595026
SEND, TABLE, PACKET_TABLE = 0x1467d0a70, 0x149dcb358, 0x149928958


def main():
    spec = importlib.util.spec_from_file_location('ping_release_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    hooks = {a: None for a in (0x144ab2a60, 0x144ab1f90, 0x144211930, 0x144ab2440, SEND, 0x1456b7990)}
    h = archive.make_harness(extra_addresses=(PRODUCER, READY_CORE), extra_leaves=(CTOR, ID, CLOCK), fixtures=hooks)
    evidence = h.comparison / 'details/run-f85aa67d34d9/details.json'
    if h.audit.sha256(evidence) != '9e91f4e11664ba34e836c5b33b67ffbcf2a9382055d11434312e908562e959e4':
        raise ValueError('Current Ping producer Ghidra evidence changed')
    uc, x = h.uc, h.x
    gate_evidence = h.comparison / 'details/run-396c0efa2fde/details.json'
    if h.audit.sha256(gate_evidence) != '6f17a039fb74489e8423113816e2cb34cd3c058c6ad77abcec6879f3b36c7d05':
        raise ValueError('Current readiness Ghidra evidence changed')
    gate = next(f for f in json.loads(gate_evidence.read_text('utf-8'))['functions'] if int(f['address'], 16) == READY)
    if not any(hex(READY_CORE) in r.get('references', []) and r['text'].startswith('JMP ') for r in gate['instructions']):
        raise ValueError('Readiness tail target differs')
    cursor = READY
    for row in gate['instructions']:
        address, data = int(row['address'], 16), bytes.fromhex(row['bytes'])
        off = h.image.offset(address - h.image.pe.base)
        if address != cursor or h.raw[off:off + len(data)] != data:
            raise ValueError('Readiness instruction boundary/source differs')
        cursor += len(data)
    h.ranges.append((READY, cursor))  # Ghidra-verified body without a .pdata root.
    for page in range(READY & ~4095, (cursor + 4095) & ~4095, 4096):
        if not any(lo <= page <= hi for lo, hi, permissions in uc.mem_regions()):
            uc.mem_map(page, 4096)
            off = h.image.offset(page - h.image.pe.base)
            uc.mem_write(page, h.raw[off:off + 4096])
    base, context, peer, other_peer, clock = [h.scratch + n for n in (0x10000, 0x11000, 0x12000, 0x13000, 0x14000)]
    param = base + 8  # Actual producer receives the wrapper's secondary interface.
    for address in (TABLE, CLOCK_GLOBAL):
        page = address & ~4095
        if not any(lo <= page <= hi for lo, hi, permissions in uc.mem_regions()):
            uc.mem_map(page, 4096)
            try:
                off = h.image.offset(page - h.image.pe.base)
                uc.mem_write(page, h.raw[off:off + 4096])
            except ValueError:
                pass
    def source(address, count):
        off = h.image.offset(address - h.image.pe.base)
        return h.raw[off:off + count]
    if int.from_bytes(source(TABLE + 0x38, 8), 'little') != SEND:
        raise ValueError('Wrapper send table changed')
    if int.from_bytes(source(PACKET_TABLE + 0x28, 8), 'little') != ID:
        raise ValueError('Ping ID table changed')
    if source(SCALE, 8).hex() != '2d431cebe2361a3f':
        raise ValueError('Ping clock multiplier changed')
    events, sent, current = [], [], {}
    def fixture(machine):
        address = machine.reg_read(x.UC_X86_REG_RIP)
        a, b = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX)]
        result = 0
        if address == 0x144ab1f90:
            result = context
        elif address == 0x144211930:
            result = current['mode']
        elif address == SEND:
            if a != base or not h.scratch <= b <= h.scratch + 0x40000 - 32:
                raise ValueError('Ping send capture outside fixture')
            if int.from_bytes(machine.mem_read(b, 8), 'little') != PACKET_TABLE:
                raise ValueError('Actual Ping constructor vptr differs')
            sent.append(struct.unpack('<qq', bytes(machine.mem_read(b + 16, 16))))
            result = 1
        elif address == 0x144ab2440 and a != base:
            raise ValueError('Recovery capture wrapper differs')
        events.append(hex(address))
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX, result)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)
    for address in hooks:
        hooks[address] = fixture
    if h.call(ID, 0) != 16:
        raise ValueError('Native Ping ID getter differs')
    cases = []
    inputs = [
        ('first', 50010000, 0, 0, 0, 0, 0, 0),
        ('boundary', 50000000, 0, 0, 0, 0, 0, 0),
        ('fractional', 50019999, 0, 0, 0, 0, 0, 0),
        ('delta-boundary', 150000000, 10000, 0, 0, 0, 0, 0),
        ('delta-send', 150010000, 10000, 0, 0, 0, 0, 0),
        ('clock-before-last', 10000000, 2000, 0, 0, 0, 0, 0),
        ('mode-two', 50010000, 0, 0, 0, 2, 0, 0),
        ('context-special', 50010000, 0, 0, 0, 0, 1, 0),
        ('wrapper-special', 50010000, 0, 0, 0, 0, 0, 1),
        ('five-outstanding', 50010000, 0, 5, 0, 0, 0, 0),
        ('six-outstanding', 50010000, 0, 6, 0, 0, 0, 0),
        ('override-six', 50010000, 0, 6, 1, 0, 0, 0),
    ]
    for index in (0, 1, 3):
        for name, ticks, last, outstanding, override, mode, special_context, special_wrapper in inputs:
            uc.mem_write(base, b'\0' * 0x5000)
            uc.mem_write(base, struct.pack('<Q', TABLE))
            uc.mem_write(base + 0x10, struct.pack('<Q', peer))
            uc.mem_write(context + 0x10, struct.pack('<Q', other_peer))
            uc.mem_write(peer + 0x2a5, bytes((special_wrapper,)))
            uc.mem_write(other_peer + 0x2a5, bytes((special_context,)))
            uc.mem_write(clock + 16, struct.pack('<q', ticks))
            uc.mem_write(CLOCK_GLOBAL, struct.pack('<Q', clock))
            uc.mem_write(FLAG, bytes((override,)))
            uc.mem_write(param + 0x158, struct.pack('<qii', last, index, outstanding))
            uc.mem_write(param + 0x110, b'\xff')  # Unrelated float timer deliberately disabled.
            current['mode'] = mode
            events.clear();sent.clear()
            h.call(PRODUCER, param, budget=8192)
            now = int(ticks * struct.unpack('<d', source(SCALE, 8))[0])
            eligible = mode != 2 and not special_context and not special_wrapper and now - last > 5000
            recovery = eligible and not override and outstanding >= 6
            expected = [(now, now - last)] if eligible and not recovery else []
            if sent != expected or events.count(hex(0x144ab2440)) != int(recovery):
                raise ValueError('Native Ping producer branch differs')
            actual_last, actual_index, actual_count = struct.unpack('<qii', bytes(uc.mem_read(param + 0x158, 16)))
            if (actual_last, actual_index, actual_count) != (now if expected else last, index, 0 if recovery else outstanding + bool(expected)):
                raise ValueError('Native Ping producer state differs')
            if expected and int.from_bytes(uc.mem_read(param + 0x170 + index * 8, 8), 'little') != now:
                raise ValueError('Native Ping tracking slot differs')
            for slot in range(4):
                actual = int.from_bytes(uc.mem_read(param + 0x170 + slot * 8, 8), 'little')
                if actual != (now if expected and slot == index else 0):
                    raise ValueError('Native Ping changed a neighbouring tracking slot')
            cases.append(dict(name=name, index=index, ticks=ticks, last=last, outstanding=outstanding,
                sent=sent.copy(), recovery=recovery, state=(actual_last, actual_index, actual_count)))
    report = dict(source_sha256=h.sha, producer=hex(PRODUCER), readiness=hex(READY), constructor=hex(CTOR),
        id_getter=hex(ID), packet_id=16, scale_bytes=source(SCALE, 8).hex(), evidence_sha256=h.audit.sha256(evidence),
        readiness_evidence_sha256=h.audit.sha256(gate_evidence),
        tool_sha256=h.audit.sha256(Path(__file__)), cases=cases, network_used=False,
        helper_sha256={name: h.audit.sha256(HERE / name) for name in
            ('replay-release-archive-input.py', 'replay-release-nested-read-thunk.py', 'build-native-entry-code.py')},
        fragments=[f for f in h.fragments if f['root_begin_rva'] + h.image.pe.base in (PRODUCER, READY_CORE)],
        leaves=[f for f in h.leaves if int(f['address'], 16) in (CTOR, ID, CLOCK)],
        readiness_thunk_instructions=gate['instructions'],
        table_bytes={hex(TABLE): source(TABLE, 80).hex(), hex(PACKET_TABLE): source(PACKET_TABLE, 64).hex()},
        limits=['Native producer, two readiness gates, clock-pointer getter, constructor and ID getter execute.',
            'Clock-cache contents, raw mode, context getter, base update, send/recovery and cleanup are fixtures.',
            'Other float timer disabled; no clock epoch, acquisition, framing, live scheduling or server necessity established.'])
    target = h.audit.save_snapshot(h.comparison / 'ping-producer-replay', report)
    print(json.dumps(dict(report=str(target), sha256=h.audit.sha256(target), cases=len(cases))))


if __name__ == '__main__':
    main()
