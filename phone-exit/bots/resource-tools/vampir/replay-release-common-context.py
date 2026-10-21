"""Whole current common-data GMC2/SDK-setting updates with synthetic services."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
GMC = 0x14455bc40
SDK = 0x14455c950
EVIDENCE_SHA = '741a018c06373c2c6524aeb0ccae30e17e0a37915a51ad0e910a0afc08998bc7'


def run():
    spec = importlib.util.spec_from_file_location('common_context_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    service_getters = (0x1444b23c0, 0x1444b2e50)
    ensure, compare, assign, allocate, free, market = (
        0x1416b0790, 0x14145f2c0, 0x141441e40, 0x141436fb0, 0x141483160, 0x144532f30)
    copy = 0x1487f7a19
    hooks = dict.fromkeys((*service_getters, ensure, compare, assign, allocate, free, market, copy))
    h = archive.make_harness(extra_addresses=(GMC, SDK), fixtures=hooks)
    evidence = h.comparison / 'details/run-af8c285547dd/details.json'
    if h.audit.sha256(evidence) != EVIDENCE_SHA:
        raise ValueError('Common-context Ghidra evidence changed')
    uc, x = h.uc, h.x
    obj, handle, settings = [h.scratch + n for n in (0x10000, 0x11000, 0x12000)]
    state, events = {}, []

    def bounded(pointer, count):
        if not h.scratch <= pointer <= h.scratch + 0x40000 - count or not 0 <= count <= 512:
            raise ValueError('Synthetic memory bound')

    def text(pointer):
        bounded(pointer, 256)
        raw = bytes(uc.mem_read(pointer, 256))
        for i in range(0, 256, 2):
            if raw[i:i+2] == bytes(2): return raw[:i]
        raise ValueError('Synthetic UTF-16 bound')

    def alloc(count):
        if not 0 <= count <= 128: raise ValueError('Synthetic FString count bound')
        pointer = state['next']
        state['next'] += 512
        bounded(pointer, 512)
        uc.mem_write(pointer, bytes(512))
        return pointer

    def descriptor(destination, value):
        if value is None:
            uc.mem_write(destination, bytes(16))
            return
        raw = (value + '\0').encode('utf-16le')
        count = len(raw) // 2
        pointer = alloc(count)
        uc.mem_write(pointer, raw)
        uc.mem_write(destination, struct.pack('<QII', pointer, count, count))

    def fixture(machine):
        at = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c = [machine.reg_read(reg) for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        result = 0
        if at in service_getters:
            if at != state['getter']: raise ValueError('Unexpected service getter')
            result = handle
            events.append('service')
        elif at == ensure:
            if a != handle: raise ValueError('Unexpected lazy service owner')
            machine.mem_write(handle + 0x110, struct.pack('<Q', settings if state['available'] else 0))
            events.append('lazy_service')
            result = handle
        elif at == compare:
            result = int(text(a) != text(b))
            events.append('compare')
        elif at == assign:
            if a not in state['destinations']: raise ValueError('Assignment outside common fields')
            bounded(b, 16)
            machine.mem_write(a, bytes(machine.mem_read(b, 16)))
            events.append(('assign', a - obj))
            result = a
        elif at == allocate:
            bounded(a, 16)
            pointer = alloc(b)
            count = struct.unpack('<QII', bytes(machine.mem_read(a, 16)))[1]
            machine.mem_write(a, struct.pack('<QII', pointer, count, b))
            events.append('allocation')
            result = a
        elif at == copy:
            bounded(a, c)
            bounded(b, c)
            machine.mem_write(a, bytes(machine.mem_read(b, c)))
            result = a
            events.append('copy')
        elif at == market:
            if b & 255 != state['market_code']: raise ValueError('Market byte changed')
            descriptor(a, state['market_text'])
            result = a
            events.append('market_fixture')
        elif at == free:
            bounded(a, 0)
            events.append('free_fixture')
        else:
            raise ValueError('Unreviewed fixture')
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX, result)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)

    for at in hooks: hooks[at] = fixture
    uc.mem_write(0x14b5662e0, bytes(4))
    uc.mem_write(0x14b1890f4, bytes(1))
    cases = []
    profiles = (
        (GMC, service_getters[0], (0x108, 0x118, 0x128, 0x138)),
        (SDK, service_getters[1], (0xc8, 0xd8, 0xe8)))
    # None is a zero-count FString; '' is a one-count NUL FString.
    pairs = ((None, None), (None, ''), ('', None), ('same', 'same'),
             ('old', 'new'), ('short', 'longer'), ('', 'new'), ('old', ''),
             ('Я', 'Я'), ('Я', 'Ю'))
    for function, getter, offsets in profiles:
        scenarios = [('present', old, new, None) for old, new in pairs]
        scenarios += [('missing', 'old', 'new', None), ('lazy', 'old', 'new', None)]
        scenarios += [('present', 'old', 'new', i) for i in range(len(offsets))]
        for mode, old, new, single in scenarios:
            state.clear()
            state.update(next=h.scratch + 0x18000, getter=getter, available=mode != 'missing',
                destinations={obj + offset for offset in offsets}, market_code=2)
            uc.mem_write(obj, b'\xa5' * 0x278)
            uc.mem_write(handle, bytes(0x118))
            uc.mem_write(settings, bytes(0x700))
            if mode == 'present': uc.mem_write(handle + 0x110, struct.pack('<Q', settings))
            incoming = [new if single is None or i == single else old for i in range(len(offsets))]
            # GMC2 uses the same source descriptor for its two IP destinations.
            if function == GMC:
                if single in (0, 1): incoming[0] = incoming[1] = new
                for offset, value in zip((0x38, 0x3f0, 0x3e0), (incoming[0], incoming[2], incoming[3])):
                    descriptor(settings + offset, value)
            else:
                descriptor(settings + 0x38, incoming[0])
                descriptor(settings + 0x28, incoming[2])
                uc.mem_write(settings + 0x48, bytes((state['market_code'],)))
                state['market_text'] = incoming[1]
            for offset in offsets: descriptor(obj + offset, old)
            before = bytes(uc.mem_read(obj, 0x278))
            settings_before = bytes(uc.mem_read(settings, 0x700))
            events.clear()
            result = h.call(function, obj, budget=16000) & 255
            after = bytes(uc.mem_read(obj, 0x278))
            expected = [old if mode == 'missing' else value for value in incoming]
            normalized = lambda value: value or ''
            changed = any(normalized(value) != normalized(old) for value in expected)
            if result != int(changed): raise ValueError('Native update changed flag differs')
            mask = set()
            for offset, value in zip(offsets, expected):
                pointer, count, capacity = struct.unpack_from('<QII', after, offset)
                actual = text(pointer).decode('utf-16le') if count > 1 else ''
                if actual != normalized(value): raise ValueError('Native update field differs')
                field_changed = normalized(value) != normalized(old)
                if not field_changed and before[offset:offset+16] != after[offset:offset+16]:
                    raise ValueError('Equal FString descriptor changed')
                mask.update(range(offset, offset + 16))
            if any(before[i] != after[i] for i in range(0x278) if i not in mask):
                raise ValueError('Native update touched neighboring fields')
            if bytes(uc.mem_read(settings, 0x700)) != settings_before:
                raise ValueError('Native update changed source settings')
            if mode == 'missing' and any(e in events for e in ('compare', 'market_fixture', 'allocation')):
                raise ValueError('Missing service consumed field values')
            cases.append(dict(function=hex(function), mode=mode, old=old, new=new,
                single_field=single, destinations=list(offsets), changed=bool(result), events=events.copy()))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        evidence_sha256=EVIDENCE_SHA, fragments=h.fragments, cases=cases,
        native_execution=True, network_used=False,
        limits=['Whole current UpdateGmc2 and UpdateSDKSetting execute with diagnostic logging disabled.',
            'Synthetic service lookup/lazy initialization, FString comparison/allocation/assignment/free and bounded CRT copy fixtures.',
            'Market formatter is an explicit fixture: only its byte input and destination are tested here.',
            'No actual SDK/GMC2 HTTP parser, language/timezone/player update, full writer/collector or live session.'])
    return h, report


def main():
    h, report = run()
    path = h.audit.save_snapshot(h.comparison / 'common-context-replay', report)
    print(json.dumps(dict(report=str(path), sha256=h.audit.sha256(path), cases=len(report['cases']))))


if __name__ == '__main__': main()
