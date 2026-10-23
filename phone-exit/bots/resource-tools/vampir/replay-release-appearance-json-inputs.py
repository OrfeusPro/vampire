"""Whole appearance helper to captured JSON boundaries; no JSON engine claim."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def run():
    spec = importlib.util.spec_from_file_location('appearance_inputs_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec); spec.loader.exec_module(archive)
    hooks = (0x14690a090, 0x141426c10, 0x1415f2740, 0x1415ea570,
        0x1415e49b0, 0x1415e5fd0, 0x141483160, 0x1456746c0, 0x141436fb0)
    fixtures = dict.fromkeys(hooks)
    h = archive.make_harness(extra_addresses=(0x146447e50, 0x14142e7d0), fixtures=fixtures)
    uc, x = h.uc, h.x
    owner, entries, bits, output, shared = [h.scratch + n for n in (0x10000, 0x11000, 0x14000, 0x15000, 0x16000)]
    state, events = {}, []
    def finish(result=None):
        if result is not None: uc.reg_write(x.UC_X86_REG_RAX, result)
        sp = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(sp, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
    def text(at):
        pointer, units, capacity = struct.unpack('<QII', bytes(uc.mem_read(at, 16)))
        if not 0 <= units <= capacity <= 64: raise ValueError('Appearance text capture bound')
        return bytes(uc.mem_read(pointer, max(0, units - 1) * 2)).decode('utf-16le') if units else ''
    def fixture(machine):
        at = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c, d = [machine.reg_read(reg) for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        if at == 0x14690a090:
            if a not in (0x50, 0x18): raise ValueError('Appearance JSON allocation contract')
            p = state['heap']; state['heap'] += 0x100
            machine.mem_write(p, bytes(a)); finish(p)
        elif at == 0x141426c10:
            raw = bytearray()
            for i in range(64):
                pair = bytes(machine.mem_read(b + i * 2, 2))
                if pair == b'\0\0': break
                raw.extend(pair)
            else: raise ValueError('Appearance literal bound')
            p = state['heap']; state['heap'] += 0x100
            machine.mem_write(p, bytes(raw) + b'\0\0')
            machine.mem_write(a, struct.pack('<QII', p, len(raw) // 2 + 1, len(raw) // 2 + 1)); finish(a)
        elif at == 0x141436fb0:
            if not 0 <= b <= 64: raise ValueError('Appearance string allocation bound')
            p = state['heap']; state['heap'] += 0x100
            machine.mem_write(p, bytes(b * 2))
            machine.mem_write(a, struct.pack('<QII', p, b, b)); finish(a)
        elif at == 0x1456746c0:
            value = struct.unpack('<f', machine.reg_read(x.UC_X86_REG_XMM2).to_bytes(16, 'little')[:4])[0]
            events.append(dict(kind='entry', key=text(b), value=value, mode=d & 255)); finish()
        elif at == 0x1415f2740:
            value = struct.unpack('<d', machine.reg_read(x.UC_X86_REG_XMM2).to_bytes(16, 'little')[:8])[0]
            events.append(dict(kind='number', key=text(b), value=value)); finish()
        elif at == 0x1415ea570:
            if b != output or c != 0: raise ValueError('Appearance serializer setup contract')
            machine.mem_write(a, struct.pack('<QQ', output, 0))
            events.append(dict(kind='setup', raw_flag=c)); finish(a)
        elif at == 0x1415e49b0:
            # Lifetime and JSON writer object are explicit fixtures. Keep refcounts
            # above final-release thresholds; no native JSON destructor claim.
            control = int.from_bytes(machine.mem_read(a + 8, 8), 'little')
            machine.mem_write(control + 8, struct.pack('<ii', 100, 100))
            machine.mem_write(shared, struct.pack('<Qii', 0, 100, 100) + bytes(0x30))
            finish(shared)
        elif at == 0x1415e5fd0:
            if int.from_bytes(machine.mem_read(a, 8), 'little') != shared + 16 or c != 1:
                raise ValueError('Appearance serializer finalize contract')
            events.append(dict(kind='serialize', raw_flag=c)); finish(1)
        else:
            finish()  # bounded free fixture, no OS memory ownership claim
    for at in hooks: fixtures[at] = fixture
    cases = []
    for count, occupied in ((0, ()), (1, (0,)), (4, (0, 2, 3)), (35, (0, 31, 32, 34))):
        for voice in (0, 1, 255):
            events.clear(); state['heap'] = h.scratch + 0x20000
            uc.mem_write(owner, bytes(0x90)); uc.mem_write(output, b'\xa5' * 32)
            uc.mem_write(owner + 0x20, bytes((voice,)))
            uc.mem_write(owner + 0x28, b'\x07')
            uc.mem_write(owner + 0x30, struct.pack('<Q', entries))
            uc.mem_write(owner + 0x58, struct.pack('<I', count))
            words = [0] * max(1, (count + 31) // 32)
            expected = []
            for index in occupied:
                words[index // 32] |= 1 << (index % 32)
                key = 'fixture_' + str(index)
                p = h.scratch + 0x18000 + index * 64
                data = key.encode('utf-16le') + b'\0\0'; uc.mem_write(p, data)
                uc.mem_write(entries + index * 0x30 + 0x10, struct.pack('<QII', p, len(data) // 2, len(data) // 2))
                value = index * 0.25 - 0.5
                uc.mem_write(entries + index * 0x30 + 0x20, struct.pack('<f', value))
                expected.append(dict(kind='entry', key=key, value=value, mode=7))
            if count > 32:
                uc.mem_write(bits, struct.pack('<' + 'I' * len(words), *words))
                uc.mem_write(owner + 0x50, struct.pack('<Q', bits))
            else: uc.mem_write(owner + 0x40, struct.pack('<I', words[0]))
            try:
                result = h.call(0x146447e50, owner, output, budget=200000)
            except h.env.unicorn.UcError as error:
                raise ValueError('Appearance helper fault at ' + hex(uc.reg_read(x.UC_X86_REG_RIP))) from error
            if result != output:
                raise ValueError('Appearance helper return contract')
            expected += [dict(kind='number', key='VoiceType', value=float(voice)),
                dict(kind='setup', raw_flag=0), dict(kind='serialize', raw_flag=1)]
            if events != expected: raise ValueError('Appearance helper captured inputs differ: ' + repr(events))
            cases.append(dict(slots=count, occupied=list(occupied), voice=voice, events=events.copy()))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        native_execution=True, network_used=False, cases=cases,
        limits=['Whole outer appearance helper and sparse iterator execute.',
            'Entry helper, JSON setters/writer/setup/serialize, allocation/refcounts/free/string assignment are fixtures/captures.',
            'Captured inputs are not actual JSON output, formatting, property-key conversion or valid customization rows.',
            'Synthetic owner values and sparse keys; no producer, server, network or real creation.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-appearance-json-inputs', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
