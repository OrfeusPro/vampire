"""Current common-data session setter; synthetic FString backends only."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
SETTER = 0x14455cb10


def main():
    spec = importlib.util.spec_from_file_location('session_setter_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    hooks = {0x14145f2c0: None, 0x141441e40: None}
    h = archive.make_harness(extra_addresses=(SETTER,), fixtures=hooks)
    evidence = h.comparison / 'details/run-3d333551d1d8/details.json'
    if h.audit.sha256(evidence) != '01f72bd93f2d2cb81a1d382c8661e9a913e7b8299d9a615db9e46b6eca2a8cd0':
        raise ValueError('Session setter Ghidra evidence changed')
    uc, x = h.uc, h.x
    keys = {}
    for address, name in ((0x1495401d8, 'I_NMSessionID'), (0x14954010c, 'I_TID')):
        data = (name + '\0').encode('ascii')
        offset = h.image.offset(address - h.image.pe.base)
        if h.raw[offset:offset+len(data)] != data:
            raise ValueError('Current ToMap key literal differs')
        keys[name] = dict(address=hex(address), bytes=data.hex())
    target, incoming, old_text, new_text = [h.scratch + n for n in (0x10000, 0x11000, 0x12000, 0x13000)]
    destination = target + 0x1d8
    uc.mem_write(0x14b5662e0, bytes(4))
    uc.mem_write(0x14b1890f4, bytes(1))
    events = []
    def text_at(pointer):
        raw = bytes(uc.mem_read(pointer, 256))
        for end in range(0, 256, 2):
            if raw[end:end+2] == bytes(2): return raw[:end]
        raise ValueError('Synthetic text bound')
    def fixture(machine):
        at = machine.reg_read(x.UC_X86_REG_RIP)
        a, b = [machine.reg_read(reg) for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX)]
        if at == 0x14145f2c0:
            if {a, b} != {old_text, new_text}: raise ValueError('Comparison pointers differ')
            result = int(text_at(a) != text_at(b))
            events.append('compare_fixture')
        else:
            if (a, b) != (destination, incoming): raise ValueError('Setter destination differs')
            machine.mem_write(a, bytes(machine.mem_read(b, 16)))
            result = a
            events.append('assignment_fixture')
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX, result)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)
    for address in hooks: hooks[address] = fixture
    cases = []
    for old, new in (('', ''), ('same', 'same'), ('old', 'new'), ('short', 'longer'),
                     ('', 'new'), ('old', ''), ('Я', 'Я'), ('Я', 'Ю')):
        events.clear()
        uc.mem_write(target, b'\xa5' * 0x278)
        for pointer, value in ((old_text, old), (new_text, new)):
            uc.mem_write(pointer, (value + '\0').encode('utf-16le') + bytes(256))
        old_desc = struct.pack('<QII', old_text, len(old) + 1, len(old) + 1)
        new_desc = struct.pack('<QII', new_text, len(new) + 1, len(new) + 1)
        uc.mem_write(destination, old_desc)
        uc.mem_write(incoming, new_desc)
        before = bytes(uc.mem_read(target, 0x278))
        result = h.call(SETTER, target, incoming) & 255
        after = bytes(uc.mem_read(target, 0x278))
        changed = old != new
        if result != int(changed) or after[0x1d8:0x1e8] != (new_desc if changed else old_desc):
            raise ValueError('Native setter result differs')
        if before[:0x1d8] != after[:0x1d8] or before[0x1e8:] != after[0x1e8:]:
            raise ValueError('Setter touched neighboring common-data fields')
        if bytes(uc.mem_read(incoming, 16)) != new_desc: raise ValueError('Input descriptor changed')
        cases.append(dict(old=old, new=new, changed=bool(result), events=events.copy()))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        evidence_sha256=h.audit.sha256(evidence), setter=hex(SETTER),
        destination_inner_offset=0x1d8, destination_data_offset=0x1b0, key_literals=keys,
        cases=cases, fragments=h.fragments, network_used=False,
        limits=['Whole current setter executes with diagnostic logging disabled.',
            'FString equality and descriptor assignment are fixtures, not native allocation/string backend proof.',
            'Only synthetic text; no SDK service, GUID generation, storage, full writer, collector or game session executed.'])
    path = h.audit.save_snapshot(h.comparison / 'session-setter-replay', report)
    print(json.dumps(dict(report=str(path), sha256=h.audit.sha256(path), cases=len(cases))))


if __name__ == '__main__': main()
