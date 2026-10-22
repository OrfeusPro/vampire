"""Current creation owner constructor and class getter, with explicit UI fixtures."""
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def run():
    spec = importlib.util.spec_from_file_location('create_class_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    fixtures = {0x1445d3da0: None, 0x145c8df30: None}
    h = archive.make_harness(extra_addresses=(0x146442670, 0x14644a0c0), fixtures=fixtures)
    evidence = h.comparison / 'details/run-1dc059f7b039/details.json'
    evidence_sha = 'f510bcdbfb4fb0d3deef03fe3cb3dc681b2a74eb69633531e986554972500303'
    if h.audit.sha256(evidence) != evidence_sha:
        raise ValueError('Creation constructor / getter export changed')
    uc, x = h.uc, h.x
    owner, ui, metadata, ui_type, entries = [h.scratch + offset for offset in
        (0x10000, 0x11000, 0x12000, 0x13000, 0x14000)]
    table = 0x149ca7190
    offset = h.image.offset(table - h.image.pe.base)
    if struct.unpack_from('<Q', h.raw, offset + 0x48)[0] != 0x146449dc0 or struct.unpack_from('<Q', h.raw, offset + 0x90)[0] != 0x14644a0c0:
        raise ValueError('Creation owner vtable binding changed')
    sentinel = struct.unpack_from('<I', h.raw, h.image.offset(0x1496726a0 - h.image.pe.base))[0]
    state, calls = {}, []

    def fixture(machine):
        address = machine.reg_read(x.UC_X86_REG_RIP)
        if address == 0x1445d3da0:
            if machine.reg_read(x.UC_X86_REG_RCX) != 0:
                raise ValueError('Unexpected UI lookup argument')
            result = ui if state['present'] else 0
            calls.append('lookup')
        elif address == 0x145c8df30:
            result = metadata
            calls.append('type')
        else:
            raise ValueError('Unknown creation source fixture')
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX, result)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)

    for address in fixtures:
        fixtures[address] = fixture
    cases = []
    for disabled, present, type_case, raw_class, raw_appearance in itertools.product(
            (0, 1), (False, True), ('match', 'mismatch', 'out_of_range'),
            (0, 1, 0x80000000, 0xffffffff), (0, 2, 255)):
        state['present'] = present
        calls.clear()
        uc.mem_write(owner - 16, b'\xa5' * (0x90 + 32))
        uc.mem_write(ui, bytes(0x400))
        uc.mem_write(ui + 0x10, struct.pack('<Q', ui_type))
        uc.mem_write(ui + 0x360, struct.pack('<IB', raw_class, raw_appearance))
        uc.mem_write(metadata, bytes(0x40))
        uc.mem_write(metadata + 0x38, struct.pack('<i', 1))
        uc.mem_write(ui_type + 0x30, struct.pack('<Qi', entries, 0 if type_case == 'out_of_range' else 2))
        uc.mem_write(entries, struct.pack('<QQQ', 0, metadata + 0x30 if type_case == 'match' else metadata + 0x20, 0))
        uc.mem_write(0x14b2f314b, bytes([disabled]))
        before_ui = bytes(uc.mem_read(ui, 0x400))
        valid = not disabled and present and type_case == 'match'
        if h.call(0x146442670, owner) != owner:
            raise ValueError('Creation owner constructor return changed')
        if int.from_bytes(uc.mem_read(owner, 8), 'little') != table:
            raise ValueError('Creation owner constructor vptr changed')
        actual_appearance = uc.mem_read(owner + 0x30, 1)[0]
        # Constructor does not initialize +30 if UI/type is unavailable.
        if actual_appearance != (raw_appearance if valid else 0xa5):
            raise ValueError('Creation owner initial appearance source differs')
        actual_class = h.call(0x14644a0c0, owner) & 0xffffffff
        if actual_class != (raw_class if valid else sentinel):
            raise ValueError('Creation class source differs')
        if bytes(uc.mem_read(ui, 0x400)) != before_ui:
            raise ValueError('Creation getter changed source UI')
        if bytes(uc.mem_read(owner - 16, 16)) != b'\xa5' * 16 or bytes(uc.mem_read(owner + 0x90, 16)) != b'\xa5' * 16:
            raise ValueError('Creation owner canary changed')
        if disabled and calls:
            raise ValueError('Disabled lookup still reached UI')
        cases.append(dict(disabled=bool(disabled), present=present, type_case=type_case,
            raw_class=raw_class, raw_appearance=raw_appearance, class_result=actual_class,
            initial_appearance=actual_appearance, lookup_calls=calls.copy()))
    # Review the exact standalone tail serializer, not a guessed unwind entry.
    address = 0x144aae8c0
    expected = bytes.fromhex('488b024c8bc2488bd1498bc848ff6010')
    actual = h.raw[h.image.offset(address - h.image.pe.base):][:len(expected)]
    if actual != expected:
        raise ValueError('Object writer tail bytes changed')
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        evidence=dict(path=str(evidence), sha256=evidence_sha),
        native_execution=True, network_used=False, cases=cases, sentinel=sentinel,
        object_writer_tail=dict(address=hex(address), bytes=actual.hex()),
        limits=['Whole creation owner constructor 0x146442670 and getter 0x14644a0c0 execute on synthetic memory.',
            'UI lookup, type singleton, metadata, guard and class/appearance bytes are fixtures.',
            'Returned class value is copied raw; no class-table ID validity or UI selection default proven.',
            'Object writer tail is checked statically, not executed in this replay.',
            'No full producer, JSON appearance generation, creation packet, live Login or account change.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-create-class-source', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']), sentinel=report['sentinel'])))
