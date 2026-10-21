"""Source-bound leaf replay after Ghidra dependency inspection; no whole-reader claim."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / '.tools/vampir-analysis'))
import capstone
import unicorn
from unicorn import x86_const as x


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def replay(code, address, result, displacement):
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    uc.mem_map(address & ~4095, 4096)
    uc.mem_write(address, code)
    uc.mem_map(0x100000, 4096)
    uc.mem_map(0x200000, 4096)
    uc.mem_map(0x300000, 4096)
    obj, archive, table = 0x100100 + displacement, 0x100700 + displacement, 0x100b00
    target, stop, stack = 0x200000, 0x200100, 0x300800
    uc.mem_write(obj, struct.pack('<Q', table))
    uc.mem_write(table + 0x20, struct.pack('<Q', target))
    uc.mem_write(target, b'\xc3')  # Explicit fixture virtual reader, only return behavior.
    uc.mem_write(stack, struct.pack('<Q', stop))
    captured = []
    def hook(machine, current, size, unused):
        if current == target:
            captured.append(dict(rcx=machine.reg_read(x.UC_X86_REG_RCX),
                                 rdx=machine.reg_read(x.UC_X86_REG_RDX)))
            machine.reg_write(x.UC_X86_REG_RAX, result)
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    for reg, value in ((x.UC_X86_REG_RCX, archive), (x.UC_X86_REG_RDX, obj), (x.UC_X86_REG_RSP, stack)):
        uc.reg_write(reg, value)
    uc.emu_start(address, stop, count=16)
    if (captured != [dict(rcx=obj, rdx=archive)] or uc.reg_read(x.UC_X86_REG_RIP) != stop
            or uc.reg_read(x.UC_X86_REG_RAX) != result):
        raise ValueError('Nested reader dispatch differs')
    return dict(returned=result, displacement=displacement, object_archive_forwarded=True)


def main():
    audit = load('thunk_audit', HERE / 'audit-client-release.py')
    native = load('thunk_entry', HERE / 'build-native-entry-code.py')
    root = native.ROOT
    comparison = root / 'ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c'
    evidence = comparison / 'details/run-5ca35f2db51a/details.json'
    expected_evidence = 'f76d87c0c5a4f2704246e0b50c2dcf196af888bb10955d4730304840a70e0fd9'
    if audit.sha256(evidence) != expected_evidence:
        raise ValueError('Reviewed Ghidra evidence changed')
    builds = [
        ('c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8', 0x144aa68b0, 0x1498d90a0, (0x141b04f00, 0x1456e3ea0, 0x1456da1a0)),
        ('98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e', 0x144aae4e0, 0x14992adf0, (0x141b0ac30, 0x1456e7cf0, 0x1456de090)),
    ]
    rows = []
    reviewed_bytes = bytes.fromhex('488b024c8bc2488bd1498bc848ff6020')
    for sha, address, table, expected_words in builds:
        source = root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
        raw = source.read_bytes()
        if hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError('Source snapshot changed')
        image = native.Image(raw)
        offset = image.offset(address - image.pe.base)
        code = raw[offset:offset + 16]
        if code != reviewed_bytes:
            raise ValueError('Unreviewed dispatch instructions')
        table_offset = image.offset(table - image.pe.base)
        words = struct.unpack_from('<QQQ', raw, table_offset)
        if words != expected_words:
            raise ValueError('Callback words changed')
        instructions = [dict(address=hex(i.address), mnemonic=i.mnemonic, operands=i.op_str)
                        for i in capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64).disasm(code, address)]
        cases = [replay(code, address, value, displacement)
                 for displacement in (0, 0x40, 0x100) for value in (0, 1, 0xdeadbeef)]
        rows.append(dict(source=str(source), source_sha256=sha, address=hex(address), file_offset=offset,
                         bytes=code.hex(), instructions=instructions, cases=cases,
                         observed_callback_table=hex(table), first_three_words=[hex(w) for w in words]))
    report = dict(schema=1, tool_sha256=audit.sha256(Path(__file__)),
                  native_tool_sha256=audit.sha256(HERE / 'build-native-entry-code.py'),
                  pe_tool_sha256=audit.sha256(HERE / 'extract-native-enums.py'),
                  requirements_sha256=audit.sha256(HERE / 'requirements-native.txt'),
                  ghidra_evidence_sha256=expected_evidence, capstone_version=capstone.__version__,
                  unicorn_version=unicorn.__version__, builds=rows, native_execution=True,
                  compatibility='not_established',
                  limits=['Only 16-byte nested-object virtual dispatch executes; virtual reader is an explicit return fixture.',
                          'Callback words checked against saved bytes; full table extent is not inferred.',
                          'No string decoding, whole list, allocation lifecycle, packet binding or live login is proven.'])
    target = audit.save_snapshot(comparison / 'nested-read-thunk-replay', report)
    print(json.dumps(dict(report=str(target), sha256=audit.sha256(target), cases=18), indent=2))


if __name__ == '__main__':
    main()
