"""Execute record constructors and verify installed vptr -> reader, not whole list IO."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def execute(raw, image, ctor, leaves, additional_functions, fill, displacement):
    env = load('record_thunk_env', HERE / 'replay-release-nested-read-thunk.py')
    native = load('record_native', HERE / 'build-native-entry-code.py')
    uc, x = env.unicorn.Uc(env.unicorn.UC_ARCH_X86, env.unicorn.UC_MODE_64), env.x
    if env.capstone.__version__ != '5.0.6' or env.unicorn.__version__ != '2.1.4':
        raise ValueError('Use pinned native tools')
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in (ctor, *additional_functions)})
    ranges = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']) for f in fragments]
    leaf_records = []
    for address in leaves:
        offset = image.offset(address - image.pe.base)
        instructions = []
        for ins in env.capstone.Cs(env.capstone.CS_ARCH_X86, env.capstone.CS_MODE_64).disasm(raw[offset:offset + 128], address):
            instructions.append(ins)
            if ins.mnemonic == 'ret':
                break
            if ins.mnemonic not in ('mov', 'lea', 'xor'):
                raise ValueError('Unreviewed nested constructor leaf')
        if not instructions or instructions[-1].mnemonic != 'ret':
            raise ValueError('Constructor leaf not bounded')
        size = instructions[-1].address + instructions[-1].size - address
        ranges.append((address, address + size))
        leaf_records.append(dict(address=hex(address), file_offset=offset, bytes=raw[offset:offset + size].hex()))
    pages = {p for a, b in ranges for p in range(a & ~4095, (b + 4095) & ~4095, 4096)}
    for page in sorted(pages):
        uc.mem_map(page, 4096)
        offset = image.offset(page - image.pe.base)
        uc.mem_write(page, raw[offset:offset + 4096])
    uc.mem_map(0x100000, 4096)
    uc.mem_map(0x200000, 4096)
    obj, stack, stop = 0x100100 + displacement, 0x200800, 0x200f00
    uc.mem_write(obj - 16, bytes([0xa5]) * 16 + bytes([fill]) * 0x170 + bytes([0xa5]) * 16)
    uc.mem_write(stack, struct.pack('<Q', stop))
    visited = set()
    def hook(machine, address, size, unused):
        if not any(a <= address and address + size <= b for a, b in ranges):
            raise ValueError('Constructor left reviewed code')
        visited.add(address)
    uc.hook_add(env.unicorn.UC_HOOK_CODE, hook)
    uc.reg_write(x.UC_X86_REG_RCX, obj)
    uc.reg_write(x.UC_X86_REG_RSP, stack)
    uc.emu_start(ctor, stop, count=2000)
    if uc.reg_read(x.UC_X86_REG_RIP) != stop or uc.reg_read(x.UC_X86_REG_RAX) != obj:
        raise ValueError('Constructor return mismatch')
    if bytes(uc.mem_read(obj - 16, 16)) != b'\xa5' * 16 or bytes(uc.mem_read(obj + 0x170, 16)) != b'\xa5' * 16:
        raise ValueError('Constructor wrote outside object')
    body = bytes(uc.mem_read(obj, 0x170))
    vptr = struct.unpack_from('<Q', body)[0]
    table_offset = image.offset(vptr - image.pe.base)
    return dict(fill=fill, displacement=displacement, vptr=hex(vptr),
                reader_slot20=hex(struct.unpack_from('<Q', raw, table_offset + 0x20)[0]),
                object_bytes=body.hex(), unique_instructions_executed=len(visited),
                canaries_intact=True, leaf_code=leaf_records)


def main():
    native = load('record_binding_native', HERE / 'build-native-entry-code.py')
    audit = load('record_binding_audit', HERE / 'audit-client-release.py')
    comparison = native.ROOT / 'ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c'
    evidence = comparison / 'details/run-cb6f5eff23f7/details.json'
    expected = '778cc016dd5b5744ef539045add4502342b263f7c7dac37ebf2947c7e1226d78'
    if audit.sha256(evidence) != expected:
        raise ValueError('Ghidra evidence changed')
    builds = [
        ('c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8', 0x14577d3d0, (0x1457eca60, 0x145789700), (), 0x1498d7ff8, 0x145781c80),
        ('98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e', 0x145784b10, (0x1457fedc0, 0x1457917a0), (0x1457a47d0,), 0x14992a420, 0x1457897d0),
    ]
    rows = []
    for sha, ctor, leaves, additional_functions, table, reader in builds:
        source = native.ROOT / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
        raw = source.read_bytes()
        if hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError('Saved source changed')
        image = native.Image(raw)
        cases = [execute(raw, image, ctor, leaves, additional_functions, fill, displacement)
                 for fill in (0, 0x5a, 0xff) for displacement in (0, 0x100)]
        if any(c['vptr'] != hex(table) or c['reader_slot20'] != hex(reader) for c in cases):
            raise ValueError('Record reader binding differs')
        fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in (ctor, *additional_functions)})
        rows.append(dict(source=str(source), source_sha256=sha, constructor=hex(ctor), fragments=fragments, cases=cases))
    report = dict(schema=1, tool_sha256=audit.sha256(Path(__file__)),
                  native_tool_sha256=audit.sha256(HERE / 'build-native-entry-code.py'),
                  environment_tool_sha256=audit.sha256(HERE / 'replay-release-nested-read-thunk.py'),
                  ghidra_evidence_sha256=expected, builds=rows, native_execution=True,
                  compatibility='not_established',
                  limits=['Actual record and nested leaf constructors execute; object vptr and file-backed reader slot checked.',
                          'Reader slot target is not executed; no whole list, archive IO, allocation lifetime or live session.'])
    target = audit.save_snapshot(comparison / 'record-binding-replay', report)
    print(json.dumps(dict(report=str(target), sha256=audit.sha256(target), cases=12), indent=2))


if __name__ == '__main__':
    main()
