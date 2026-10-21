"""New-release native input archive constructor and scalar reads, bounded memcpy fixture."""
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


def main():
    env = load('archive_release_env', HERE / 'replay-release-nested-read-thunk.py')
    native = load('archive_release_native', HERE / 'build-native-entry-code.py')
    audit = load('archive_release_audit', HERE / 'audit-client-release.py')
    imports = load('archive_release_imports', HERE / 'build-object-zero-init-code.py')
    sha = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
    source = native.ROOT / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('New source changed')
    comparison = native.ROOT / 'ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c'
    evidence = comparison / 'details/run-ecc4c9718f83/details.json'
    evidence_sha = 'c2e050e62bd50d5bfe0fc5a97bd0047fc3b9d8be223cea79dde03f1747fb4f11'
    if audit.sha256(evidence) != evidence_sha:
        raise ValueError('Ghidra inspection changed')
    if env.capstone.__version__ != '5.0.6' or env.unicorn.__version__ != '2.1.4':
        raise ValueError('Pinned tools required')
    image = native.Image(raw)
    ctor, table, copy = 0x144aad4e0, 0x1496726a8, 0x1487f7a19
    readers = {'u8': (0x144aad590, 1), 'u16': (0x144aad5a0, 2),
               'u32': (0x144aad5f0, 4), 'u64': (0x144aad7f0, 8), 'bool': (0x144aad840, 1)}
    addresses = [ctor, 0x144aad910, *[a for a, size in readers.values() if a != 0x144aad590]]
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in addresses})
    ranges = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']) for f in fragments]
    leaves = []
    for address in (0x144aae160, 0x144aae4f0, 0x144aad590):
        offset = image.offset(address - image.pe.base)
        instructions = []
        for ins in env.capstone.Cs(env.capstone.CS_ARCH_X86, env.capstone.CS_MODE_64).disasm(raw[offset:offset + 96], address):
            instructions.append(ins)
            if ins.mnemonic in ('ret', 'jmp'):
                break
            if ins.mnemonic not in ('mov', 'lea', 'xor'):
                raise ValueError('Unreviewed archive leaf')
        if not instructions or instructions[-1].mnemonic not in ('ret', 'jmp'):
            raise ValueError('Archive leaf bound')
        length = instructions[-1].address + instructions[-1].size - address
        ranges.append((address, address + length))
        leaves.append(dict(address=hex(address), file_offset=offset, bytes=raw[offset:offset + length].hex()))
    offset = image.offset(copy - image.pe.base)
    if raw[offset:offset + 2] != b'\xff\x25':
        raise ValueError('Copy import thunk changed')
    target = copy + 6 + struct.unpack_from('<i', raw, offset + 2)[0]
    copy_import = imports.import_at(raw, image, target)
    if (copy_import['dll'].lower(), copy_import['name']) != ('vcruntime140.dll', 'memcpy'):
        raise ValueError('Unverified copy import')
    uc, x = env.unicorn.Uc(env.unicorn.UC_ARCH_X86, env.unicorn.UC_MODE_64), env.x
    pages = {p for a, b in ranges for p in range(a & ~4095, (b + 4095) & ~4095, 4096)}
    pages.update((table & ~4095, copy & ~4095))
    for page in sorted(pages):
        uc.mem_map(page, 4096)
        offset = image.offset(page - image.pe.base)
        uc.mem_write(page, raw[offset:offset + 4096])
    scratch = 0x20000000
    uc.mem_map(scratch, 0x10000)
    obj, buffer, output, stack, stop = [scratch + n for n in (0x1000, 0x3000, 0x5000, 0x8000, 0xf000)]
    def hook(machine, address, size, unused):
        if address == copy:
            a, b, count = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
            if count > 64 or not all(scratch <= p <= scratch + 0x10000 - count for p in (a, b)):
                raise ValueError('Copy fixture bound')
            if count:
                machine.mem_write(a, bytes(machine.mem_read(b, count)))
            sp = machine.reg_read(x.UC_X86_REG_RSP)
            machine.reg_write(x.UC_X86_REG_RAX, a)
            machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
            machine.reg_write(x.UC_X86_REG_RSP, sp + 8)
        elif not any(a <= address and address + size <= b for a, b in ranges):
            raise ValueError('Unreviewed archive execution ' + hex(address))
    uc.hook_add(env.unicorn.UC_HOOK_CODE, hook)
    def call(address, a, b=0):
        uc.mem_write(stack, struct.pack('<Q', stop))
        for reg, value in ((x.UC_X86_REG_RCX, a), (x.UC_X86_REG_RDX, b), (x.UC_X86_REG_RSP, stack)):
            uc.reg_write(reg, value)
        uc.emu_start(address, stop, count=2048)
        if uc.reg_read(x.UC_X86_REG_RIP) != stop:
            raise ValueError('Archive instruction budget')
        return uc.reg_read(x.UC_X86_REG_RAX)
    cases = []
    for kind, (reader, width) in readers.items():
        for value in (0, 1, (1 << (width * 8)) - 1):
            payload = value.to_bytes(width, 'little')
            for size in range(width + 1):
                uc.mem_write(obj, b'\xa5' * 0x80)
                if call(ctor, obj) != obj or int.from_bytes(uc.mem_read(obj, 8), 'little') != table:
                    raise ValueError('Archive constructor binding')
                uc.mem_write(buffer, b'\0' * 64)
                uc.mem_write(buffer, payload[:size])
                uc.mem_write(output, b'\xcc' * 16)
                # Explicit buffer fixture after actual default construction; no buffer-ctor claim.
                uc.mem_write(obj + 0x20, struct.pack('<QI', buffer, size))
                uc.mem_write(obj + 0x30, struct.pack('<Q', buffer))
                accepted = call(reader, obj, output) & 255
                consumed = int.from_bytes(uc.mem_read(obj + 0x30, 8), 'little') - buffer
                expected = int(bool(value)) if kind == 'bool' else value
                decoded = int.from_bytes(uc.mem_read(output, width), 'little')
                if accepted != int(size == width) or consumed != size or (accepted and decoded != expected):
                    raise ValueError('Archive read / truncation differs')
                cases.append(dict(kind=kind, input=value, available=size, accepted=accepted,
                                  consumed=consumed, decoded_if_accepted=decoded if accepted else None))
    report = dict(schema=1, source=str(source), source_sha256=sha,
                  tool_sha256=audit.sha256(Path(__file__)), ghidra_evidence_sha256=evidence_sha,
                  dependencies={p: audit.sha256(HERE / p) for p in ('build-native-entry-code.py',
                                'extract-native-enums.py', 'build-object-zero-init-code.py', 'requirements-native.txt')},
                  capstone_version=env.capstone.__version__, unicorn_version=env.unicorn.__version__,
                  constructor=hex(ctor), actual_vptr=hex(table), copy_import=copy_import,
                  fragments=fragments, leaves=leaves, cases=cases, native_execution=True,
                  compatibility='not_established',
                  limits=['Actual default input archive constructor and scalar/raw readers execute, little-endian only.',
                          'Input buffer fields are explicit fixtures; memcpy is bounded fixture for verified CRT import.',
                          'No FString/UTF-8, array callback, whole list, network dispatch, packet IDs or live session.'])
    target = audit.save_snapshot(comparison / 'archive-input-replay', report)
    print(json.dumps(dict(report=str(target), sha256=audit.sha256(target), cases=len(cases)), indent=2))


if __name__ == '__main__':
    main()
