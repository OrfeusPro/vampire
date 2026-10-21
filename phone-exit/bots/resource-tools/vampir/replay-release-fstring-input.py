"""Execute new-release FString/UTF-8 input with explicit bounded storage fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def main():
    spec = importlib.util.spec_from_file_location('new_archive_harness', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    audit = archive.load('fstring_audit', HERE / 'audit-client-release.py')
    native = archive.load('fstring_source', HERE / 'build-native-entry-code.py')
    ghidra = native.ROOT / 'ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/run-c49c5bae9fe5/details.json'
    ghidra_sha = 'dd47cf6861dc3872ee93f05d9bcd08849f0a144bcb8c15a7f92c49370790038a'
    if audit.sha256(ghidra) != ghidra_sha:
        raise ValueError('Reviewed UTF8 Ghidra evidence changed')
    fixtures = {}
    h = archive.make_harness(extra_addresses=(0x144aae320, 0x144aad6e0, 0x14144c520,
        0x141446780, 0x14143be10, 0x14143ba80), extra_leaves=(0x141432060,), fixtures=fixtures)
    uc, x = h.uc, h.x
    # Add fixture pages after assigning handlers, before emulation.
    fixture_addresses = (0x141427890, 0x141436da0, 0x1421e7580, 0x141483160, 0x1487eac40)
    for a in fixture_addresses:
        for page in (a & ~4095, (a & ~4095) + 4096):
            if any(lo <= page <= hi for lo, hi, permissions in uc.mem_regions()):
                continue
            uc.mem_map(page, 4096)
            offset = h.image.offset(page - h.image.pe.base)
            uc.mem_write(page, h.raw[offset:offset + 4096])
    heap = [h.scratch + 0x20000]
    def allocate(size):
        if not 0 <= size <= 8192 or heap[0] + size > h.scratch + 0x2e000:
            raise ValueError('String storage fixture bound')
        pointer = heap[0]
        heap[0] += (max(size, 1) + 15) & ~15
        uc.mem_write(pointer, b'\0' * max(size, 1))
        return pointer
    def finish(result=None):
        if result is not None:
            uc.reg_write(x.UC_X86_REG_RAX, result)
        sp = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(sp, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
    def storage(machine):
        current = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c, d = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        if current == 0x141427890:
            data = bytearray()
            if b:
                for index in range(2048):
                    pair = bytes(machine.mem_read(b + index * 2, 2))
                    if pair == b'\0\0':
                        break
                    data.extend(pair)
                else:
                    raise ValueError('FString assignment fixture bound')
            pointer = allocate(len(data) + 2) if data else 0
            if data:
                machine.mem_write(pointer, bytes(data) + b'\0\0')
            units = len(data) // 2 + 1 if data else 0
            machine.mem_write(a, struct.pack('<QII', pointer, units, units))
            finish(a)
        elif current == 0x141436da0:
            if b or d != 2:
                raise ValueError('UTF16 scratch allocation contract changed')
            machine.mem_write(a, struct.pack('<Q', allocate(c * 2)))
            finish()
        elif current == 0x1421e7580:
            length, capacity = struct.unpack('<QQ', bytes(machine.mem_read(a + 16, 16)))
            if b != 1 or length > 2048:
                raise ValueError('Stdstring growth fixture bound')
            old = int.from_bytes(machine.mem_read(a, 8), 'little') if capacity > 15 else a
            data = bytes(machine.mem_read(old, length)) if length else b''
            capacity = max(32, (length + 2) * 2) - 1
            pointer = allocate(capacity + 1)
            machine.mem_write(pointer, data + bytes((d & 255, 0)))
            machine.mem_write(a, struct.pack('<QQQQ', pointer, 0, length + 1, capacity))
            finish(a)
        else:
            finish()  # Explicit free / stack-cookie fixtures, preserving RAX.
    for address in fixture_addresses:
        fixtures[address] = storage
    cases, short = [], []
    texts = ('', 'ASCII', 'Ж界🙂', 'é' * 16, 'a' * 129, '界' * 130)
    for text in texts:
        encoded = text.encode('utf-8')
        body = struct.pack('<H', len(encoded)) + encoded
        for size in range(len(body) + 1):
            heap[0] = h.scratch + 0x20000
            uc.mem_write(h.obj, bytes(0x80))
            uc.mem_write(h.output, bytes(32))
            uc.mem_write(h.buffer, bytes(4096))
            uc.mem_write(h.buffer, body[:size])
            h.call(h.ctor, h.obj)
            uc.mem_write(h.obj + 0x20, struct.pack('<QI', h.buffer, size))
            uc.mem_write(h.obj + 0x30, struct.pack('<Q', h.buffer))
            try:
                accepted = h.call(0x144aae320, h.obj, h.output, budget=250000) & 255
            except h.env.unicorn.UcError as error:
                raise ValueError('String emulator memory fault at ' + hex(uc.reg_read(x.UC_X86_REG_RIP))) from error
            consumed = int.from_bytes(uc.mem_read(h.obj + 0x30, 8), 'little') - h.buffer
            pointer, units, capacity = struct.unpack('<QII', bytes(uc.mem_read(h.output, 16)))
            if not 0 <= units <= capacity <= 2048:
                raise ValueError('FString result bound')
            decoded = bytes(uc.mem_read(pointer, (units - 1) * 2)).decode('utf-16le') if units else ''
            if size == len(body):
                if accepted != 1 or consumed != len(body) or decoded != text:
                    raise ValueError('Native FString decode differs')
                cases.append(dict(utf8_bytes=len(encoded), utf16_units=len(text.encode('utf-16le')) // 2,
                                  accepted=accepted, consumed=consumed, text_matches=True))
            else:
                if accepted != 0 or consumed != size or decoded:
                    raise ValueError('Truncated FString unexpectedly accepted')
                short.append(dict(complete_body_bytes=len(body), available=size, consumed=consumed, accepted=accepted))
    report = dict(schema=1, source=str(h.source), source_sha256=h.sha,
                  tool_sha256=h.audit.sha256(Path(__file__)),
                  ghidra_evidence_sha256=ghidra_sha,
                  harness_sha256=h.audit.sha256(HERE / 'replay-release-archive-input.py'),
                  capstone_version=h.env.capstone.__version__, unicorn_version=h.env.unicorn.__version__,
                  fragments=h.fragments, leaves=h.leaves, cases=cases, truncated=short,
                  fixture_addresses=[hex(a) for a in fixture_addresses], native_execution=True,
                  compatibility='not_established',
                  limits=['Actual FString/stdstring/UTF-8 decoder and archive byte IO execute.',
                          'FString assignment, stdstring growth, UTF16 allocation, free, cookie and verified memcpy are bounded fixtures.',
                          'Valid strings without embedded NUL only; malformed UTF-8 and whole list not proven.'])
    target = h.audit.save_snapshot(h.comparison / 'fstring-input-replay', report)
    print(json.dumps(dict(report=str(target), sha256=h.audit.sha256(target), cases=len(cases), truncated=len(short)), indent=2))


if __name__ == '__main__':
    main()
