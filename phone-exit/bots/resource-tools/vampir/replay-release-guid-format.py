"""Current native GUID mode-0 formatter and hex writer on synthetic words."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
FORMAT, HEX = 0x14154eb20, 0x1415b30d0


def main():
    spec = importlib.util.spec_from_file_location('guid_release_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    hooks = {0x1487eac40: None}
    h = archive.make_harness(extra_addresses=(HEX,), fixtures=hooks)
    evidence = h.comparison / 'details/run-1fe12e787a88/details.json'
    hex_evidence = h.comparison / 'details/run-765554611ab2/details.json'
    if h.audit.sha256(evidence) != '3bcf0b7a1265fee453fbc7be4f641046f47e379fbf9615bdfc174dc562ccb25d' or h.audit.sha256(hex_evidence) != '31bc1d2e366b30de909b740493e30d974154b161019b376a782d1515a909e9ae':
        raise ValueError('Current GUID Ghidra evidence changed')
    function = next(f for f in json.loads(evidence.read_text())['functions'] if int(f['address'], 16) == FORMAT)
    decoder = h.native.capstone.Cs(h.native.capstone.CS_ARCH_X86, h.native.capstone.CS_MODE_64)
    decoder.detail = True
    pages = set()
    for row in function['instructions']:
        at, data = int(row['address'], 16), bytes.fromhex(row['bytes'])
        offset = h.image.offset(at - h.image.pe.base)
        if h.raw[offset:offset+len(data)] != data: raise ValueError('GUID instruction source differs')
        h.ranges.append((at, at + len(data)))
        pages.update(range(at & ~4095, (at + len(data) + 4095) & ~4095, 4096))
        for instruction in decoder.disasm(data, at):
            for operand in instruction.operands:
                if operand.type == h.native.X86_OP_MEM and operand.mem.base == h.native.X86_REG_RIP:
                    pages.add((at + len(data) + operand.mem.disp) & ~4095)
    for page in sorted(pages):
        if not any(lo <= page <= hi for lo, hi, _ in h.uc.mem_regions()):
            h.uc.mem_map(page, 4096)
            try:
                offset = h.image.offset(page - h.image.pe.base)
                h.uc.mem_write(page, h.raw[offset:offset+4096])
            except ValueError: pass
    cookie_calls = []
    def cookie(machine):
        value = machine.reg_read(h.x.UC_X86_REG_RCX)
        if value != int.from_bytes(machine.mem_read(0x14b274780, 8), 'little'):
            raise ValueError('GUID cookie mismatch')
        cookie_calls.append(True)
        sp = machine.reg_read(h.x.UC_X86_REG_RSP)
        machine.reg_write(h.x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(h.x.UC_X86_REG_RSP, sp + 8)
    hooks[0x1487eac40] = cookie
    guid, descriptor, text = [h.scratch + n for n in (0x10000, 0x11000, 0x12000)]
    cases = []
    for words in ((0, 0, 0, 0), (0xffffffff,) * 4,
                  (0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210),
                  (1, 0x100, 0x10000, 0x1000000)):
        h.uc.mem_write(guid, struct.pack('<IIII', *words))
        h.uc.mem_write(descriptor, struct.pack('<QII', text, 0, 64))
        h.uc.mem_write(text, b'\xa5' * 160)
        h.call(FORMAT, guid, descriptor, 0, budget=8192)
        pointer, count, capacity = struct.unpack('<QII', bytes(h.uc.mem_read(descriptor, 16)))
        value = bytes(h.uc.mem_read(text, 66)).decode('utf-16le')
        expected = ''.join(f'{word:08X}' for word in words)
        if (pointer, count, capacity, value) != (text, 33, 64, expected + '\0'):
            raise ValueError('Current native GUID format differs')
        if bytes(h.uc.mem_read(text+66, 94)) != b'\xa5' * 94: raise ValueError('GUID output overflow')
        cases.append(dict(words=words, formatted=value[:-1], count=count))
    if len(cookie_calls) != len(cases): raise ValueError('GUID return not verified')
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        evidence_sha256=h.audit.sha256(evidence), hex_evidence_sha256=h.audit.sha256(hex_evidence),
        formatter_instructions=function['instructions'], fragments=h.fragments, cases=cases,
        network_used=False, user_identity_read=False,
        limits=['Whole current formatter executes only mode 0, with actual native hex writer.',
            'Preallocated FString capacity and cookie backend are fixtures; allocation path is not exercised.',
            'Synthetic words only; no CoCreateGuid, settings storage, SDK lifecycle or game Login executed.'])
    path = h.audit.save_snapshot(h.comparison / 'guid-format-replay', report)
    print(json.dumps(dict(report=str(path), sha256=h.audit.sha256(path), cases=len(cases))))


if __name__ == '__main__': main()
