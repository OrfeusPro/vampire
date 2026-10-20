"""Execute result-code -> text-key mapper, tracing only reached instructions."""
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('result_text_ping', HERE / 'build-headless-ping-codec.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, unicorn, x = base.native, base.unicorn, base.x
ENTRY, CONSTRUCT = 0x1458091b0, 0x141420f70


class Replay:
    def __init__(self, raw, image):
        self.raw, self.image = raw, image
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        root = image.roots[image.containing(ENTRY)]
        self.ranges, self.pages, self.trace, self.literals = [], set(), {}, []
        for begin, end, unwind in image.ranges:
            if image.roots[(begin, end, unwind)] != root: continue
            offset = image.offset(begin)
            data = raw[offset:offset + end - begin]
            self.ranges.append(dict(begin=image.pe.base + begin, end=image.pe.base + end,
                file_offset=offset, sha256=hashlib.sha256(data).hexdigest()))
            for page in range((image.pe.base + begin) & ~4095, (image.pe.base + end + 4095) & ~4095, 4096):
                self.map_page(page)
        self.uc.mem_map(CONSTRUCT & ~4095, 4096)
        self.uc.mem_write(CONSTRUCT, b'\xc3')
        self.uc.mem_map(0x20000000, 0x20000)
        self.stack, self.stop, self.descriptor = 0x20010000, 0x2001f000, 0x20001000
        self.cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.hook)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED, self.unmapped)

    def map_page(self, page):
        if page in self.pages: return
        if len(self.pages) >= 64: raise ValueError('Source page budget')
        offset = self.image.offset(page - self.image.pe.base)
        self.uc.mem_map(page, 4096)
        self.uc.mem_write(page, self.raw[offset:offset + 4096])
        self.pages.add(page)

    def unmapped(self, uc, access, address, size, value, user):
        self.map_page(address & ~4095)
        return True

    def hook(self, uc, address, size, user):
        if address == CONSTRUCT:
            desc, pointer = (uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX))
            offset = self.image.offset(pointer - self.image.pe.base)
            end = self.raw.index(b'\0', offset, offset + 256)
            data = self.raw[offset:end + 1]
            text = data[:-1].decode('ascii')
            self.literals.append(dict(address=pointer, file_offset=offset, bytes=data.hex(),
                sha256=hashlib.sha256(data).hexdigest(), text=text))
            encoded = (text + '\0').encode('utf-16le')
            uc.mem_write(0x20002000, encoded)
            uc.mem_write(desc, struct.pack('<QII', 0x20002000, len(encoded) // 2, len(encoded) // 2))
            rsp = uc.reg_read(x.UC_X86_REG_RSP)
            target = int.from_bytes(uc.mem_read(rsp, 8), 'little')
            uc.reg_write(x.UC_X86_REG_RAX, desc)
            uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(x.UC_X86_REG_RIP, target)
            return
        if not any(r['begin'] <= address < r['end'] for r in self.ranges):
            raise ValueError('Unexpected mapper execution address ' + hex(address))
        data = bytes(uc.mem_read(address, size))
        rows = list(self.cs.disasm(data, address))
        if len(rows) != 1 or rows[0].size != size: raise ValueError('Reached instruction decode failed')
        row = rows[0]
        self.trace[address] = dict(address=address, file_offset=self.image.offset(address - self.image.pe.base),
            bytes=data.hex(), mnemonic=row.mnemonic, operands=row.op_str)

    def execute(self, code):
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        for reg, value in ((x.UC_X86_REG_RSP, self.stack), (x.UC_X86_REG_RCX, self.descriptor), (x.UC_X86_REG_RDX, code)):
            self.uc.reg_write(reg, value)
        try: self.uc.emu_start(ENTRY, self.stop, count=4096)
        except unicorn.UcError as error:
            raise ValueError('Mapper code ' + str(code) + ' stopped at ' + hex(self.uc.reg_read(x.UC_X86_REG_RIP))) from error
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop or len(self.literals) != 1:
            raise ValueError('Mapper did not return one bounded key')
        return dict(code=code, key=self.literals[0]['text'], literal=self.literals[0],
            ranges=self.ranges, trace=list(self.trace.values()))


def build():
    manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
    raw = Path(manifest['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest['source_sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    cases = [Replay(raw, image).execute(code) for code in (0, 1, 42, 54, 57, 58, 59)]
    key = next(c['key'] for c in cases if c['code'] == 58)
    if key != 'BlockedIp': raise ValueError('Verified code 58 key changed')
    index_path = native.ROOT / 'table-study/index.json'
    table = next(t for t in json.loads(index_path.read_text('utf-8'))['tables'] if t['file'] == 'ProjectRED-Windows-6106.csv')
    path = index_path.parent / table['file']
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != table['sha256']: raise ValueError('Extracted error table changed')
    rows = list(csv.DictReader(io.StringIO(data.decode('utf-8-sig'))))
    found = [(i + 1, r) for i, r in enumerate(rows) if r['Key'] == key]
    if len(found) != 1: raise ValueError('Error localization key is not unique')
    return dict(source=manifest['source'], source_sha256=manifest['source_sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        cases=cases, localization=dict(path=str(path), sha256=table['sha256'],
            index_sha256=hashlib.sha256(index_path.read_bytes()).hexdigest(), provenance=table,
            data_row=found[0][0], row=found[0][1]),
        limitations=['Actual complete mapper entry/return for seven codes; FString constructor is a bounded fixture.',
            'Only reached instructions decoded; inline switch data not treated as linear code.',
            'Source pages loaded on demand under a 64-page budget; no game/process/network.',
            'Static localization join by verified key; popup table override and rendering not executed.',
            'BlockedIp labels the server refusal, not its policy, geography, cause or remedy.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/result-error-text-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        keys={c['code']: c['key'] for c in report['cases']})))
