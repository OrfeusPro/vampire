"""Whole native query-value loop for printable ASCII; real whitelist/hex.

Single-unit conversion and FString reserve/append are bounded fixtures.
Unicode conversion and whole map serializer are outside this replay.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('nid_encode_lifecycle', HERE / 'replay-device-key-lifecycle.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.guid.source.config.native, base.x
ENCODE = 0x141c13850


class Replay(base.Replay):
    def __init__(self, raw, image, source, fragments, primitives):
        super().__init__(raw, image, source, {})
        rows = [r for f in fragments for r in f['instructions']]
        self.allowed.update(r['address'] for r in rows)
        pages = {p & ~4095 for r in rows for p in (r['address'], *r['rip_references'])}
        cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
        cs.detail = True
        for body in primitives['bodies']:
            data = bytes.fromhex(body['bytes'])
            if raw[body['file_offset']:body['file_offset'] + len(data)] != data: raise ValueError('Escape leaf changed')
            for instruction in cs.disasm(data, body['address']):
                self.allowed.add(instruction.address)
                for op in instruction.operands:
                    if op.type == native.capstone.x86_const.X86_OP_MEM and op.mem.base == native.capstone.x86_const.X86_REG_RIP:
                        pages.add((instruction.address + instruction.size + op.mem.disp) & ~4095)
            pages.update(range(body['address'] & ~4095, (body['address'] + len(data) + 4095) & ~4095, 4096))
        for proof in primitives['data']:
            data = bytes.fromhex(proof['bytes'])
            if raw[proof['file_offset']:proof['file_offset'] + len(data)] != data: raise ValueError('Escape table changed')
            pages.add(proof['address'] & ~4095)
        self.encode_hooks = {0x141430bc0, 0x141440af0, 0x141424430, 0x1414242a0}
        pages.update(a & ~4095 for a in self.encode_hooks)
        for page in pages:
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            try: off = image.offset(page - image.pe.base)
            except ValueError: continue  # Explicit zeroed BSS for native whitelist initialization.
            self.uc.mem_write(page, raw[off:off + 4096])

    def hook(self, uc, address, size, user):
        if address in self.allowed: return
        if address not in self.encode_hooks: return super().hook(uc, address, size, user)
        a, b, c = [uc.reg_read(reg) for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        if address == 0x141430bc0:
            if b > 4096: raise ValueError('Reserve fixture bound')
        elif address == 0x141440af0:
            value = int.from_bytes(uc.mem_read(c, 2), 'little')
            if b != 4 or not 32 <= value <= 126: raise ValueError('ASCII conversion fixture scope')
            uc.mem_write(a, bytes([value, 0, 0, 0]))
        elif address == 0x141424430:
            if c > 3: raise ValueError('Escaped append fixture bound')
            self.string(a, self.text(a) + bytes(uc.mem_read(b, c * 2)).decode('utf-16le'))
        else:
            if not 32 <= b & 65535 <= 126: raise ValueError('Safe character fixture scope')
            self.string(a, self.text(a) + chr(b & 65535))
        uc.reg_write(x.UC_X86_REG_RAX, a)
        sp = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RIP, struct.unpack('<Q', bytes(uc.mem_read(sp, 8)))[0])
        uc.reg_write(x.UC_X86_REG_RSP, sp + 8)

    def encode(self, value):
        descriptor = self.base + 0x5000
        data = value.encode('utf-16le')
        pointer = self.allocate(max(len(data), 2))
        if data: self.uc.mem_write(pointer, data)
        self.uc.mem_write(descriptor, struct.pack('<QII', pointer, len(value), len(value)))
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        for reg, value in ((x.UC_X86_REG_RSP, self.stack), (x.UC_X86_REG_RCX, self.output),
                           (x.UC_X86_REG_RDX, descriptor)):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(ENCODE, self.stop, count=100000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop: raise ValueError('Encoder instruction budget')
        return self.text(self.output)


def build():
    path = native.ROOT / 'code-clues/headless-device-identity.json'
    source = json.loads(path.read_text('utf-8'))
    auth_path = native.ROOT / 'code-clues/headless-auth-index.json'
    auth = json.loads(auth_path.read_text('utf-8'))
    raw = Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256'] or auth['sha256'] != source['sha256']:
        raise ValueError('Query source changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(ENCODE)]})
    values = [chr(n) for n in range(32, 127)] + ['', 'a b+c&d=e%f/?#', ''.join(chr(n) for n in range(32, 127)), '0123456789ABCDEF']
    cases = []
    for value in values:
        em = Replay(raw, image, source, fragments, auth['escape_primitives'])
        cases.append(dict(value=value, encoded=em.encode(value)))
    return dict(source=source['source'], sha256=source['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256=hashlib.sha256((HERE / 'replay-device-key-lifecycle.py').read_bytes()).hexdigest(),
                auth_evidence_sha256=hashlib.sha256(auth_path.read_bytes()).hexdigest(),
                fragments=fragments, primitives=auth['escape_primitives'], cases=cases,
                native_execution=True, network_ready=False,
                limitations=['Whole value loop and native whitelist/hex; ASCII conversion, reserve/append fixtures.',
                             'No Unicode conversion, whole map serialization, HTTP or browser.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/nid-query-encode-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
