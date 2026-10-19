"""Execute native UTF-16-unit XOR and actual FString single-unit append."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('gmc2_xor_values', HERE / 'build-headless-sdk-bootstrap-values.py')
values = importlib.util.module_from_spec(spec)
spec.loader.exec_module(values)
XOR, APPEND, GROW = 0x1444ddf50, 0x1414242a0, 0x141431e70


class Emulator(values.Emulator):
    def __init__(self, raw, image, fragments):
        super().__init__(raw, image, fragments)
        roots = {image.roots[image.containing(a)][0] for a in (XOR, APPEND)}
        extra = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva'])
                 for f in fragments if f['root_begin_rva'] in roots]
        self.allowed.extend(extra)
        pages = {a & ~4095 for lo, hi in extra for a in range(lo, hi + 4095, 4096)}
        pages.add(GROW & ~4095)
        for f in fragments:
            if f['root_begin_rva'] in roots:
                pages.update(a & ~4095 for row in f['instructions'] for a in row['rip_references'])
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page, 4096)
            try:
                off = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[off:off + 4096])
        # Explicit logging-disabled fixture; diagnostic branch is not executed.
        rows = {r['address']: r for f in fragments for r in f['instructions']}
        targets = rows[0x1444ddf61]['rip_references']
        if targets != [0x14b4f2060]:
            raise ValueError('XOR diagnostic flag reference changed')
        self.uc.mem_write(targets[0], b'\0')

    def hook(self, machine, address, size, user):
        if address != GROW:
            return super().hook(machine, address, size, user)
        x = self.x
        destination = machine.reg_read(x.UC_X86_REG_RCX)
        pointer, count, capacity = struct.unpack('<QII', bytes(machine.mem_read(destination, 16)))
        if destination != self.scratch + 0x1000 or not 1 <= count <= 2048 or capacity > count:
            raise ValueError('XOR output allocation fixture exceeded')
        # Native append has already updated count, while capacity still describes old storage.
        old = bytes(machine.mem_read(pointer, capacity * 2)) if capacity else b''
        new_capacity = min(2048, max(count, capacity * 2, 8))
        new_pointer = self.scratch + 0x20000
        machine.mem_write(new_pointer, old)
        machine.mem_write(destination, struct.pack('<Q', new_pointer))
        machine.mem_write(destination + 12, struct.pack('<I', new_capacity))
        self.events.append(dict(kind='FString_growth_shim', capacity=new_capacity))
        rsp = machine.reg_read(x.UC_X86_REG_RSP)
        ret = struct.unpack('<Q', bytes(machine.mem_read(rsp, 8)))[0]
        machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(x.UC_X86_REG_RIP, ret)

    def decode(self, source, key):
        if len(source) > 1024 or not 1 <= len(key) <= 128 or any(not 0 <= v <= 65535 for v in source + key):
            raise ValueError('XOR native fixture budget exceeded')
        destination, source_desc, key_desc = [self.scratch + o for o in (0x1000, 0x2000, 0x3000)]
        self.uc.mem_write(source_desc, struct.pack('<QII', self.scratch + 0x5000, len(source), len(source)))
        if source:
            self.uc.mem_write(self.scratch + 0x5000, struct.pack('<' + 'H' * len(source), *source))
        self.uc.mem_write(key_desc, struct.pack('<QII', self.scratch + 0x8000, len(key) + 1, len(key) + 1))
        self.uc.mem_write(self.scratch + 0x8000, struct.pack('<' + 'H' * (len(key) + 1), *key, 0))
        self.uc.mem_write(destination - 8, b'\xa5' * 32)
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        for reg, value in ((self.x.UC_X86_REG_RSP, self.stack), (self.x.UC_X86_REG_RDX, destination),
                           (self.x.UC_X86_REG_R8, source_desc), (self.x.UC_X86_REG_R9, key_desc)):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(XOR, self.stop, count=131072)
        if self.uc.reg_read(self.x.UC_X86_REG_RIP) != self.stop:
            raise ValueError('XOR instruction budget exceeded')
        pointer, count, capacity = struct.unpack('<QII', bytes(self.uc.mem_read(destination, 16)))
        output = list(struct.unpack('<' + 'H' * (count - 1), bytes(self.uc.mem_read(pointer, (count - 1) * 2)))) if count else []
        terminated = not count or bytes(self.uc.mem_read(pointer + (count - 1) * 2, 2)) == b'\0\0'
        guards = bytes(self.uc.mem_read(destination - 8, 8)) + bytes(self.uc.mem_read(destination + 16, 8))
        if guards != b'\xa5' * 16 or not terminated:
            raise ValueError('XOR native output guards/termination changed')
        return dict(source_units=source, key_units=key, output_units=output,
                    guards_unchanged=True, output_terminated=terminated, calls=self.events)


def build():
    prior_path = values.native.ROOT / 'code-clues/headless-sdk-config.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('GMC2 XOR source changed')
    image = values.native.Image(raw)
    fragments = values.native.decode_ranges(image, {image.roots[image.containing(a)] for a in (XOR, APPEND, 0x1444f0e80)})
    fixtures = [([], [1]), ([0], [0]), ([1], [1]), ([1, 0, 1, 0], [1]),
                ([0xffff, 0xd800, 0xdc00, 0], [0x1234, 0, 0xffff]),
                (list(range(256)), [0x41, 0x42, 0x43]),
                ([0x41] * 1024, [0x42]), ([0x41] * 1024, [0x41])]
    fixtures += [([i, i ^ 0xffff, 0, i], [i, 0, 0x1234]) for i in (0, 1, 127, 128, 255, 256, 0x7fff, 0x8000, 0xd800, 0xffff)]
    cases = [Emulator(raw, image, fragments).decode(source, key) for source, key in fixtures]
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), fragments=fragments,
        cases=cases, logging_disabled_fixture=True, logging_fixture_address=0x14b4f2060,
        network_ready=False,
        limitations=['Full XOR helper and actual UTF-16 single-unit append executed; output growth is a bounded shim.',
            'Explicit source-unit array and NUL-terminated key FString fixtures; no Base64/JSON/DECKEY acquisition.',
            'Zero XOR results are ignored by native append; nonzero UTF-16 units are retained without Unicode validation.',
            'Empty key with nonempty source would divide by zero; common API rejects empty key locally.'])


if __name__ == '__main__':
    report = build()
    target = values.native.ROOT / 'code-clues/headless-gmc2-xor.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(), cases=len(report['cases'])), indent=2))
