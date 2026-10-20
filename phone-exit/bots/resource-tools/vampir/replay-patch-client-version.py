"""Execute the reviewed JSON key-to-field slice; JSON accessor is a fixture."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('patch_key_platform', HERE / 'replay-version-platform-context.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.x
START, STOP, ACCESSOR = 0x144a98eb1, 0x144a98f24, 0x1415e5ae0


class Replay(base.Replay):
    def __init__(self, raw, image, source, prior, fragments, value):
        super().__init__(raw, image, source, fragments, prior['members'], False)
        self.allowed = {r['address'] for f in fragments for r in f['instructions'] if START <= r['address'] < STOP}
        self.patch, self.json_object = self.allocate(0x300), self.allocate(0x80)
        self.string(self.patch + 0x1b0, 'old-version-fixture')
        self.value, self.keys = value, []
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        for reg, value in ((x.UC_X86_REG_RSP, self.stack), (x.UC_X86_REG_RBP, self.stack - 0x400),
                           (x.UC_X86_REG_R14, self.patch + 0x198), (x.UC_X86_REG_R13, 0),
                           (x.UC_X86_REG_RSI, self.json_object)):
            self.uc.reg_write(reg, value)
        page = ACCESSOR & ~4095
        if not any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): self.uc.mem_map(page, 4096)

    def hook(self, uc, address, size, user):
        if address == STOP: uc.emu_stop(); return
        if address == ACCESSOR:
            a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
            pointer = int.from_bytes(uc.mem_read(c, 8), 'little')
            count = int.from_bytes(uc.mem_read(c + 8, 4), 'little')
            key = bytes(uc.mem_read(pointer, count * 2)).decode('utf-16le')
            if a != self.json_object or key != 'ClientVersion': raise ValueError('Patch version key or object changed')
            self.keys.append(key)
            self.string(b, self.value)
            uc.reg_write(x.UC_X86_REG_RAX, b)
            stack = uc.reg_read(x.UC_X86_REG_RSP)
            uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(stack, 8), 'little'))
            uc.reg_write(x.UC_X86_REG_RSP, stack + 8)
            return
        return super().hook(uc, address, size, user)

    def capture(self):
        self.uc.emu_start(START, self.stop, count=256)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != STOP: raise ValueError('Patch key slice budget')
        value = self.text(self.patch + 0x1b0)
        if value != self.value or self.keys != ['ClientVersion']: raise ValueError('Patch version field differs')
        return dict(json_string_fixture=self.value, keys=self.keys, patch_field='0x1b0', value=value)


def build():
    root = native.ROOT / 'code-clues'
    source = json.loads((root / 'headless-device-identity.json').read_text('utf-8'))
    prior = json.loads((root / 'version-platform-context-replay.json').read_text('utf-8'))
    raw = Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(START)]})
    cases = [Replay(raw, image, source, prior, fragments, value).capture()
             for value in ('', 'Revision258392', 'Revision258269', 'Revision42junk', 'Ж界')]
    return dict(source=source['source'], source_sha256=source['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256=hashlib.sha256((HERE / 'replay-version-platform-context.py').read_bytes()).hexdigest(),
                fragments=fragments, cases=cases,
                limitations=['Actual key preparation and FString descriptor move from parser slice; explicit object state.',
                             'JSON parsing/accessor and FString/free primitives are bounded fixtures, not the full JSON parser.',
                             'Missing/wrong-type JSON keys and patch completion are not executed by this slice.',
                             'No game launch, process memory, installation writes or network.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/patch-client-version-replay.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
