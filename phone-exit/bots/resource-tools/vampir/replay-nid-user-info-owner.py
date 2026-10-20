"""Native logging owner -> zero UserInfo -> actual SDK getter chain, no OS calls."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


base = load('nid_owner_platform', 'replay-version-platform-context.py')
imports = load('nid_owner_import', 'build-object-zero-init-code.py')
native, x = base.native, base.x
CONSTRUCT, ZERO, GET, SETTINGS, LOCK = 0x14450f5d0, 0x14450e830, 0x144521e80, 0x144524800, 0x30010000


class Replay(base.Replay):
    def __init__(self, raw, image, source, platform, fragments, leaves, fixture):
        super().__init__(raw, image, source, fragments, platform['members'], False)
        self.allowed = {r['address'] for f in fragments for r in f['instructions']}
        pages = set()
        for leaf in leaves:
            a, end = int(leaf['start'], 16), int(leaf['end_exclusive'], 16)
            cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
            self.allowed.update(r.address for r in cs.disasm(raw[leaf['file_offset']:leaf['file_offset'] + end - a], a))
            pages.update(range(a & ~4095, (end + 4095) & ~4095, 4096))
        hooks = (0x1468e4100, 0x1487a2e25, 0x14146d9e0, 0x14450f8e0, LOCK)
        pages.update(p & ~4095 for a in hooks for p in (a, a + 64))
        for page in pages:
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            try: offset = image.offset(page - image.pe.base)
            except ValueError: continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        rows = {r['address']: r for f in fragments for r in f['instructions']}
        self.lock_slot = rows[0x14450f8a9]['rip_references'][0]
        self.imported = imports.import_at(raw, image, self.lock_slot)
        if self.imported['name'] != 'InitializeSRWLock': raise ValueError('Owner lock import changed')
        self.uc.mem_write(self.lock_slot, struct.pack('<Q', LOCK))
        self.fill, self.allocations = fixture, []
        self.owner = self.allocate(0x110)
        self.uc.mem_write(self.owner, bytes([fixture]) * 0x110)
        self.uc.mem_write(0x14b4f2060, b'\0')
        self.events = []

    def hook(self, uc, address, size, user):
        if address in self.allowed: return
        a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        result = 0
        if address == 0x1468e4100:
            if a not in (0x278, 0x18, 0x10): raise ValueError('Unexpected owner allocation size')
            result = self.allocate(a)
            self.uc.mem_write(result, bytes([self.fill]) * a)
            self.allocations.append(dict(pointer=result, size=a))
        elif address == 0x1487a2e25:
            if b != 0 or c != 0x278: raise ValueError('Unexpected owner memset')
            self.uc.mem_write(a, bytes(c)); result = a
        elif address == 0x14146d9e0:
            self.uc.mem_write(a, bytes(uc.mem_read(b, 8)))
            self.uc.mem_write(b, bytes(8)); result = a
        elif address == 0x14450f8e0:
            if a not in (self.owner + 0x58, self.owner + 0x68): raise ValueError('Unrelated owner container changed')
            self.uc.mem_write(a, bytes(16)); result = a
            self.events.append('container_constructor_capture')
        elif address == LOCK:
            if a != self.owner + 0xe0: raise ValueError('Owner lock location changed')
            self.uc.mem_write(a, bytes(8)); self.events.append('lock_initializer_capture')
        else: return super().hook(uc, address, size, user)
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(stack, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)

    def capture(self):
        if self.call(CONSTRUCT, self.owner) != self.owner: raise ValueError('Owner constructor return changed')
        inner = int.from_bytes(self.uc.mem_read(self.owner + 0x28, 8), 'little')
        if inner not in [a['pointer'] for a in self.allocations if a['size'] == 0x278]: raise ValueError('UserInfo allocation changed')
        bridge, handle = self.allocate(0x400), self.allocate(8)
        self.uc.mem_write(bridge + 0x310, struct.pack('<Q', self.owner))
        self.uc.mem_write(handle, struct.pack('<Q', bridge))
        wrapper = self.call(SETTINGS, handle)
        info = self.call(GET, wrapper)
        if wrapper != bridge + 0x310 or info != inner + 0x28: raise ValueError('Actual UserInfo pointer chain changed')
        if bytes(self.uc.mem_read(info, 0x250)) != bytes(0x250): raise ValueError('Initial UserInfo is not empty')
        return dict(fill=self.fill, user_info_empty=True, descriptor_count=37,
                    owner_pointer_offset='0x28', inner_field_offset='0x28',
                    allocation_sizes=[a['size'] for a in self.allocations], captures=self.events)


def build():
    root = native.ROOT / 'code-clues'
    source = json.loads((root / 'headless-device-identity.json').read_text('utf-8'))
    platform = json.loads((root / 'version-platform-context-replay.json').read_text('utf-8'))
    manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
    raw = Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(CONSTRUCT)]})
    leaves = [r for f in manifest['functions'] if int(f['address'], 16) in (ZERO, GET, SETTINGS) for r in f['ranges']]
    if len(leaves) != 3: raise ValueError('Reviewed UserInfo leaves missing')
    diagnostic_fragments = native.decode_ranges(image, {image.roots[image.containing(a)]
        for a in (0x144551060, 0x144550e40, 0x144588bb0)})
    names = []
    for address in (0x1494e6f10, 0x1494e7330, 0x1494ee190):
        offset = image.offset(address - image.pe.base)
        end = raw.find(b'\0', offset, offset + 512)
        if end < 0: raise ValueError('Diagnostic literal bound')
        data = raw[offset:end + 1]
        references = [r for f in diagnostic_fragments for r in f['instructions'] if address in r['rip_references']]
        if len(references) != 1: raise ValueError('Diagnostic function reference changed')
        names.append(dict(address=hex(address), file_offset=offset, text=data[:-1].decode('ascii'),
                          bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest(), instruction=references[0]))
    return dict(source=source['source'], source_sha256=source['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256=hashlib.sha256((HERE / 'replay-version-platform-context.py').read_bytes()).hexdigest(),
                fragments=fragments, leaves=leaves, diagnostic_names=names,
                cases=[Replay(raw, image, source, platform, fragments, leaves, fill).capture() for fill in (0, 0x55, 0xff)],
                limitations=['Native full owner constructor, 475-byte zeroing constructor and both getter entries/returns execute.',
                             'Allocation/memset, shared-pointer transfer, two unrelated container constructors and lock initialization are fixtures.',
                             'No allocator failure paths, logging backend initialization, live UserInfo population, process memory or network.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/nid-user-info-owner-replay.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
