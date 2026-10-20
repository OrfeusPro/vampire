"""Native common-owner -> platform log getter/thunk and absent-service branch."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load('signin_log_platform', 'replay-version-platform-context.py')
config = load('signin_log_literals', 'build-headless-sdk-config.py')
native, x = base.native, base.x
GET, THUNK, SEND = 0x144524d70, 0x144548ca0, 0x144548cb0


class Replay(base.Replay):
    def __init__(self, raw, image, source, platform, fragments, leaves):
        super().__init__(raw, image, source, fragments, platform['members'], False)
        self.allowed = {r['address'] for f in fragments for r in f['instructions']}
        cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
        for leaf in leaves:
            start, end = int(leaf['start'], 16), int(leaf['end_exclusive'], 16)
            self.allowed.update(i.address for i in cs.disasm(raw[leaf['file_offset']:leaf['file_offset'] + end - start], start))
        hooks = (0x144523ff0, 0x14451fd40, THUNK, GET)
        for page in {p & ~4095 for a in hooks for p in (a, a + 64)}:
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page, 4096)
            offset = image.offset(page - image.pe.base)
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.allowed.update((THUNK, THUNK + 4))
        self.uc.mem_write(0x14b4f2060, b'\0')
        self.events = []
        self.expected_impl = 0

    def hook(self, uc, address, size, user):
        a, b = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX)]
        if address == SEND:
            if a != self.expected_impl:
                raise ValueError('Platform log thunk target object changed')
            self.events.append('native_impl_entered')
        if address in self.allowed:
            return
        if address == 0x144523ff0:
            if a != self.expected_impl:
                raise ValueError('Unexpected weak service owner')
            uc.mem_write(b, bytes(16))
            result = b
            self.events.append('weak_service_getter_fixture')
        elif address == 0x14451fd40:
            if b != 0:
                raise ValueError('Expected absent service fixture')
            uc.mem_write(a, bytes(16))
            result = a
            self.events.append('weak_service_lock_absent_fixture')
        else:
            return super().hook(uc, address, size, user)
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(stack, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)

    def capture(self, padding):
        owner, wrapper = self.allocate(0xf0), self.allocate(16)
        impl = self.allocate(0x100)
        self.uc.mem_write(owner, bytes([padding]) * 0xf0)
        self.uc.mem_write(owner + 0x88, struct.pack('<Q', impl))
        self.uc.mem_write(wrapper, struct.pack('<Q', owner))
        self.expected_impl = impl
        component = self.call(GET, wrapper)
        if component != owner + 0x78:
            raise ValueError('Platform log getter offset changed')
        before = bytes(self.uc.mem_read(owner, 0xf0))
        self.call(THUNK, component)
        if bytes(self.uc.mem_read(owner, 0xf0)) != before:
            raise ValueError('Absent-service branch changed owner memory')
        if self.events != ['native_impl_entered', 'weak_service_getter_fixture', 'weak_service_lock_absent_fixture']:
            raise ValueError('Unexpected absent-service call sequence')
        return dict(fill=padding, component_offset='0x78', impl_offset_in_component='0x10',
                    impl_offset_in_owner='0x88', events=self.events, owner_unchanged=True,
                    service_available=False)


def build():
    root = native.ROOT / 'code-clues'
    source = json.loads((root / 'headless-device-identity.json').read_text('utf-8'))
    platform = json.loads((root / 'version-platform-context-replay.json').read_text('utf-8'))
    manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
    raw = Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256']:
        raise ValueError('Client changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(SEND)]})
    leaves = [r for f in manifest['functions'] if int(f['address'], 16) == GET for r in f['ranges']]
    if len(leaves) != 1:
        raise ValueError('Reviewed platform log getter missing')
    offset = image.offset(THUNK - image.pe.base)
    if raw[offset:offset + 9].hex() != '488b4910e907000000':
        raise ValueError('Platform log thunk bytes changed')
    names = []
    for address in (0x1494ebba0, 0x1494ebbe8, 0x1494c5ea8, 0x1494de338):
        literal = config.read_literal(raw, image, address)
        refs = [r for f in fragments for r in f['instructions'] if address in r['rip_references']]
        if literal is None or not refs:
            raise ValueError('Platform log literal reference missing')
        names.append(dict(literal=literal, references=refs))
    return dict(source=source['source'], source_sha256=source['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256=hashlib.sha256((HERE / 'replay-version-platform-context.py').read_bytes()).hexdigest(),
                fragments=fragments, leaves=leaves, diagnostic_literals=names,
                thunk=dict(address=hex(THUNK), file_offset=offset, bytes=raw[offset:offset+9].hex(),
                           sha256=hashlib.sha256(raw[offset:offset+9]).hexdigest()),
                cases=[Replay(raw, image, source, platform, fragments, leaves).capture(fill) for fill in (0, 0x55, 0xff)],
                limitations=['Real getter, forwarding thunk and full SendSignIn absent-service branch execute.',
                             'Owner/platform-log objects and weak-service absence are fixtures; logging diagnostics disabled.',
                             'Service-present event payload, logging transport and common-data population are not executed.',
                             'No live client, memory reading, auth or network.'])


if __name__ == '__main__':
    report = build()
    target = native.ROOT / 'code-clues/sdk-sign-in-log-replay.json'
    target.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(), cases=report['cases'])))
