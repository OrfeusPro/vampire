"""Native SetDeviceKey body/compare and getter integration, isolated storage fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('device_setter_lifecycle', HERE / 'replay-device-key-lifecycle.py')
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)
x = lifecycle.x


class Replay(lifecycle.Replay):
    def __init__(self, raw, image, report, fixture, compare):
        super().__init__(raw, image, report, fixture)
        extra = []
        for fragment in report['fragments']:
            if fragment['root_begin_rva'] != 0x454b390:
                continue
            extra.extend(row for row in fragment['instructions']
                         if 0x14454b390 <= row['address'] < 0x14454b40c
                         or 0x14454b464 <= row['address'] < 0x14454b54f)
        self.allowed.update(row['address'] for row in extra)
        leaf = compare['compare_leaf']
        table = compare['compare_table']
        cs = lifecycle.guid.source.config.native.capstone.Cs(
            lifecycle.guid.source.config.native.capstone.CS_ARCH_X86,
            lifecycle.guid.source.config.native.capstone.CS_MODE_64)
        self.allowed.update(i.address for i in cs.disasm(bytes.fromhex(leaf['bytes']), leaf['address']))
        pages = {row['address'] & ~4095 for row in extra}
        pages.update(a & ~4095 for row in extra for a in row['rip_references'])
        pages.update(a & ~4095 for a in (leaf['address'], table['address'], 0x14143c260, 0x14454b40c))
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset + 4096])

    def hook(self, uc, address, size, user):
        if address == 0x14454b390:
            args = [uc.reg_read(r) for r in (x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
            self.events.append(dict(action='SetDeviceKey_native_entry', value=self.text(args[0]), flag=bool(args[1])))
        if address == 0x14454b40c:
            # Skip console-variable/TLS platform selection; remaining body is native.
            uc.reg_write(x.UC_X86_REG_RIP, 0x14454b464 if self.fixture['platform'] == 3 else 0x14454b523)
            self.events.append(dict(action='setter_platform_fixture', platform=self.fixture['platform']))
            return
        if address == 0x14143c260:
            a, b = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX)]
            self.string(a, self.text(b))
            self.events.append(dict(action='FString_assignment_fixture', value=self.text(a)))
            uc.reg_write(x.UC_X86_REG_RAX, a)
            rsp = uc.reg_read(x.UC_X86_REG_RSP)
            target = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
            uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(x.UC_X86_REG_RIP, target)
            return
        return super().hook(uc, address, size, user)

    def setter(self, value, force):
        desc = self.base + 0x6000
        self.string(desc, value)
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        for register, argument in ((x.UC_X86_REG_RSP, self.stack), (x.UC_X86_REG_RCX, self.settings),
                                   (x.UC_X86_REG_RDX, desc), (x.UC_X86_REG_R8, int(force))):
            self.uc.reg_write(register, argument)
        self.uc.emu_start(0x14454b390, self.stop, count=10000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop:
            raise ValueError('SetDeviceKey replay instruction budget exceeded')
        return self.text(self.settings + 0x618)


def build():
    root = lifecycle.guid.source.config.native.ROOT
    source_path = root / 'code-clues/headless-device-identity.json'
    compare_path = root / 'code-clues/nid-result-primitives.json'
    report = json.loads(source_path.read_text('utf-8'))
    primitives = json.loads(compare_path.read_text('utf-8'))
    raw = Path(report['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != report['sha256'] or primitives['sha256'] != report['sha256']:
        raise ValueError('Device setter source changed')
    compare = {name: primitives['evidence'][name] for name in ('compare_leaf', 'compare_table')}
    for item in compare.values():
        content = bytes.fromhex(item['bytes'])
        if raw[item['file_offset']:item['file_offset'] + len(content)] != content:
            raise ValueError('Device setter compare source mismatch')
    image = lifecycle.guid.source.config.native.Image(raw)
    cases = []
    pairs = [('', ''), ('same-fixture', 'same-fixture'), ('AbC-fixture', 'aBc-fixture'),
             ('abc-fixture', 'abd-fixture'), ('short', 'longer-fixture'), ('', 'previous-fixture'),
             ('new-fixture', '')]
    for value, stored in pairs:
        for force in (False, True):
            for platform in (3, 1):
                for write_ok in (False, True):
                    fixture = dict(stored=stored, platform=platform, write_ok=write_ok,
                                   settings='old-settings-fixture', force=force, value=value)
                    replay = Replay(raw, image, report, fixture, compare)
                    cases.append(dict(fixture=fixture, output=replay.setter(value, force), events=replay.events))
    integrated = []
    for platform in (3, 1):
        for state in ('stored', 'settings', 'new'):
            for save_flag in (False, True):
                fixture = dict(platform=platform, state=state, save_flag=save_flag, write_ok=False, save_ok=False,
                               stored='stored-device-fixture' if state == 'stored' else '',
                               settings='settings-device-fixture' if state == 'settings' else '')
                replay = Replay(raw, image, report, fixture, compare)
                integrated.append(dict(fixture=fixture, output=replay.device(), events=replay.events))
    native = lifecycle.guid.source.config.native
    save_fragments = native.decode_ranges(image, {image.roots[image.containing(a)]
                                                  for a in (0x14453cdf0, 0x144520bd0)})
    save_literals = []
    for fragment in save_fragments:
        for row in fragment['instructions']:
            if row['mnemonic'] == 'lea':
                for ref in row['rip_references']:
                    if literal := lifecycle.guid.source.config.read_literal(raw, image, ref):
                        save_literals.append(dict(instruction=row['address'], **literal))
    return dict(schema_version=1, source=report['source'], sha256=report['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                source_report_sha256=hashlib.sha256(source_path.read_bytes()).hexdigest(),
                compare_report_sha256=hashlib.sha256(compare_path.read_bytes()).hexdigest(), compare=compare,
                save_static_fragments=save_fragments, save_static_literals=save_literals,
                cases=cases, getter_integration=integrated, user_identity_read=False, limitations=[
                    'SetDeviceKey prologue and body executed; verbose logging disabled and platform/TLS block explicitly skipped.',
                    'Native ASCII case-insensitive compare reuses source-bound leaf/table from NID primitives.',
                    'StoredValue read/write, store/section and FString assignment/allocation/free remain fixtures/captures.',
                    'Getter integration executes native setter body; Save is still a capture and CoCreateGuid/parser fixtures unchanged.',
                    'Save and its path getter exported as static evidence only, not executed or interpreted as verified persistence.',
                    'No actual registry, Saved/profile, processes, network or real identity accessed.'])


if __name__ == '__main__':
    report = build()
    path = lifecycle.guid.source.config.native.ROOT / 'code-clues/device-key-setter-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                          cases=len(report['cases']), getter_integration=len(report['getter_integration']))))
