"""Native NID web/token device-key pair assembly; identity getters are fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('nid_device_lifecycle', HERE / 'replay-device-key-lifecycle.py')
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)
native = lifecycle.guid.source.config.native
x = lifecycle.x
SEGMENTS = (
    dict(name='nid_web_deviceKey', root=0x1450de4f0, begin=0x1450dea30, end=0x1450dea6a,
         rbp=0x100, pair=0x500, text=0x80, setting_register='R15', constructor=0x141420f70),
    dict(name='nid_code_device_key', root=0x1450e2640, begin=0x1450e2c63, end=0x1450e2ca9,
         rbp=0x100, pair=0x190, text=0x40, setting_register='R13', constructor=0x141421150),
    dict(name='nid_refresh_device_key', root=0x1450e2f50, begin=0x1450e35c4, end=0x1450e360a,
         rbp=0x100, pair=0x1c0, text=0x70, setting_register='R13', constructor=0x141421150),
)


class Replay(lifecycle.Replay):
    def __init__(self, raw, image, base_report, fragments, segment):
        super().__init__(raw, image, base_report, {})
        self.segment = segment
        rows = [r for f in fragments for r in f['instructions']
                if segment['begin'] <= r['address'] < segment['end']]
        self.allowed.update(r['address'] for r in rows)
        pages = {r['address'] & ~4095 for r in rows}
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        pages.update(a & ~4095 for a in (0x141420f70, 0x141421150, 0x144522b50))
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
        if address in self.allowed:
            return
        a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        if address == 0x144522b50:
            if a != self.settings:
                raise ValueError('NID context settings pointer mismatch')
            self.string(b, 'nid-device-fixture')
            result = b
            self.events.append(dict(action='GetDeviceKeyForNetmarbleId_fixture', save_flag=bool(c)))
        elif address in (0x141420f70, 0x141421150):
            data = bytearray()
            unit_size = 1 if address == 0x141420f70 else 2
            for n in range(128):
                unit = bytes(uc.mem_read(b + n * unit_size, unit_size))
                if unit == bytes(unit_size):
                    break
                data.extend(unit)
            else:
                raise ValueError('NID device key literal bound')
            self.string(a, data.decode('ascii' if unit_size == 1 else 'utf-16le'))
            result = a
        else:
            return super().hook(uc, address, size, user)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def capture(self):
        segment = self.segment
        rbp = self.stack + segment['rbp']
        for register, value in ((x.UC_X86_REG_RBP, rbp), (x.UC_X86_REG_RSP, self.stack),
                                (getattr(x, 'UC_X86_REG_' + segment['setting_register']), self.settings)):
            self.uc.reg_write(register, value)
        # Adjacent client-id setup reads these stack slots; their values stay fixtures.
        self.uc.mem_write(self.stack + 0x78, struct.pack('<Q', self.settings))
        self.uc.mem_write(self.stack + 0x70, struct.pack('<Q', self.settings))
        self.uc.emu_start(segment['begin'], segment['end'], count=1024)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != segment['end']:
            raise ValueError('NID device context instruction budget exceeded')
        key_desc, value_desc = struct.unpack('<QQ', bytes(self.uc.mem_read(rbp + segment['pair'], 16)))
        if key_desc != rbp + segment['text']:
            raise ValueError('NID device key pair pointer mismatch')
        return dict(name=segment['name'], begin=segment['begin'], end=segment['end'],
                    key=self.text(key_desc), value=self.text(value_desc), events=self.events)


def build():
    base_path = native.ROOT / 'code-clues/headless-device-identity.json'
    report = json.loads(base_path.read_text('utf-8'))
    raw = Path(report['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != report['sha256']:
        raise ValueError('NID device context source changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(s['root'])] for s in SEGMENTS})
    literals = []
    for f in fragments:
        for row in f['instructions']:
            if row['mnemonic'] == 'lea':
                for ref in row['rip_references']:
                    if literal := lifecycle.guid.source.config.read_literal(raw, image, ref):
                        literals.append(dict(instruction=row['address'], **literal))
    return dict(schema_version=1, source=report['source'], sha256=report['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                source_report_sha256=hashlib.sha256(base_path.read_bytes()).hexdigest(),
                fragments=fragments, literals=literals,
                cases=[Replay(raw, image, report, fragments, s).capture() for s in SEGMENTS],
                native_execution=True, network_ready=False, limitations=[
                    'Only native device-key literal/getter/pair assembly slices execute, not full web URL or token request.',
                    'GetDeviceKeyForNetmarbleId returns an explicit fixture; its body/storage and active settings not executed.',
                    'FString ASCII/wide constructors and client-id adjacent context are fixtures.',
                    'NID web deviceKey and OAuth device_key bind the NID-specific getter; SDK sign-in deviceKey remains distinct.',
                    'No actual identities, accounts, files Saved, registry or network used.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/nid-device-context-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
