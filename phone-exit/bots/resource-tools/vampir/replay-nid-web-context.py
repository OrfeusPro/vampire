"""Native assembly of all ten base NID webview key/value pairs.

Captures before map construction/URL serialization. NM getter runs on a cache
fixture; other context getters and string storage are explicit fixtures.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('nid_web_lifecycle', HERE / 'replay-device-key-lifecycle.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.guid.source.config.native, base.x
BEGIN, END, ROOT = 0x1450de8c8, 0x1450deb18, 0x1450de4f0
KEYS = ('gameCode', 'buildCode', 'countryCode', 'language', 'os', 'nmDeviceKey',
        'deviceKey', 'osVersion', 'clientId', 'nidV')


class Replay(base.Replay):
    def __init__(self, raw, image, source, fragments, fixture):
        super().__init__(raw, image, source, dict(cache=fixture['nm_device_key']))
        self.web_fixture = fixture
        rows = [r for f in fragments for r in f['instructions']
                if BEGIN <= r['address'] < END or image.pe.base + f['root_begin_rva'] == 0x1450e7bc0]
        self.allowed.update(r['address'] for r in rows)
        self.web_hooks = {0x141420f70, 0x141421150, 0x14452b820, 0x144522160,
                          0x143d163c0, 0x1444e66b0, 0x144522b50, 0x1444e64f0}
        pages = {p & ~4095 for r in rows for p in (r['address'], *r['rip_references'])}
        pages.update(a & ~4095 for a in self.web_hooks)
        for page in pages:
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            off = image.offset(page - image.pe.base)
            self.uc.mem_write(page, raw[off:off + 4096])

    def hook(self, uc, address, size, user):
        if address in self.allowed: return
        if address not in self.web_hooks: return super().hook(uc, address, size, user)
        a, b, c = [uc.reg_read(reg) for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        f = self.web_fixture
        if address in (0x141420f70, 0x141421150):
            unit = 1 if address == 0x141420f70 else 2
            text = bytearray()
            for index in range(128):
                value = bytes(uc.mem_read(b + index * unit, unit))
                if value == bytes(unit): break
                text.extend(value)
            else: raise ValueError('Web context literal bound')
            self.string(a, text.decode('ascii' if unit == 1 else 'utf-16le'))
            result = a
        else:
            if address == 0x144522160:
                if a != self.settings: raise ValueError('Country settings receiver changed')
                output, value = b, f['country']
            elif address == 0x144522b50:
                if a != self.settings or c & 255 != 1: raise ValueError('NID device getter context changed')
                output, value = b, f['nid_device_key']
            else:
                output = a
                names = {0x143d163c0: 'language', 0x1444e66b0: 'os', 0x1444e64f0: 'os_version'}
                value = ('B' if b & 255 == 1 else 'C' if b & 255 == 2 else 'A') if address == 0x14452b820 else f[names[address]]
            self.string(output, value)
            self.events.append(dict(action='web_context_getter_fixture', address=address))
            result = output
        uc.reg_write(x.UC_X86_REG_RAX, result)
        sp = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RIP, struct.unpack('<Q', bytes(uc.mem_read(sp, 8)))[0])
        uc.reg_write(x.UC_X86_REG_RSP, sp + 8)

    def capture(self):
        rbp, sdk = self.stack + 0x100, self.base + 0x6000
        f = self.web_fixture
        self.string(sdk + 0x38, f['game_code'])
        self.string(sdk + 0x98, f['client_id'])
        self.uc.mem_write(sdk + 0x48, bytes([f['build_code']]))
        for reg, value in ((x.UC_X86_REG_RBP, rbp), (x.UC_X86_REG_RSP, self.stack),
                           (x.UC_X86_REG_RBX, sdk), (x.UC_X86_REG_R15, self.settings), (x.UC_X86_REG_R12, 0)):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(BEGIN, END, count=10000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != END: raise ValueError('Web context instruction budget')
        pairs = []
        for index in range(10):
            key, value = struct.unpack('<QQ', bytes(self.uc.mem_read(rbp + 0x4a0 + index * 16, 16)))
            pairs.append([self.text(key), self.text(value)])
        if tuple(p[0] for p in pairs) != KEYS: raise ValueError('Native base web keys changed')
        return dict(fixture=f, pairs=pairs, events=self.events)

    def webview_type(self, raw_type):
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        for reg, value in ((x.UC_X86_REG_RSP, self.stack), (x.UC_X86_REG_RCX, self.output),
                           (x.UC_X86_REG_RDX, raw_type)):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(0x1450e7bc0, self.stop, count=10000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop: raise ValueError('Webview type budget')
        return dict(raw_type=raw_type, value=self.text(self.output))


def build():
    path = native.ROOT / 'code-clues/headless-device-identity.json'
    source = json.loads(path.read_text('utf-8'))
    raw = Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256']: raise ValueError('Web source changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in (ROOT, 0x1450e7bc0)})
    default = dict(game_code='thered', build_code=0, country='KR', language='en-US', os='windows',
                   nm_device_key='nm-fixture', nid_device_key='nid-fixture', os_version='os-fixture', client_id='client-fixture')
    profiles = [dict(default, build_code=value) for value in (0, 1, 2, 3, 255)]
    profiles.extend((dict(default, country='', os_version=''), dict(default, language='Українська'),
                     dict(default, nm_device_key='OTHER-NM-fixture', nid_device_key='OTHER-NID-fixture')))
    types = Replay(raw, image, source, fragments, default)
    return dict(source=source['source'], sha256=source['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256=hashlib.sha256((HERE / 'replay-device-key-lifecycle.py').read_bytes()).hexdigest(),
                fragments=fragments, begin=BEGIN, end=END,
                cases=[Replay(raw, image, source, fragments, f).capture() for f in profiles],
                type_cases=[types.webview_type(value) for value in range(256)],
                native_execution=True, network_ready=False,
                limitations=['Native pair assembly and cached NM getter; other getters and FString storage are fixtures.',
                             'Stops before map construction; authType/token conditions and URL serializer are not executed. WebViewType getter executes separately.',
                             'No real identities, network, browser or account credentials.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/nid-web-context-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
