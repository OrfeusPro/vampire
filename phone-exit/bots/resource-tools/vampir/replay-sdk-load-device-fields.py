"""Native Load device field restoration and post-restore gates; no SaveGame I/O."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('load_device_lifecycle', HERE / 'replay-device-key-lifecycle.py')
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)
native, x = lifecycle.guid.source.config.native, lifecycle.x
SEGMENTS = ((0x14452da12, 0x14452da35), (0x14452de2e, 0x14452de56),
            (0x14452df6a, 0x14452e004))


class Replay(lifecycle.Replay):
    def __init__(self, raw, image, base_report, report, fixture):
        super().__init__(raw, image, base_report, dict(settings='old-sdk-fixture', save_ok=False))
        self.load_fixture = fixture
        rows = [r for f in report['fragments'] if f['root_begin_rva'] == 0x452c6e0
                for r in f['instructions'] if any(a <= r['address'] < b for a, b in SEGMENTS)]
        self.allowed.update(r['address'] for r in rows)
        pages = {r['address'] & ~4095 for r in rows}
        pages.update((r['address'] + len(bytes.fromhex(r['bytes'])) - 1) & ~4095 for r in rows)
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        pages.update(a & ~4095 for a in (0x14454b5c0, 0x144522b50))
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.saved = self.base + 0x8000
        self.string(self.saved + 0x208, fixture['sdk_key'])
        self.string(self.saved + 0x5a0, fixture['nid_key'])
        self.string(self.settings + 0x628, 'old-nid-fixture')
        self.uc.mem_write(self.saved + 0x28, struct.pack('<Q', fixture['saved_tag']))
        self.uc.mem_write(0x14b4f13fd, bytes([fixture['post_restore_gate']]))

    def hook(self, uc, address, size, user):
        if address in self.allowed:
            return
        if address not in (0x14454b5c0, 0x144522820, 0x144522b50):
            return super().hook(uc, address, size, user)
        a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        if a != self.settings:
            raise ValueError('Load device fixture settings pointer mismatch')
        if address == 0x14454b5c0:
            self.string(a + 0x628, self.text(b))
            self.events.append(dict(action='SetDeviceKeyForNetmarbleId_capture', value=self.text(b), flag=bool(c)))
            result = 0
        else:
            offset = 0x618 if address == 0x144522820 else 0x628
            self.string(b, self.text(a + offset))
            self.events.append(dict(action='GetDeviceKey_capture' if offset == 0x618 else
                                    'GetDeviceKeyForNetmarbleId_capture', save_flag=bool(c)))
            result = b
        uc.reg_write(x.UC_X86_REG_RAX, result)
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def capture(self):
        rbp = self.stack + 0x100
        for register, value in ((x.UC_X86_REG_RBP, rbp), (x.UC_X86_REG_RSP, self.stack),
                                (x.UC_X86_REG_RSI, self.saved), (x.UC_X86_REG_R13, self.settings),
                                (x.UC_X86_REG_R12, 0), (x.UC_X86_REG_RDI, 0)):
            self.uc.reg_write(register, value)
        for begin, end in SEGMENTS:
            try:
                self.uc.emu_start(begin, end, count=4096)
            except Exception as error:
                raise ValueError('Load device slice failed at ' + hex(self.uc.reg_read(x.UC_X86_REG_RIP))
                                 + ' fixture=' + repr(self.load_fixture)) from error
            if self.uc.reg_read(x.UC_X86_REG_RIP) != end:
                raise ValueError('Load device slice instruction budget exceeded')
        return dict(fixture=self.load_fixture, sdk_key=self.text(self.settings + 0x618),
                    nid_key=self.text(self.settings + 0x628), events=self.events)


def build():
    source_path = native.ROOT / 'code-clues/headless-sdk-storage.json'
    report = json.loads(source_path.read_text('utf-8'))
    base_report = json.loads((native.ROOT / 'code-clues/headless-device-identity.json').read_text('utf-8'))
    raw = Path(report['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != report['sha256'] or base_report['sha256'] != report['sha256']:
        raise ValueError('SDK Load source changed')
    image = native.Image(raw)
    cases = []
    for sdk_key in ('', 'saved-sdk-fixture'):
        for nid_key in ('', 'saved-nid-fixture'):
            for gate in (0, 1):
                for saved_tag in (0xc41f, 0x4c9dac):
                    fixture = dict(sdk_key=sdk_key, nid_key=nid_key, post_restore_gate=gate, saved_tag=saved_tag)
                    cases.append(Replay(raw, image, base_report, report, fixture).capture())
    return dict(schema_version=1, source=report['source'], sha256=report['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                source_report_sha256=hashlib.sha256(source_path.read_bytes()).hexdigest(),
                segments=[dict(begin=a, end=b) for a, b in SEGMENTS], cases=cases,
                native_execution=True, user_storage_read=False, limitations=[
                    'Only two Load FString field restoration slices and post-restore dispatch execute.',
                    'SaveGame object, global gate and saved tag are explicit fixtures, not decoded from real files.',
                    'FString assignment/copy, both getters/setters and Save are fixtures/captures; no normalization or generation in getter captures.',
                    'Complete Load parsing/type/version checks, file I/O and Save persistence do not execute.',
                    'No tokens, registry, Saved/profile files, process memory or network accessed.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/sdk-load-device-fields-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
