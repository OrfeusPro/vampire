"""Native channelKey migration path transform, with explicit allocation-tail fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('channel_migration_suffix', HERE / 'replay-sdk-nid-path-suffix.py')
suffix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suffix)
native, x = suffix.native, suffix.x
BEGIN, END = 0x14454c9a1, 0x14454cac1


class Replay(suffix.Replay):
    def __init__(self, raw, image, base_report, prior, fixture):
        super().__init__(raw, image, base_report, prior['fragments'], prior['wrapper'],
                         dict(sub=fixture['channel_key'], nm_key=fixture['nm_key']))
        self.migration_fixture = fixture
        rows = [r for f in prior['fragments'] if f['root_begin_rva'] == 0x454c7a0
                for r in f['instructions'] if BEGIN <= r['address'] < END]
        self.allowed.update(r['address'] for r in rows)
        pages = {r['address'] & ~4095 for r in rows}
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.string(0x14b4f1ec0, fixture['channel_key'])
        self.string(0x14b4f1ed0, 'old-migration-fixture')
        self.string(self.stack + 0x60, fixture['nm_key'])

    def hook(self, uc, address, size, user):
        super().hook(uc, address, size, user)
        if address == 0x141431680 and self.buffer is not None:
            # The source allocator's initialization is unknown; make this uncertainty explicit.
            count = int.from_bytes(uc.mem_read(self.stack + 0x40, 4), 'little')
            uc.mem_write(self.buffer, bytes([self.migration_fixture['allocation_fill']]) * count)

    def capture_migration(self):
        for register, value in ((x.UC_X86_REG_RSP, self.stack), (x.UC_X86_REG_RBP, self.stack + 0x100),
                                (x.UC_X86_REG_R14, 0), (x.UC_X86_REG_RSI, self.empty)):
            self.uc.reg_write(register, value)
        self.uc.emu_start(BEGIN, END, count=20000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != END:
            raise ValueError('Migration path instruction budget exceeded')
        return dict(fixture=self.migration_fixture, transformed_hex=self.before,
                    migration_path=self.text(0x14b4f1ed0))


def build():
    path = native.ROOT / 'code-clues/sdk-nid-path-suffix-replay.json'
    prior = json.loads(path.read_text('utf-8'))
    base_report = json.loads((native.ROOT / 'code-clues/headless-device-identity.json').read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('Channel migration path EXE changed')
    image = native.Image(raw)
    fixtures = [dict(channel_key='C' * size, nm_key='0123456789ABCDEFFEDCBA9876543210', allocation_fill=fill)
                for size in (0, 16, 17, 32) for fill in (0, 0xaa)]
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                source_report_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                begin=BEGIN, end=END, cases=[Replay(raw, image, base_report, prior, f).capture_migration() for f in fixtures],
                native_execution=True, user_storage_read=False, limitations=[
                    'Native channelKey length rounding, low-byte minus1 loop, AES-NI and hex writer control flow execute.',
                    'Explicit zero/AA allocation fill fixtures expose unverified tail initialization for unaligned inputs.',
                    'Caller does not write rounded tail bytes in this slice; actual allocator initialization remains unknown.',
                    'ChannelKey presence/read, bUseMigration config gate, token decode and real migration file operations not executed.',
                    'Other dispatch/ANSI/FString/formatting fixtures inherited and bounded as in NID suffix replay.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/sdk-channel-migration-path-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
