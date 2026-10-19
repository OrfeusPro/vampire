"""Native constructor filename defaults and Load path continuation, no live files."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('filename_path', HERE / 'replay-sdk-storage-path.py')
paths = importlib.util.module_from_spec(spec)
spec.loader.exec_module(paths)
native, x = paths.storage.source.config.native, paths.x
CTOR = (0x1444ad167, 0x1444ad1a2)
LOAD = (0x14452c791, 0x14452c840)


class Replay(paths.Replay):
    def __init__(self, raw, image, base_report, storage_report, extra, directory):
        super().__init__(raw, image, base_report, storage_report, directory)
        rows = [r for f in storage_report['fragments'] + extra for r in f['instructions']
                if CTOR[0] <= r['address'] < CTOR[1] or LOAD[0] <= r['address'] < LOAD[1]]
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

    def capture_filename(self):
        rbp = self.stack + 0x100
        for register, value in ((x.UC_X86_REG_RSP, self.stack), (x.UC_X86_REG_RBP, rbp),
                                (x.UC_X86_REG_RBX, self.settings), (x.UC_X86_REG_RDI, 0)):
            self.uc.reg_write(register, value)
        self.uc.emu_start(*CTOR, count=1024)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != CTOR[1]:
            raise ValueError('SDK filename constructor slice budget exceeded')
        names = dict(field_2e8=self.text(self.settings + 0x2e8), field_2f8=self.text(self.settings + 0x2f8))
        # Load's optional extra directory gate disabled fixture, not active-state inference.
        for register, value in ((x.UC_X86_REG_R13, self.settings), (x.UC_X86_REG_R15, 0),
                                (x.UC_X86_REG_RDI, 0)):
            self.uc.reg_write(register, value)
        self.uc.emu_start(*LOAD, count=10000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != LOAD[1]:
            raise ValueError('SDK filename Load path slice budget exceeded')
        return dict(persistent_directory=self.persistent_dir, defaults=names,
                    load_filename=self.text(rbp - 0x70), events=self.events)


def build():
    root = native.ROOT
    storage_path = root / 'code-clues/headless-sdk-storage.json'
    report = json.loads(storage_path.read_text('utf-8'))
    base_report = json.loads((root / 'code-clues/headless-device-identity.json').read_text('utf-8'))
    raw = Path(report['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != report['sha256']:
        raise ValueError('SDK filename source changed')
    image = native.Image(raw)
    extra = native.decode_ranges(image, {image.roots[image.containing(a)] for a in (0x1444acf40, 0x1444aacb0)})
    offset = image.offset(0x1444ac6c0 - image.pe.base)
    thunk_bytes = raw[offset:offset + 0x14]
    cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    instructions = list(cs.disasm(thunk_bytes, 0x1444ac6c0))
    if sum(i.size for i in instructions) != len(thunk_bytes) or instructions[-1].mnemonic != 'ret' or not any(
            i.mnemonic == 'jmp' and i.op_str == '0x1444acf40' for i in instructions):
        raise ValueError('NMServiceSettings constructor thunk changed')
    literals = []
    for f in extra:
        for row in f['instructions']:
            if row['mnemonic'] == 'lea':
                for ref in row['rip_references']:
                    if literal := paths.storage.source.config.read_literal(raw, image, ref):
                        literals.append(dict(instruction=row['address'], **literal))
    return dict(schema_version=1, source=report['source'], sha256=report['sha256'],
                source_report_sha256=hashlib.sha256(storage_path.read_bytes()).hexdigest(),
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fragments=extra, literals=literals,
                constructor_thunk=dict(address=0x1444ac6c0, file_offset=offset, bytes=thunk_bytes.hex(),
                                       sha256=hashlib.sha256(thunk_bytes).hexdigest()),
                cases=[Replay(raw, image, base_report, report, extra, directory).capture_filename()
                       for directory in ('C:/fixture/Saved/PersistentDownloadDir', 'C:/пример/PersistentDownloadDir/', '')],
                native_execution=True, user_storage_read=False, limitations=[
                    'Only constructor filename slice and Load filename path continuation execute, reusing native directory/join.',
                    'Persistent base directory, FString helpers and optional extra-directory gate are explicit fixtures.',
                    'Class registration and constructor thunk chain exported statically; complete UObject lifecycle/config not executed.',
                    'Defaults do not establish active filename; Load file I/O/parsing/Save and real profiles not used.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/sdk-storage-filename-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
