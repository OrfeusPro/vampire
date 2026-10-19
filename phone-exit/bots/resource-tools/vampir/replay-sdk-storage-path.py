"""Native SDK storage directory path selection/join with a fixture base directory."""
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


storage = load('sdk_path_sources', 'build-headless-sdk-storage.py')
lifecycle = load('sdk_path_lifecycle', 'replay-device-key-lifecycle.py')
x = lifecycle.x


class Replay(lifecycle.Replay):
    def __init__(self, raw, image, base_report, report, persistent_dir):
        super().__init__(raw, image, base_report, {})
        self.persistent_dir = persistent_dir
        rows = [r for f in report['fragments'] if f['root_begin_rva'] in
                (0x4520bd0, 0x157fce0, 0x156f6b0, 0x142c9d0) for r in f['instructions']]
        self.allowed.update(r['address'] for r in rows)
        self.allowed.update((0x140bb4a10, 0x140bb4a12))
        pages = {r['address'] & ~4095 for r in rows}
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        pages.update(a & ~4095 for a in (0x140bb4a10, 0x1414459a0, 0x141421150,
                                        0x141430bc0, 0x141424430, 0x141432550))
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.string(0x14b4f1408, 'NetmarbleSDK')

    def wide(self, pointer):
        data = bytearray()
        for n in range(4096):
            unit = bytes(self.uc.mem_read(pointer + n * 2, 2))
            if unit == b'\0\0':
                return data.decode('utf-16le')
            data.extend(unit)
        raise ValueError('SDK path wide text fixture bound')

    def hook(self, uc, address, size, user):
        if address in self.allowed:
            return
        a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        result = 0
        if address == 0x1414459a0:
            data = (self.persistent_dir + '\0').encode('utf-16le')
            result = self.allocate(len(data))
            uc.mem_write(result, data)
            self.events.append(dict(action='persistent_directory_fixture', value=self.persistent_dir))
        elif address == 0x141421150:
            self.string(a, self.wide(b))
            result = a
        elif address in (0x141430bc0, 0x141432550):
            old, count, capacity = struct.unpack('<QII', bytes(uc.mem_read(a, 16)))
            if b > 4096:
                raise ValueError('SDK path reserve fixture bound')
            new = self.allocate((b + 1) * 2)
            if old and capacity:
                uc.mem_write(new, bytes(uc.mem_read(old, min(capacity, b + 1) * 2)))
            uc.mem_write(a, struct.pack('<QII', new, count, b + 1))
        elif address == 0x141424430:
            if c > 4096:
                raise ValueError('SDK path append fixture bound')
            value = bytes(uc.mem_read(b, c * 2)).decode('utf-16le') if c else ''
            self.string(a, self.text(a) + value)
            result = a
        else:
            return super().hook(uc, address, size, user)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def capture(self):
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP, self.stack)
        self.uc.reg_write(x.UC_X86_REG_RCX, self.output)
        self.uc.emu_start(0x144520bd0, self.stop, count=10000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop:
            raise ValueError('SDK path instruction budget exceeded')
        return dict(persistent_directory=self.persistent_dir, directory=self.text(self.output), events=self.events)


def build():
    root = storage.source.config.native.ROOT
    source_path = root / 'code-clues/headless-sdk-storage.json'
    report = json.loads(source_path.read_text('utf-8'))
    base_report = json.loads((root / 'code-clues/headless-device-identity.json').read_text('utf-8'))
    raw = Path(report['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != report['sha256'] or base_report['sha256'] != report['sha256']:
        raise ValueError('SDK storage path EXE changed')
    image = storage.source.config.native.Image(raw)
    fixtures = ('C:/fixture/Saved/PersistentDownloadDir', 'C:/fixture/Saved/PersistentDownloadDir/',
                'C:\\fixture\\Saved\\PersistentDownloadDir\\', 'C:/пример/Saved/PersistentDownloadDir', '',
                'C:\\fixture\\Saved\\PersistentDownloadDir')
    return dict(schema_version=1, source=report['source'], sha256=report['sha256'],
                source_report_sha256=hashlib.sha256(source_path.read_bytes()).hexdigest(),
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                cases=[Replay(raw, image, base_report, report, value).capture() for value in fixtures],
                native_execution=True, user_storage_read=False, limitations=[
                    'Native path getter, actual true predicate, wrapper, join dispatch and slash append helper execute.',
                    'Persistent directory getter, FString ctor/append/allocation/copy/free are fixtures; no real path resolution.',
                    'Only directory path, not complete settings filename or Save/Load/file operations.',
                    'Windows EXE only; no profiles, real device keys or credentials read.'])


if __name__ == '__main__':
    report = build()
    path = storage.source.config.native.ROOT / 'code-clues/sdk-storage-path-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
