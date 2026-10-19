"""Native SDK device getter branches with explicit parser/storage/platform fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('device_lifecycle_source', HERE / 'replay-device-guid-format.py')
guid = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guid)
unicorn, x = guid.unicorn, guid.x
WORDS = (0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210)


class Replay:
    def __init__(self, raw, image, report, fixture):
        self.fixture = fixture
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        self.allowed = set()
        pages = set()
        for f in report['fragments']:
            root = f['root_begin_rva']
            for row in f['instructions']:
                if root in (0x44e5ff0, 0x155a550, 0x15ad580) or (
                    root == 0x4522820 and 0x144522904 <= row['address'] < 0x144522aa9):
                    self.allowed.add(row['address'])
                    pages.add(row['address'] & ~4095)
                    pages.update(a & ~4095 for a in row['rip_references'])
        for span in report['spans'][1:]:
            self.allowed.update(row['address'] for row in span['instructions'])
            pages.update(row['address'] & ~4095 for row in span['instructions'])
        hooks = (0x1414313d0, 0x141431e70, 0x1487a2e19, 0x14147d580,
                 0x141424870, 0x141420cc0, 0x1415c59c0, 0x1415d1990,
                 0x14155abf0, 0x1415bf470, 0x148796040, 0x14452f230,
                 0x14452f170, 0x14454b390, 0x14453cdf0)
        pages.update(a & ~4095 for a in hooks)
        pages.add(0x14b2004c0 & ~4095)
        for page in sorted(pages):
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - image.pe.base)
            except ValueError:
                continue  # BSS pages remain zeroed in the isolated fixture.
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.base = 0x20000000
        self.uc.mem_map(self.base, 0x80000)
        self.cursor = self.base + 0x10000
        self.stack, self.stop = self.base + 0x70000, self.base + 0x7f000
        self.settings, self.output = self.base + 0x2000, self.base + 0x4000
        self.events = []
        self.uc.mem_write(0x14b4f2060, b'\0')  # Verbose logging disabled fixture.
        for address, value in ((0x14b4f1030, 'Netmarble'), (0x14b4f1040, 'NetmarbleSDK'),
                               (0x14b4f1070, 'NMDeviceKey'), (0x14b4f1a88, 'DeviceKey'),
                               (0x14b4f13a0, fixture.get('cache', ''))):
            self.string(address, value)
        self.string(self.settings + 0x618, fixture.get('settings', ''))
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.hook)

    def allocate(self, size):
        if not 0 < size <= 8192 or self.cursor + size >= self.base + 0x60000:
            raise ValueError('Lifecycle allocation fixture bound')
        pointer = self.cursor
        self.cursor += (size + 15) & ~15
        return pointer

    def string(self, desc, text):
        data = (text + '\0').encode('utf-16le')
        pointer = self.allocate(len(data))
        self.uc.mem_write(pointer, data)
        self.uc.mem_write(desc, struct.pack('<QII', pointer, len(data) // 2, len(data) // 2))

    def text(self, desc):
        pointer, count, capacity = struct.unpack('<QII', bytes(self.uc.mem_read(desc, 16)))
        if count == 0:
            return ''
        if not 1 <= count <= capacity <= 4096:
            raise ValueError('Lifecycle FString fixture bound')
        data = bytes(self.uc.mem_read(pointer, count * 2)).decode('utf-16le')
        if not data.endswith('\0'):
            raise ValueError('Lifecycle unterminated FString fixture')
        return data[:-1]

    def hook(self, uc, address, size, user):
        if address in self.allowed:
            return
        a, b, c, d = [uc.reg_read(r) for r in
                       (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        result = 0
        if address == 0x1414313d0:
            old, count, capacity = struct.unpack('<QII', bytes(uc.mem_read(a, 16)))
            new = self.allocate(b * 2)
            uc.mem_write(a, struct.pack('<QII', new, count, b))
        elif address == 0x141431e70:
            old, count, capacity = struct.unpack('<QII', bytes(uc.mem_read(a, 16)))
            new = self.allocate(count * 2)
            if old and capacity:
                uc.mem_write(new, bytes(uc.mem_read(old, min(count, capacity) * 2)))
            uc.mem_write(a, struct.pack('<QII', new, count, count))
        elif address == 0x1487a2e19:
            if not 0 <= c <= 8192:
                raise ValueError('Lifecycle memcpy fixture bound')
            uc.mem_write(a, bytes(uc.mem_read(b, c)))
            result = a
        elif address in (0x14147d580, 0x148796040):
            pass
        elif address == 0x141424870:
            self.string(a, bytes(uc.mem_read(b, c * 2)).decode('utf-16le'))
            result = a
        elif address == 0x141420cc0:
            self.string(a, self.text(b))
            result = a
        elif address == 0x1415c59c0:
            path = [self.text(p) for p in (a, b, c)]
            self.string(d, self.fixture.get('stored', ''))
            result = int(self.fixture.get('read_ok', True))
            self.events.append(dict(action='stored_read_fixture', path=path, returned=result))
        elif address == 0x14155abf0:
            words = self.fixture.get('parsed_words', WORDS)
            uc.mem_write(b, struct.pack('<IIII', *words))
            result = int(self.fixture.get('parse_ok', True))
            self.events.append(dict(action='guid_parse_fixture', input=self.text(a), returned=result, words=list(words)))
        elif address == 0x1415bf470:
            result = self.fixture.get('guid_hresult', 0)
            if result == 0:
                uc.mem_write(a, struct.pack('<IIII', *WORDS))
            self.events.append(dict(action='CoCreateGuid_fixture', returned=result))
        elif address == 0x1415d1990:
            result = int(self.fixture.get('write_ok', True))
            self.events.append(dict(action='stored_write_capture', path=[self.text(p) for p in (a, b, c)],
                                    value=self.text(d), returned=result))
        elif address in (0x14452f230, 0x14452f170):
            self.string(b, 'store-fixture' if address == 0x14452f230 else 'game-fixture')
            result = b
        elif address == 0x14454b390:
            value = self.text(b)
            self.string(a + 0x618, value)
            self.events.append(dict(action='SetDeviceKey_capture', value=value, flag=bool(c)))
        elif address == 0x14453cdf0:
            result = int(self.fixture.get('save_ok', True))
            self.events.append(dict(action='Save_capture', returned=result))
        else:
            raise ValueError('Unexpected lifecycle execution at ' + hex(address))
        uc.reg_write(x.UC_X86_REG_RAX, result)
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def nm(self):
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP, self.stack)
        self.uc.reg_write(x.UC_X86_REG_RCX, self.output)
        self.uc.emu_start(0x1444e5ff0, self.stop, count=10000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop:
            raise ValueError('NM getter instruction budget exceeded')
        return self.text(self.output)

    def device(self):
        rbp = self.stack + 0x100
        for register, value in ((x.UC_X86_REG_RBP, rbp), (x.UC_X86_REG_RSP, rbp - 0x50),
                                (x.UC_X86_REG_RSI, self.settings), (x.UC_X86_REG_RDI, self.output),
                                (x.UC_X86_REG_RBX, 0), (x.UC_X86_REG_R13, int(self.fixture['save_flag'])),
                                (x.UC_X86_REG_R15, self.fixture['platform'])):
            self.uc.reg_write(register, value)
        self.uc.emu_start(0x144522904, 0x144522aa9, count=10000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != 0x144522aa9:
            raise ValueError('Device getter slice instruction budget exceeded')
        return self.text(self.output)


def build():
    path = guid.source.config.native.ROOT / 'code-clues/headless-device-identity.json'
    report = json.loads(path.read_text('utf-8'))
    raw = Path(report['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != report['sha256']:
        raise ValueError('Device lifecycle EXE changed')
    image = guid.source.config.native.Image(raw)
    nm_fixtures = [dict(name='cached', cache='cache-fixture'),
                   dict(name='stored-original', stored='original-case-fixture'),
                   dict(name='parse-failure', stored='invalid-fixture', parse_ok=False),
                   dict(name='zero-guid', stored='0' * 32, parsed_words=[0, 0, 0, 0]),
                   dict(name='write-failure', stored='', parse_ok=False, write_ok=False),
                   dict(name='read-failure', stored='', parse_ok=False, read_ok=False),
                   dict(name='read-failure-value', stored='retained-value-fixture', read_ok=False),
                   dict(name='guid-failure', stored='', parse_ok=False, guid_hresult=0x80004005)]
    cases = []
    for fixture in nm_fixtures:
        replay = Replay(raw, image, report, fixture)
        first = replay.nm()
        boundary = len(replay.events)
        second = replay.nm()
        cases.append(dict(fixture=fixture, first=first, second=second,
                          first_events=replay.events[:boundary], second_events=replay.events[boundary:]))
    device_cases = []
    for platform in (3, 1):
        for state in ('stored', 'settings', 'new'):
            for flag in (False, True):
                fixture = dict(platform=platform, save_flag=flag, state=state, save_ok=False,
                               stored='stored-device-fixture' if state == 'stored' else '',
                               settings='settings-device-fixture' if state == 'settings' else '')
                replay = Replay(raw, image, report, fixture)
                device_cases.append(dict(fixture=fixture, output=replay.device(), events=replay.events))
    return dict(schema_version=1, source=report['source'], sha256=report['sha256'],
                evidence_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                nm_cases=cases, device_cases=device_cases, user_identity_read=False,
                limitations=[
                    'Full NM getter with verbose logs disabled; DeviceKey getter slice 144522904..144522aa9 only.',
                    'GUID constructor, default formatter and hex writer execute native code; CoCreateGuid is a fixture.',
                    'GUID parser and StoredValue calls are fixtures/captures; parser does not validate the synthetic text.',
                    'FString allocation/copy/assign, memcpy/free and security check are fixtures/captures.',
                    'DeviceKey platform and store/section are fixtures; SetDeviceKey updates fixture settings only, Save captured.',
                    'No registry, Saved, live process or network used; real identity and server confirmation remain open.'])


if __name__ == '__main__':
    report = build()
    path = guid.source.config.native.ROOT / 'code-clues/device-key-lifecycle-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                          nm_cases=len(report['nm_cases']), device_cases=len(report['device_cases']))))
