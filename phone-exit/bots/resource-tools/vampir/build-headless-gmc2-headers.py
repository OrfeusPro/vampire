"""Native RequestGMC2 argument/conditional header capture, no HTTP or accounts."""
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('gmc2_header_url', HERE / 'build-headless-gmc2-url.py')
url = importlib.util.module_from_spec(spec)
spec.loader.exec_module(url)
START, STOP = 0x1444f5560, 0x1444f57b1
CTOR_START, CTOR_STOP = 0x1444bd970, 0x1444bda2e
ASCII_STRING = 0x141420f70
DEVICE, PLAYER = 0x1444e5ff0, 0x144524d80
SET_URL, SET_HEADER, SET_METHOD = 0x2003d000, 0x2003d010, 0x2003d020


class Emulator(url.Emulator):
    def __init__(self, raw, image, fragments):
        super().__init__(raw, image, fragments)
        self.allowed += [(START, STOP), (CTOR_START, CTOR_STOP)]
        pages = {a & ~4095 for a in (ASCII_STRING, DEVICE, PLAYER, 0x1444aab90, 0x1444aacb0)}
        pages.add((DEVICE & ~4095) + 4096)
        pages.update(a & ~4095 for lo, hi in ((START, STOP), (CTOR_START, CTOR_STOP))
                     for a in range(lo, hi + 4095, 4096))
        for f in fragments:
            for row in f['instructions']:
                if START <= row['address'] < STOP or CTOR_START <= row['address'] < CTOR_STOP:
                    pages.update(a & ~4095 for a in row['rip_references'])
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset + 4096])

    def text(self, address):
        pointer, count, capacity = struct.unpack('<QII', bytes(self.uc.mem_read(address, 16)))
        if not 0 <= count <= capacity <= 2048:
            raise ValueError('Header FString fixture bounds exceeded')
        if count == 0:
            return ''
        if not self.scratch <= pointer <= self.scratch + 0x40000 - count * 2:
            raise ValueError('Header fixture outside scratch')
        payload = bytes(self.uc.mem_read(pointer, count * 2))
        if not payload.endswith(b'\0\0'):
            raise ValueError('Unterminated header fixture')
        return payload[:-2].decode('utf-16le')

    def hook(self, machine, address, size, user):
        if any(lo <= address < hi for lo, hi in self.allowed):
            return
        x = self.x
        a, b, c = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        result = machine.reg_read(x.UC_X86_REG_RAX)
        if address == ASCII_STRING:
            literal = url.values.settings.config.read_literal(self.raw, self.image, b)
            if not literal or literal['encoding'] != 'ascii':
                raise ValueError('Unexpected header ASCII constructor source')
            self.put(a, literal['text'])
            result = a
        elif address in (SET_URL, SET_HEADER, SET_METHOD):
            if a != self.request:
                raise ValueError('Unexpected HTTP object fixture')
            if address == SET_HEADER:
                self.headers.append(dict(name=self.text(b), value=self.text(c)))
            else:
                self.request_values['url' if address == SET_URL else 'method'] = self.text(b)
        elif address == DEVICE:
            self.put(a, self.fixture['device_key'])
            result = a
            self.events.append(dict(kind='device_key_getter_fixture'))
        elif address == PLAYER:
            self.put(b, self.fixture['player_id'])
            result = b
            self.events.append(dict(kind='player_id_getter_fixture'))
        elif address in (0x1444aab90, 0x1444aacb0):
            result = self.scratch + 0x7000
        else:
            return super().hook(machine, address, size, user)
        rsp = machine.reg_read(x.UC_X86_REG_RSP)
        ret = struct.unpack('<Q', bytes(machine.mem_read(rsp, 8)))[0]
        machine.reg_write(x.UC_X86_REG_RAX, result)
        machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(x.UC_X86_REG_RIP, ret)

    def capture(self, fixture):
        self.fixture = fixture
        self.request, manager, settings, account = [self.scratch + o for o in (0x2000, 0x3000, 0x6000, 0x8000)]
        vtable, rbp = self.scratch + 0x1000, self.scratch + 0xa000
        self.uc.mem_write(self.request, struct.pack('<Q', vtable))
        for offset, address in ((0x68, SET_URL), (0xb0, SET_HEADER), (0x60, SET_METHOD)):
            self.uc.mem_write(vtable + offset, struct.pack('<Q', address))
        self.headers, self.request_values = [], {}
        # Stop before the remaining constructor fields/defaults; only names used below.
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(self.x.UC_X86_REG_RSP, self.stack)
        self.uc.reg_write(self.x.UC_X86_REG_RCX, manager)
        self.uc.emu_start(CTOR_START, CTOR_STOP, count=512)
        if self.uc.reg_read(self.x.UC_X86_REG_RIP) != CTOR_STOP:
            raise ValueError('Header constructor instruction budget exceeded')
        for address in url.values.INITIALIZERS:
            self.run(address)
        self.put(settings + 0x38, fixture['game_code'])
        self.uc.mem_write(settings + 0x48, bytes([fixture['build_code']]))
        self.put(account + 0x78, fixture['access_token'])
        self.uc.mem_write(self.scratch + 0x5000 + 0x110, struct.pack('<Q', settings))
        self.uc.mem_write(self.scratch + 0x7000 + 0x110, struct.pack('<Q', account))
        url_string, service, etag = self.scratch + 0x9000, self.scratch + 0x9100, self.scratch + 0x9200
        self.put(url_string, fixture['url'])
        self.put(service, fixture['service_code'])
        self.put(etag, fixture['etag'])
        self.events = []
        self.uc.mem_write(self.stack + 0x38, struct.pack('<Q', self.request))
        self.uc.mem_write(self.stack + 0x60, struct.pack('<Q', service))
        for reg, value in ((self.x.UC_X86_REG_RSP, self.stack), (self.x.UC_X86_REG_RBP, rbp),
            (self.x.UC_X86_REG_R14, manager), (self.x.UC_X86_REG_R12, etag), (self.x.UC_X86_REG_RDI, url_string)):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(START, STOP, count=4096)
        if self.uc.reg_read(self.x.UC_X86_REG_RIP) != STOP:
            raise ValueError('Header slice instruction budget exceeded')
        return dict(fixture=fixture, request=self.request_values, headers=self.headers,
                    calls=self.events, network_used=False)


def build():
    prior_path = url.values.native.ROOT / 'code-clues/headless-sdk-config.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('GMC2 header source changed')
    image = url.values.native.Image(raw)
    fragments = url.values.native.decode_ranges(image, {image.roots[image.containing(a)] for a in
        (START, CTOR_START, DEVICE, PLAYER, url.values.BUILD, *url.values.INITIALIZERS)})
    cases = []
    for code, etag, token in itertools.product((0, 1, 2, 255), ('', 'etag-fixture'), ('', 'token-fixture')):
        fixture = dict(url='https://config.invalid/request', service_code='service-fixture', game_code='game-fixture',
            build_code=code, etag=etag, access_token=token, player_id='player-fixture', device_key='device-fixture')
        cases.append(Emulator(raw, image, fragments).capture(fixture))
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), fragments=fragments,
        start=START, stop=STOP, cases=cases, active_values_verified=False, network_ready=False,
        limitations=['Native constructor prefix/RequestGMC2 header slice/build getter/initializers executed.',
            'FString/heap/copy/free/singletons/device key/player id and HTTP vtable calls are explicit fixtures/capture shims.',
            'HTTP request creation/serialization/transport/callback/response and active settings are not executed.',
            'All session/device values are synthetic; no account files, secrets or network used.'])


if __name__ == '__main__':
    report = build()
    target = url.values.native.ROOT / 'code-clues/headless-gmc2-headers.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(), cases=len(report['cases'])), indent=2))
