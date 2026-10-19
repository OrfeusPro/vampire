"""Native SDK response field traversal with explicit JSON/settings fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('signin_response_lifecycle', HERE / 'replay-device-key-lifecycle.py')
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)
native, x = lifecycle.guid.source.config.native, lifecycle.x
BEGIN, END = 0x1444cc725, 0x1444ccb55
STOPS = {0x1444ccd5f: 'http_outside_200_206', 0x1444ccc62: 'no_resultData',
         0x1444ccc4e: 'no_playerInfo', 0x1444ccb61: 'no_player'}


class Replay(lifecycle.Replay):
    def __init__(self, raw, image, base_report, fragments, ctor, fixture):
        super().__init__(raw, image, base_report, {})
        self.response_fixture = fixture
        self.objects = {}
        self.response_events = []
        rows = [r for f in fragments for r in f['instructions'] if
                f['root_begin_rva'] < 0x2000000 or BEGIN <= r['address'] < END]
        self.allowed.update(r['address'] for r in rows)
        cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
        self.allowed.update(i.address for i in cs.disasm(bytes.fromhex(ctor['bytes']), ctor['address']))
        self.allowed.update(STOPS)
        pages = {r['address'] & ~4095 for r in rows}
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        pages.update(a & ~4095 for a in (*STOPS, ctor['address'], ctor['address'] + len(bytes.fromhex(ctor['bytes'])),
            *ctor['rip_references'], 0x141421150, 0x144524d80, 0x144477400, 0x144476670,
            0x1444768c0, 0x1444bb470, 0x141421d80, 0x14454bc50, 0x14453cdf0,
            0x14452bde0, 0x14454b8c0, 0x1445280c0, 0x1444f0c20, 0x14446fa60))
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.callback, self.auth, self.module = self.base + 0x9000, self.base + 0xa000, self.base + 0xb000
        self.uc.mem_write(self.callback, struct.pack('<Q', self.auth))
        self.string(self.module + 0x78, 'old-sdk-token-fixture')
        self.string(self.module + 0x68, 'old-region-fixture')
        self.string(0x14b4f0b70, 'resultData')
        self.string(0x14b4f09e0, 'accessToken')

    def wide(self, pointer):
        data = bytearray()
        for n in range(1024):
            unit = bytes(self.uc.mem_read(pointer + n * 2, 2))
            if unit == b'\0\0':
                return data.decode('utf-16le')
            data.extend(unit)
        raise ValueError('SDK response wide fixture bound')

    def hook(self, uc, address, size, user):
        if address in STOPS:
            uc.emu_stop()
            return
        if address in self.allowed:
            return
        a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        result = 0
        if address == 0x141421150:
            self.string(a, self.wide(b))
            result = a
        elif address == 0x144524d80:
            self.string(b, 'old-player-fixture')
            result = b
        elif address == 0x144477400:
            key = self.text(b)
            result = int(isinstance(self.objects.get(a), dict) and key in self.objects[a])
            self.response_events.append(dict(action='presence_fixture', key=key, returned=bool(result)))
        elif address == 0x144476670:
            value = self.objects.get(a, {}).get(self.text(c))
            if not isinstance(value, dict):
                raise ValueError('SDK response object fixture type mismatch')
            self.objects[b] = value
            result = b
        elif address == 0x1444768c0:
            value = self.objects.get(a, {}).get(self.text(c))
            if not isinstance(value, str):
                raise ValueError('SDK response string fixture type mismatch')
            self.string(b, value)
            result = b
        elif address == 0x1444bb470:
            result = self.module
        elif address == 0x141421d80:
            value = self.text(b)
            self.string(a, value)
            self.response_events.append(dict(action='module_string_assignment_capture', offset=a - self.module, value=value))
            result = a
        elif address in (0x14454bc50, 0x14454b8c0):
            self.response_events.append(dict(action='settings_setter_capture', target=address, value=self.text(b), flag=bool(c)))
        elif address == 0x14453cdf0:
            self.response_events.append(dict(action='Save_capture', returned=False))
        elif address == 0x14452bde0:
            self.response_events.append(dict(action='settings_followup_capture', target=address))
        elif address in (0x1445280c0, 0x1444f0c20):
            value = self.objects.get(b if address == 0x1445280c0 else a)
            self.response_events.append(dict(action='player_status_object_capture', target=address, value=value))
        elif address == 0x14446fa60:
            pass
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
        self.uc.reg_write(x.UC_X86_REG_RCX, self.auth)
        self.uc.emu_start(0x1444bc380, self.stop, count=1024)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop:
            raise ValueError('SDK response auth constructor budget exceeded')
        keys = {hex(offset): self.wide(struct.unpack('<Q', bytes(self.uc.mem_read(self.auth + offset, 8)))[0])
                for offset in range(0x20, 0x58, 8)}
        rbp = self.stack + 0x100
        self.objects[rbp + 0x1a0] = self.response_fixture['body']
        for register, value in ((x.UC_X86_REG_RSP, self.stack), (x.UC_X86_REG_RBP, rbp),
                                (x.UC_X86_REG_RDI, self.callback), (x.UC_X86_REG_RBX, 0),
                                (x.UC_X86_REG_R15, 0), (x.UC_X86_REG_R12, self.response_fixture['status'])):
            self.uc.reg_write(register, value)
        self.uc.emu_start(BEGIN, END, count=8192)
        rip = self.uc.reg_read(x.UC_X86_REG_RIP)
        if rip != END and rip not in STOPS:
            raise ValueError('SDK response field slice budget exceeded')
        return dict(fixture=self.response_fixture, constructor_keys=keys,
                    stage=STOPS.get(rip, 'player_fields_processed'), sdk_access_token=self.text(self.module + 0x78),
                    game_region=self.text(self.module + 0x68), events=self.response_events)


def build():
    root = native.ROOT
    base_report = json.loads((root / 'code-clues/headless-device-identity.json').read_text('utf-8'))
    body_path = root / 'code-clues/sdk-sign-in-body-replay.json'
    prior = json.loads(body_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('SDK sign-in response EXE changed')
    image = native.Image(raw)
    ctor = prior['constructor_leaf']
    if raw[ctor['file_offset']:ctor['file_offset'] + len(bytes.fromhex(ctor['bytes']))] != bytes.fromhex(ctor['bytes']):
        raise ValueError('SDK response constructor source mismatch')
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in
        (0x1444cc1a0, 0x1411b00d0, 0x1411b0310, 0x1411b0580,
         0x14454bc50, 0x14454b8c0, 0x14452bde0)})
    literals = []
    for f in fragments:
        for row in f['instructions']:
            if row['mnemonic'] == 'lea':
                for ref in row['rip_references']:
                    if lit := lifecycle.guid.source.config.read_literal(raw, image, ref):
                        literals.append(dict(instruction=row['address'], **lit))
    fixtures = []
    player = dict(playerId='new-player-fixture', gameRegion='region-fixture', joinedCountryCode='UA',
                  playerStatus={'fixture': 'player-status'})
    full = dict(resultData=dict(accessToken='new-sdk-token-fixture', playerInfo=dict(player=player)))
    for status in (199, 200, 201, 206, 207):
        fixtures.append(dict(name='http-' + str(status), status=status, body=full))
    for missing in ('resultData', 'playerInfo', 'player', 'playerId', 'gameRegion', 'joinedCountryCode', 'playerStatus', 'accessToken'):
        value = json.loads(json.dumps(full))
        if missing == 'resultData':
            value = {}
        elif missing in ('playerInfo', 'accessToken'):
            del value['resultData'][missing]
        elif missing == 'player':
            del value['resultData']['playerInfo']['player']
        else:
            del value['resultData']['playerInfo']['player'][missing]
        fixtures.append(dict(name='missing-' + missing, status=200, body=value))
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                body_report_sha256=hashlib.sha256(body_path.read_bytes()).hexdigest(),
                fragments=fragments, constructor_leaf=ctor, literals=literals,
                cases=[Replay(raw, image, base_report, fragments, ctor, fixture).capture() for fixture in fixtures],
                native_execution=True, network_ready=False, limitations=[
                    'Auth constructor and native response HTTP range/resultData/playerInfo/player field traversal slices execute.',
                    'JSON presence/object/string operations, settings getters/setters, module writes and Save are fixtures/captures.',
                    'Slice begins after JSON/errorCode handling and stops before full callback completion; stage is not login success.',
                    'Wrong JSON types, errorCode numeric conversion, remaining response fields and final game session are not validated here.',
                    'No auth POST, live tokens, accounts, storage or network used.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/sdk-sign-in-response-fields-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
