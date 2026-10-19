"""Execute compiled OnResult validation/adoption slice with explicit map/SDK shims."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('nid_validation_bootstrap', HERE / 'build-headless-sdk-bootstrap-values.py')
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)
START, END = 0x1450ee94a, 0x1450ef437
REJECTIONS = {0x1450ee98c: 'missing_resultCode', 0x1450eeaeb: 'empty_resultCode',
    0x1450ef57e: 'invalid_or_nonzero_result', 0x1450eecc8: 'empty_accessToken',
    0x1450eee80: 'empty_channelKey', 0x1450eefd2: 'unknown_channel',
    0x1450ef12a: 'empty_netmarbleId', 0x1450ef281: 'empty_joinedCountryCode',
    0x1450ef571: 'auth_type_gate'}


class Replay:
    def __init__(self, raw, image, fragments, bindings):
        ping = bootstrap.settings.ping
        self.x = ping.x
        self.uc = ping.unicorn.Uc(ping.unicorn.UC_ARCH_X86, ping.unicorn.UC_MODE_64)
        self.base, self.stack = 0x20000000, 0x20070000
        self.uc.mem_map(self.base, 0x80000)
        self.cursor = self.base + 0x10000
        self.rbp = self.stack + 0x100
        self.owner, self.settings = self.base + 0x2000, self.base + 0x3000
        self.rows = self.base + 0x4000
        self.events, self.lookups, self.outcome = [], [], None
        self.allowed = {r['address'] for f in fragments for r in f['instructions']
                        if START <= r['address'] <= END or f['root_begin_rva'] == 0x1420cc0}
        self.hooks = {0x141420380, 0x141437e50, 0x141420cc0, 0x1415dea40,
            0x1414313d0, 0x1487a2e19, 0x14452b060, 0x1444aacb0,
            0x14454a480, 0x141424870, 0x14454ba20, 0x14454a870, 0x14454c470}
        pages = {a & ~4095 for a in self.allowed | self.hooks | set(REJECTIONS)}
        pages.update(a & ~4095 for f in fragments for r in f['instructions']
                     if r['address'] in self.allowed for a in r['rip_references'])
        for page in sorted(pages):
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.names = {r['global_address']: r['source']['text'] for r in bindings}
        for address, text in self.names.items():
            self.string(address, text)
        self.uc.hook_add(ping.unicorn.UC_HOOK_CODE, self.hook)
        self.uc.hook_add(ping.unicorn.UC_HOOK_MEM_INVALID, self.invalid_memory)

    def invalid_memory(self, uc, access, address, size, value, user):
        if address < 4096:
            self.outcome = 'unmapped_null_access'
            self.events.append(dict(kind='unmapped_null_access', address=address, size=size,
                                    instruction=uc.reg_read(self.x.UC_X86_REG_RIP)))
        return False

    def allocate(self, size):
        if not 0 < size <= 4096 or self.cursor + size >= self.base + 0x60000:
            raise ValueError('NID replay allocation exceeds fixture budget')
        result = self.cursor
        self.cursor += (size + 15) & ~15
        return result

    def string(self, descriptor, text):
        payload = (text + '\0').encode('utf-16le')
        pointer = self.allocate(len(payload))
        self.uc.mem_write(pointer, payload)
        self.uc.mem_write(descriptor, struct.pack('<QII', pointer, len(payload) // 2, len(payload) // 2))

    def text(self, descriptor):
        pointer, count, capacity = struct.unpack('<QII', bytes(self.uc.mem_read(descriptor, 16)))
        if count == 0:
            return ''
        if not 1 <= count <= capacity <= 2048 or not self.base <= pointer < self.base + 0x60000 - count * 2:
            raise ValueError('NID replay string outside fixture bounds')
        payload = bytes(self.uc.mem_read(pointer, count * 2))
        if not payload.endswith(b'\0\0'):
            raise ValueError('Unterminated NID replay string')
        return payload[:-2].decode('utf-16le')

    def hook(self, uc, address, size, user):
        if address in REJECTIONS:
            self.outcome = REJECTIONS[address]
            uc.emu_stop()
            return
        if address == END:
            self.outcome = 'adoption_calls_reached'
            uc.emu_stop()
            return
        if address in self.allowed:
            return
        if address not in self.hooks:
            raise ValueError('Unreviewed NID replay target ' + hex(address))
        x = self.x
        a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        result = 0
        if address == 0x141420380:
            result = 0  # Hash fixture; actual lookup keyed by explicit descriptor below.
        elif address == 0x141437e50:
            if a != self.rbp + 0x170 or c not in self.names:
                raise ValueError('Unexpected map lookup arguments')
            key = self.names[c]
            self.lookups.append(key)
            result = self.indices.get(key, 0xffffffff)
        elif address == 0x1415dea40:
            uc.mem_write(a, struct.pack('<i', self.parsed_value))
            result = int(self.parse_ok)
            self.events.append(dict(kind='integer_parser_return_fixture', ok=self.parse_ok, value=self.parsed_value))
        elif address == 0x1414313d0:
            if not 1 <= b <= 2048:
                raise ValueError('String allocation fixture exceeds budget')
            uc.mem_write(a, struct.pack('<Q', self.allocate(b * 2)))
            uc.mem_write(a + 12, struct.pack('<I', b))
        elif address == 0x1487a2e19:
            if not 0 < c <= 4096 or not all(self.base <= p < self.base + 0x60000 - c for p in (a, b)):
                raise ValueError('Copy fixture outside bounds')
            uc.mem_write(a, bytes(uc.mem_read(b, c)))
            result = a
        elif address == 0x14452b060:
            uc.mem_write(a, bytes([self.channel]))
            result = a
            self.events.append(dict(kind='channel_mapper_return_fixture', value=self.channel))
        elif address == 0x1444aacb0:
            result = self.base + 0x5000
            uc.mem_write(result + 0x110, struct.pack('<Q', self.settings))
        elif address in (0x14454a480, 0x14454ba20, 0x14454c470):
            if a != self.settings:
                raise ValueError('Unexpected settings receiver')
            self.events.append(dict(kind='settings_call_capture', target=address, value=self.text(b), r8=c))
        elif address == 0x14454a870:
            self.events.append(dict(kind='channel_settings_capture', value=b & 255))
        elif address == 0x141424870:
            if a != self.settings + 0xb0:
                raise ValueError('Unexpected settings string destination')
            descriptor = self.base + 0x6000
            uc.mem_write(descriptor, struct.pack('<QII', b, c + 1, c + 1))
            self.events.append(dict(kind='country_assignment_capture', value=self.text(descriptor)))
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        return_address = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, return_address)

    def run(self, fields, parse_ok=True, parsed_value=0, channel=20, auth_type=0):
        self.indices = {key: n for n, key in enumerate(fields)}
        for key, n in self.indices.items():
            self.string(self.rows + n * 40 + 16, fields[key])
        self.uc.mem_write(self.rbp + 0x170, struct.pack('<Q', self.rows))
        self.uc.mem_write(self.owner + 0x150, struct.pack('<I', auth_type))
        self.parse_ok, self.parsed_value, self.channel = parse_ok, parsed_value, channel
        empty = self.base + 0x7000
        self.string(empty, '')
        empty_pointer = struct.unpack('<Q', bytes(self.uc.mem_read(empty, 8)))[0]
        for name, value in dict(rsp=self.stack, rbp=self.rbp, r15=self.owner, rdi=empty_pointer,
                                rsi=0, r12=0, rbx=0).items():
            self.uc.reg_write(getattr(self.x, 'UC_X86_REG_' + name.upper()), value)
        try:
            self.uc.emu_start(START, 0, count=4096)
        except bootstrap.settings.ping.unicorn.UcError:
            if self.outcome != 'unmapped_null_access':
                raise
        if self.outcome is None:
            raise ValueError('NID replay did not reach a reviewed stop')
        return dict(fields=fields, parse_ok=parse_ok, parsed_value=parsed_value, channel=channel,
                    auth_type=auth_type, outcome=self.outcome, lookups=self.lookups, events=self.events)


def build():
    path = bootstrap.native.ROOT / 'code-clues/headless-nid-result.json'
    prior = json.loads(path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('NID validation source changed')
    image = bootstrap.native.Image(raw)
    fragments = bootstrap.native.decode_ranges(image, {image.roots[image.containing(a)] for a in (START, 0x141420cc0)})
    settings_fragments = bootstrap.native.decode_ranges(image, {image.roots[image.containing(a)]
        for a in (0x14454a480, 0x14454ba20, 0x14454a870, 0x14454c470)})
    settings_diagnostics = []
    for fragment in settings_fragments:
        for row in fragment['instructions']:
            if row['mnemonic'] == 'lea':
                for address in row['rip_references']:
                    literal = bootstrap.settings.config.read_literal(raw, image, address)
                    if literal and 'UNMServiceSettings::' in literal['text']:
                        settings_diagnostics.append(dict(instruction=row['address'], **literal))
    fields = dict(resultCode='0', accessToken='access-fixture', refreshToken='refresh-fixture',
                  channelKey='mailUserKey', netmarbleId='user-fixture', joinedCountryCode='UA')
    fixtures = [dict(name='complete', fields=fields)]
    for key in fields:
        fixtures.extend([dict(name='missing_' + key, fields={k: v for k, v in fields.items() if k != key}),
                         dict(name='empty_' + key, fields={**fields, key: ''})])
    fixtures.extend([dict(name='parse_failure', fields={**fields, 'resultCode': 'bad'}, parse_ok=False),
        dict(name='nonzero_result', fields={**fields, 'resultCode': '200'}, parsed_value=200),
        dict(name='unknown_channel', fields=fields, channel=0)])
    fixtures.extend(dict(name='auth_type_' + str(n), fields=fields, auth_type=n) for n in (1, 2, 4, 5, 6, 255))
    cases = []
    for fixture in fixtures:
        options = dict(fixture)
        name = options.pop('name')
        replay = Replay(raw, image, fragments, prior['bindings'])
        try:
            result = replay.run(**options)
        except Exception as error:
            raise ValueError('NID fixture ' + name + ' failed at ' + hex(replay.uc.reg_read(replay.x.UC_X86_REG_RIP))) from error
        cases.append(dict(name=name, **result))
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        source_index_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        start=START, stop=END, fragments=fragments, cases=cases, network_ready=False,
        settings_fragments_static=settings_fragments, settings_diagnostics=settings_diagnostics,
        limitations=['Actual OnResult validation/adoption caller instructions only; entry service/query parsing bypassed.',
            'FString copy constructor executed; hash/map lookup, allocation/memcpy, integer parser, channel mapper and settings getters are explicit shims.',
            'Integer/channel return fixtures prove caller gates, not accepted number syntax or channel enum value.',
            'Settings calls/country assignment captured, setters and persistence not executed.',
            'Stops before post-adoption callback; no real token, account, network, game session or Android verification.'])


if __name__ == '__main__':
    report = build()
    path = bootstrap.native.ROOT / 'code-clues/nid-result-validation-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                         cases=len(report['cases'])), indent=2))
