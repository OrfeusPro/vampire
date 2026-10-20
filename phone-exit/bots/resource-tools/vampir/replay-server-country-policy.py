"""Native SDK field slice -> real country setter/getters -> full server predicate."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('country_response', HERE / 'replay-sdk-sign-in-response-fields.py')
response = importlib.util.module_from_spec(spec)
spec.loader.exec_module(response)
native, x, unicorn = response.native, response.x, response.lifecycle.unicorn
SET, GET, SETTINGS_GET, PREDICATE = 0x14454b8c0, 0x1456048f0, 0x1445242f0, 0x145d3b1b0


class Replay(response.Replay):
    def __init__(self, raw, image, base_report, prior, extra, spans, fixture):
        body = dict(resultData=dict(accessToken='token-fixture', playerInfo=dict(player=dict(
            playerId='player-fixture', joinedCountryCode=fixture['sdk_country'], gameRegion='region-fixture'))))
        super().__init__(raw, image, base_report, prior['fragments'], prior['constructor_leaf'],
                         dict(status=200, body=body))
        self.country_fixture = fixture
        rows = [r for f in extra for r in f['instructions']] + [r for f in spans for r in f['instructions']]
        self.allowed.update(r['address'] for r in rows)
        pages = {a & ~4095 for r in rows for a in
                 (r['address'], r['address'] + len(bytes.fromhex(r['bytes'])) - 1, *r['rip_references'])}
        pages.update(a & ~4095 for a in (0x14143c260, 0x1456048a0, 0x1444aab90, 0x1416aaaf0))
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            try: off = image.offset(page - image.pe.base)
            except ValueError: continue
            self.uc.mem_write(page, raw[off:off + 4096])
        # The older response harness calls this fixture object "module".
        # Keep the setter target and singleton-returned player the same object.
        self.player = self.module
        self.manager, self.container, self.master = (self.allocate(n) for n in (0x100, 0x200, 0x400))
        self.uc.mem_write(self.callback + 0x18, struct.pack('<Q', self.player))
        self.string(self.player + 0x210, 'old-country-fixture')
        self.uc.mem_write(self.manager + 0x38, struct.pack('<Q', self.player if fixture.get('manager_player', True) else 0))
        self.uc.mem_write(self.container + 0x110, struct.pack('<Q', self.player if fixture.get('sdk_player', True) else 0))
        self.uc.mem_write(0x14b520cc3, bytes([fixture.get('sdk_enabled', True)]))
        self.string(0x14b520d60, fixture.get('fallback', 'JP'))
        entry, bucket = self.allocate(128), self.allocate(16)
        self.uc.mem_write(self.master + 0x88, struct.pack('<Q', entry))
        count = int(fixture.get('record_present', True))
        self.uc.mem_write(self.master + 0x90, struct.pack('<I', count))
        self.uc.mem_write(self.master + 0xc8, struct.pack('<Q', bucket))
        self.uc.mem_write(self.master + 0xd0, struct.pack('<I', 1))
        self.uc.mem_write(bucket, struct.pack('<i', 0 if count else -1))
        self.uc.mem_write(entry, struct.pack('<I', 251))
        self.uc.mem_write(entry + 0x78, struct.pack('<i', -1))
        values = fixture['countries']
        array = self.allocate(max(16, len(values) * 16))
        for n, value in enumerate(values): self.string(array + n * 16, value)
        self.uc.mem_write(entry + 8 + 0x50, struct.pack('<QII', array, len(values), len(values)))

    def hook(self, uc, address, size, user):
        if address in self.allowed: return
        a, b = (uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX))
        if address == 0x14143c260:
            self.string(a, self.text(b))
            result = a
        elif address == 0x1456048a0:
            result = self.manager if self.country_fixture.get('manager_present', True) else 0
        elif address == 0x1444aab90:
            result = self.container
        elif address == 0x1416aaaf0:
            result = 0  # Explicit fixture: lazy initialization leaves the player absent.
        else:
            return super().hook(uc, address, size, user)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def capture(self):
        fields = super().capture()
        if fields['stage'] != 'player_fields_processed': raise ValueError('SDK country slice incomplete')
        if self.text(self.player + 0x210) != self.country_fixture['sdk_country']:
            raise ValueError('Actual SDK setter did not update the getter field')
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP, self.stack)
        self.uc.reg_write(x.UC_X86_REG_RCX, self.master)
        self.uc.reg_write(x.UC_X86_REG_RDX, 251)
        self.uc.emu_start(PREDICATE, self.stop, count=4096)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop:
            raise ValueError('Server country predicate instruction budget')
        accepted = bool(self.uc.reg_read(x.UC_X86_REG_RAX) & 0xff)
        f = self.country_fixture
        sdk = f.get('sdk_enabled', True) and f.get('manager_present', True) and f.get('manager_player', True)
        compared = (f['sdk_country'] if f.get('sdk_player', True) else '') if sdk else f.get('fallback', 'JP')
        expected = f.get('record_present', True) and (not f['countries'] or compared.lower() in [v.lower() for v in f['countries']])
        if accepted != expected: raise ValueError('Native country predicate differs from independent model')
        return dict(fixture=f, country_after_setter=self.text(self.player + 0x210), compared=compared, accepted=accepted)


def build():
    paths = [native.ROOT / 'code-clues' / n for n in
             ('sdk-sign-in-response-fields-replay.json', 'headless-device-identity.json', 'begin-game-server-target-replay.json')]
    prior, base_report, target = [json.loads(p.read_text('utf-8')) for p in paths]
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    extra = native.decode_ranges(image, {image.roots[image.containing(a)] for a in (SET, GET, SETTINGS_GET, PREDICATE)})
    lookup = next(s for s in target['spans'] if s['address'] == 0x145d39440)
    manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
    compare = next(f for f in manifest['functions'] if f['name'] == 'WorldMoveStart_CompareLevelPath')
    span = compare['ranges'][0]
    address = int(span['start'], 16)
    data = raw[span['file_offset']:span['file_offset'] + int(span['end_exclusive'], 16) - address]
    cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    cs.detail = True
    rows = []
    for r in cs.disasm(data, address):
        refs = [r.address + r.size + op.mem.disp for op in r.operands
                if op.type == native.capstone.x86_const.X86_OP_MEM and op.mem.base == native.capstone.x86_const.X86_REG_RIP]
        rows.append(dict(address=r.address, bytes=r.bytes.hex(), mnemonic=r.mnemonic, operands=r.op_str, rip_references=refs))
    if sum(len(bytes.fromhex(r['bytes'])) for r in rows) != len(data): raise ValueError('Comparison decode incomplete')
    spans = [lookup, dict(address=address, file_offset=span['file_offset'], bytes=data.hex(), instructions=rows)]
    for s in spans:
        b = bytes.fromhex(s['bytes'])
        if raw[s['file_offset']:s['file_offset'] + len(b)] != b: raise ValueError('Native span changed')
    common = dict(sdk_country='HK', countries=['KR', 'TW', 'HK', 'MO', 'JP'])
    fixtures = [dict(common, name='hk-five-countries'), dict(common, name='hk-only', countries=['HK']),
                dict(common, name='denied', countries=['JP']), dict(common, name='second-match', countries=['JP', 'HK']),
                dict(common, name='lowercase-sdk', sdk_country='hk'), dict(common, name='lowercase-list', countries=['hk']),
                dict(common, name='empty-country', sdk_country=''), dict(common, name='empty-member', countries=['']),
                dict(common, name='both-empty', sdk_country='', countries=['']), dict(common, name='empty-list', countries=[]),
                dict(common, name='absent-record', record_present=False),
                dict(common, name='sdk-disabled', sdk_enabled=False, countries=['HK']),
                dict(common, name='absent-manager', manager_present=False, countries=['HK']),
                dict(common, name='absent-manager-player', manager_player=False, countries=['HK']),
                dict(common, name='absent-sdk-player', sdk_player=False, countries=['HK'])]
    return dict(source=prior['source'], source_sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                upstream={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
                fragments=extra, spans=spans,
                cases=[Replay(raw, image, base_report, prior, extra, spans, f).capture() for f in fixtures],
                limitations=['SDK response constructor/field traversal slice, actual country setter, full predicate/getter chain, lookup and comparison execute.',
                             'JSON/FString memory helpers and singleton objects are fixtures; setter bool=false matches response caller.',
                             'Fallback country is an explicit fixture, not a recovered global initializer; logging disabled.',
                             'Full response/errorCode/SDK callback and full ServerList_Update not executed here.',
                             'Synthetic countries only; no game launch, process memory, credentials, persistence or network.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/server-country-policy-replay.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
