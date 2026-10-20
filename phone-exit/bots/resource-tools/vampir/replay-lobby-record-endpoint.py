"""Native master record copy slice -> BeginGame lookup -> endpoint capture."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lobby_endpoint_connect', HERE / 'replay-game-connect-target.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.x
START, END = 0x145d4b625, 0x145d4b6cf


class Replay(base.Replay):
    def __init__(self, raw, image, fragments, spans, fixture, wire_record):
        super().__init__(raw, image, fragments, spans, fixture)
        self.copying = True
        rows = [r for f in fragments for r in f['instructions'] if START <= r['address'] < END]
        if not rows or rows[0]['address'] != START or rows[-1]['address'] + len(bytes.fromhex(rows[-1]['bytes'])) != END:
            raise ValueError('Native server copy boundaries changed')
        self.allowed.update(r['address'] for r in rows)
        pages = {a & ~4095 for r in rows for a in (r['address'], r['address'] + len(bytes.fromhex(r['bytes'])) - 1)}
        pages.add(0x1415181e0 & ~4095)
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            off = image.offset(page - image.pe.base)
            self.uc.mem_write(page, raw[off:off + 4096])
        source = self.allocate(0x70)
        self.source = source
        self.uc.mem_write(source + 8, struct.pack('<II', wire_record['group_id'], wire_record['server_id']))
        for offset, text in ((0x10, wire_record['name']), (0x20, wire_record['host']), (0x38, 'extra-fixture')):
            self.string(source + offset, text)
        self.uc.mem_write(source + 0x30, struct.pack('<HH', wire_record['port'], wire_record['other_port']))
        self.uc.mem_write(source + 0x34, bytes([6, 5]))
        self.uc.mem_write(source + 0x48, bytes([0, 1, 1, 0]))
        self.uc.mem_write(source + 0x4c, struct.pack('<I', 207))
        self.uc.mem_write(source + 0x60, bytes([22]))
        self.uc.mem_write(source + 0x64, struct.pack('<I', 0xffffffff))
        self.uc.mem_write(source + 0x68, b'\x01')
        # Master map topology/key are fixtures; actual copy writes the value.
        self.entry = int.from_bytes(self.uc.mem_read(self.master + 0x88, 8), 'little')
        self.uc.mem_write(self.entry + 8, bytes(0x70))

    def hook(self, uc, address, size, user):
        if getattr(self, 'copying', False) and address == 0x1415181e0:
            a, b = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX)]
            if a != self.entry + 8 + 0x50 or b != self.source + 0x50:
                raise ValueError('Nested array copy arguments changed')
            # Empty array fixture only. Native allocation/copy ownership excluded.
            uc.mem_write(a, bytes(16))
            rsp = uc.reg_read(x.UC_X86_REG_RSP)
            uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(rsp, 8), 'little'))
            uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
            return
        return super().hook(uc, address, size, user)

    def capture(self):
        for reg, value in ((x.UC_X86_REG_RCX, self.entry), (x.UC_X86_REG_R15, self.source),
                (x.UC_X86_REG_RSP, self.stack)):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(START, END, count=4096)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != END: raise ValueError('Native copy instruction budget')
        value = self.entry + 8
        copied = dict(ids=list(struct.unpack('<II', bytes(self.uc.mem_read(value + 8, 8)))),
            name=self.text(value + 0x10), host=self.text(value + 0x20),
            ports=list(struct.unpack('<HH', bytes(self.uc.mem_read(value + 0x30, 4)))))
        self.copying = False
        result = super().capture()
        result['copied_record'] = copied
        return result


def build():
    path = native.ROOT / 'code-clues/game-connect-target-replay.json'
    prior = json.loads(path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    update = native.decode_ranges(image, {image.roots[image.containing(START)]})
    rows = {r['address']: r for f in update for r in f['instructions']}
    if rows[0x145d4b585]['operands'] != 'r8d, dword ptr [r15 + 0xc]':
        raise ValueError('Master server key source changed')
    cases = []
    for server_id in (42, 207):
        for host in ('game.invalid', 'long-server-host-for-connect.invalid'):
            for port in (12001, 32767, 32768, 65535):
                record = dict(group_id=7, server_id=server_id, name='server-fixture', host=host, port=port, other_port=23456)
                fixture = dict(last_id=server_id, invalid_id=0xffffffff, fallback_id=server_id, busy=False,
                    records=[dict(id=server_id, text='old.invalid', word_30=1, word_32=2)],
                    override_text='', override_port=0, connect_disabled=False, connect_result=True)
                result = Replay(raw, image, prior['fragments'] + update, prior['spans'], fixture, record).capture()
                if (result['target_id'], result['target_text'], result['target_words']) != (server_id, host, [port, 23456]):
                    raise ValueError('Copied lobby record did not reach game target')
                cases.append(dict(source_record=record, result=result))
    return dict(schema_version=1, source=prior['source'], source_sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        dependency_sha256=hashlib.sha256((HERE / 'replay-game-connect-target.py').read_bytes()).hexdigest(),
        update_fragments=update, key_source=rows[0x145d4b585], copy_start=START, copy_end=END, cases=cases,
        limitations=['Actual master record copy slice followed by native BeginGame lookup/setters and ConnectToServer on same fixture objects.',
            'Map key/topology/last selection are fixtures; full master Update guards/insertion are not executed.',
            'String assignment, empty nested array copy and lower socket connect are fixtures/captures.',
            'Source record represents decoder layout but native ID104 reader is not chained in this replay. No live game connection.'])


if __name__ == '__main__':
    report = build()
    output = native.ROOT / 'code-clues/lobby-record-endpoint-replay.json'
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(output), sha256=hashlib.sha256(output.read_bytes()).hexdigest(), cases=len(report['cases']))))
