"""Native migration allocation wrappers with explicit quantize/realloc backend."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('migration_allocation_source', HERE / 'replay-sdk-channel-migration-path.py')
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)
native, x = migration.native, migration.x


class Replay(migration.Replay):
    def __init__(self, raw, image, base_report, prior, evidence, fixture):
        super().__init__(raw, image, base_report, prior, fixture)
        self.backend_events = []
        rows = [r for f in evidence['fragments'] for r in f['instructions']]
        self.allowed.update(r['address'] for r in rows)
        self.allowed.update(i['address'] for i in evidence['quantize_leaf']['instructions'])
        pages = {r['address'] & ~4095 for r in rows}
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        pages.update(a & ~4095 for a in (0x14148c2a0, 0x14b27ef48))
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.backend = self.base + 0x9000
        table = self.base + 0x9100
        self.quantize, self.realloc = self.base + 0x7c000, self.base + 0x7c010
        self.uc.mem_write(0x14b27ef48, struct.pack('<Q', self.backend))
        self.uc.mem_write(self.backend, struct.pack('<Q', table))
        self.uc.mem_write(table + 0x60, struct.pack('<Q', self.quantize))
        self.uc.mem_write(table + 0x38, struct.pack('<Q', self.realloc))

    def hook(self, uc, address, size, user):
        if address not in (self.quantize, self.realloc):
            return super().hook(uc, address, size, user)
        a, b, c, d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        if a != self.backend:
            raise ValueError('Migration backend fixture pointer mismatch')
        if address == self.quantize:
            self.backend_events.append(dict(action='quantize_fixture', requested=b, alignment=c))
            result = b
        else:
            if b != 0 or not 0 < c <= 1024 or d != 1:
                raise ValueError('Migration backend fixture realloc contract changed')
            self.buffer = self.allocate(c + 32)
            uc.mem_write(self.buffer, bytes([self.migration_fixture['allocation_fill']]) * c)
            result = self.buffer
            self.backend_events.append(dict(action='realloc_fixture', requested=c, alignment=d, fill=self.migration_fixture['allocation_fill']))
        uc.reg_write(x.UC_X86_REG_RAX, result)
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)


def build():
    root = native.ROOT
    prior_path = root / 'code-clues/sdk-nid-path-suffix-replay.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    base_report = json.loads((root / 'code-clues/headless-device-identity.json').read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('Migration allocator EXE changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in
                                           (0x141431680, 0x141431210, 0x14148c8d0)})
    cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    address = 0x14148c2a0
    offset = image.offset(address - image.pe.base)
    data = raw[offset:offset + 0x1d]
    instructions = list(cs.disasm(data, address))
    if sum(i.size for i in instructions) != len(data) or instructions[-1].mnemonic != 'jmp':
        raise ValueError('Migration quantize leaf boundary changed')
    evidence = dict(fragments=fragments, quantize_leaf=dict(address=address, file_offset=offset,
        bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest(),
        instructions=[dict(address=i.address, mnemonic=i.mnemonic, operands=i.op_str) for i in instructions]))
    cases = []
    for size in (16, 17, 31, 32, 33):
        for fill in (0, 0xaa):
            fixture = dict(channel_key='C' * size, nm_key='0123456789ABCDEFFEDCBA9876543210', allocation_fill=fill)
            replay = Replay(raw, image, base_report, prior, evidence, fixture)
            result = replay.capture_migration()
            result['backend_events'] = replay.backend_events
            cases.append(result)
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                source_report_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                evidence=evidence, cases=cases, native_execution=True, user_storage_read=False,
                limitations=[
                    'Actual native TArray-like byte allocation/count/capacity wrappers and backend dispatch execute.',
                    'Quantize backend returns requested size; realloc backend supplies explicitly filled bytes, not real engine memory.',
                    'Wrapper path does not initialize rounded byte tail; complete real allocator contract remains unproven.',
                    'Migration transform/AES-NI/HEX execute with earlier explicit dispatch/conversion/formatting fixtures.',
                    'No real token, channel key, profile, registry, processes or network accessed.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/sdk-migration-allocation-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
