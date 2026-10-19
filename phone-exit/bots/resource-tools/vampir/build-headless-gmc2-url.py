"""Replay GMC2 URL assembly slice on explicit settings/manager fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('gmc2_values', HERE / 'build-headless-sdk-bootstrap-values.py')
values = importlib.util.module_from_spec(spec)
spec.loader.exec_module(values)
START, STOP = 0x1444f3a68, 0x1444f3d7d
APPEND, GROW = 0x14175be40, 0x1415749c0


class Emulator(values.Emulator):
    def __init__(self, raw, image, fragments):
        super().__init__(raw, image, fragments)
        self.allowed.append((START, STOP))
        append_root = image.roots[image.containing(APPEND)][0]
        self.allowed.extend((image.pe.base + f['begin_rva'], image.pe.base + f['end_rva'])
                            for f in fragments if f['root_begin_rva'] == append_root)
        pages = {a & ~4095 for a in (APPEND, GROW, 0x1444ab740, 0x14147d580, 0x14144dd90)}
        pages.update(a & ~4095 for a in range(START, STOP + 4095, 4096))
        pages.update(a & ~4095 for lo, hi in self.allowed for a in range(lo, hi + 4095, 4096))
        for f in fragments:
            for row in f['instructions']:
                if START <= row['address'] < STOP:
                    pages.update(a & ~4095 for a in row['rip_references'])
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page, 4096)
            try:
                off = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[off:off + 4096])
        self.allocations = {}

    def allocate(self, count):
        if not 1 <= count <= 16384 or self.cursor + count + 32 >= self.scratch + 0x2f000:
            raise ValueError('GMC2 fixture allocation budget exceeded')
        pointer = self.cursor
        self.cursor += (count + 31) & ~31
        self.allocations[pointer] = count
        return pointer

    def put(self, address, text):
        payload = (text + '\0').encode('utf-16le')
        pointer = self.allocate(len(payload))
        self.uc.mem_write(pointer, payload)
        self.uc.mem_write(address, struct.pack('<QII', pointer, len(payload) // 2, len(payload) // 2))

    def copy(self, destination, source, length):
        if not 0 <= length <= 16384 or not all(self.scratch <= p <= self.scratch + 0x40000 - length for p in (source, destination)):
            raise ValueError('GMC2 copy fixture bounds exceeded')
        self.uc.mem_write(destination, bytes(self.uc.mem_read(source, length)))

    def grow(self, builder, units):
        begin, current, end = struct.unpack('<QQQ', bytes(self.uc.mem_read(builder, 24)))
        used = current - begin
        if not 0 <= used <= end - begin <= 16384 or not 0 <= units <= 4096:
            raise ValueError('GMC2 builder fixture budget exceeded')
        capacity = max(end - begin, used + units * 2 + 2) + 32
        pointer = self.allocate(capacity)
        self.copy(pointer, begin, used)
        self.uc.mem_write(builder, struct.pack('<QQQ', pointer, pointer + used, pointer + capacity))

    def hook(self, machine, address, size, user):
        if any(lo <= address < hi for lo, hi in self.allowed):
            return
        x = self.x
        a, b, c = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        result = machine.reg_read(x.UC_X86_REG_RAX)
        if address == GROW:
            self.grow(a, b)
            self.events.append(dict(kind='builder_growth_shim', units=b))
        elif address == 0x1414313d0:
            if not 1 <= b <= 4096:
                raise ValueError('GMC2 FString allocation budget exceeded')
            pointer = self.allocate(b * 2)
            machine.mem_write(a, struct.pack('<Q', pointer))
            machine.mem_write(a + 12, struct.pack('<I', b))
            self.events.append(dict(kind='FString_allocation_shim', units=b))
        elif address in (0x1487a2e19, 0x14144dd90):
            self.copy(a, b, c)
            result = a
            self.events.append(dict(kind='bounded_copy_shim', bytes=c))
        elif address == 0x1444ab740:
            result = self.scratch + 0x5000
            self.events.append(dict(kind='settings_singleton_fixture'))
        elif address == 0x14147d580:
            if a not in self.allocations:
                raise ValueError('GMC2 free outside fixture ownership')
            self.events.append(dict(kind='free_capture'))
        else:
            return super().hook(machine, address, size, user)
        rsp = machine.reg_read(x.UC_X86_REG_RSP)
        ret = struct.unpack('<Q', bytes(machine.mem_read(rsp, 8)))[0]
        machine.reg_write(x.UC_X86_REG_RAX, result)
        machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(x.UC_X86_REG_RIP, ret)

    def assemble(self, base, group, build_code, market):
        for address in values.INITIALIZERS:
            self.run(address)
        manager, settings, rbp = self.scratch + 0x3000, self.scratch + 0x6000, self.scratch + 0x8000
        self.put(manager + 0x1e8, base)
        self.put(manager + 0x1c8, group)
        self.put(settings + 0x28, market)
        self.uc.mem_write(settings + 0x48, bytes([build_code]))
        self.uc.mem_write(self.scratch + 0x5000 + 0x110, struct.pack('<Q', settings))
        self.events = []
        x = self.x
        for reg, value in ((x.UC_X86_REG_RSP, self.stack), (x.UC_X86_REG_RBP, rbp),
                           (x.UC_X86_REG_R15, manager), (x.UC_X86_REG_R14, 0)):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(START, STOP, count=4096)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != STOP:
            raise ValueError('GMC2 URL instruction budget exceeded')
        begin, current, end = struct.unpack('<QQQ', bytes(self.uc.mem_read(rbp + 0xf0, 24)))
        if not 0 < current - begin < 8192 or current > end:
            raise ValueError('GMC2 output exceeds fixture budget')
        result = bytes(self.uc.mem_read(begin, current - begin)).decode('utf-16le')
        return dict(base=base, group=group, build_code=build_code, market=market,
                    result=result, calls=list(self.events), network_used=False)


def build():
    prior_path = values.native.ROOT / 'code-clues/headless-sdk-bootstrap-values.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('GMC2 source changed')
    image = values.native.Image(raw)
    fragments = values.native.decode_ranges(image, {image.roots[image.containing(a)]
        for a in (START, APPEND, values.VERSION, values.BUILD, *values.INITIALIZERS)})
    fixtures = [(base, group, code, market)
        for base in ('https://config.invalid', 'https://config.invalid/', '')
        for group in ('netmarbles-v5', '') for code in (0, 1, 2, 255) for market in ('nmp',)]
    fixtures += [('https://config.invalid/' + 'x' * 1200, 'long-group', 2, 'nmp'),
                 ('https://config.invalid', '/group/', 1, 'a b&c=1')]
    cases = [Emulator(raw, image, fragments).assemble(*fixture) for fixture in fixtures]
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        prior_report_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
        fragments=fragments, start=START, stop=STOP, cases=cases, network_ready=False,
        active_values_verified=False, limitations=[
            'Native URL assembly slice and SDK version/build getters executed with explicit manager/settings fixtures.',
            'Native ASCII-view append also executed; FString construction/allocation/copy/free, buffer growth, atexit and singleton are shims.',
            'Stops before request/callback setup; not whole RefreshSDKConstants or HTTP.',
            'No percent encoding observed in this slice; common API restricts supported input fields separately.'])


if __name__ == '__main__':
    report = build()
    target = values.native.ROOT / 'code-clues/headless-gmc2-url.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                         cases=len(report['cases'])), indent=2))
