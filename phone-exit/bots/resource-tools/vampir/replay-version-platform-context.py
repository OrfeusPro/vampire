"""Source-bound ENnOsType descriptor -> native selector/lookup/value scenarios.

UEnum construction is not executed: the recovered descriptor supplies explicit
object/name fixtures. Native selector and lookup/value routines execute in full.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('platform_base', HERE / 'replay-device-key-lifecycle.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.guid.source.config.native, base.x
SELECTOR, PLATFORM, LOOKUP, VALUE = 0x1445c77a0, 0x143c13690, 0x1416d7af0, 0x1416d7a10


class Replay(base.Replay):
    def __init__(self, raw, image, source, fragments, members, scoped):
        super().__init__(raw, image, source, {})
        self.names = {}
        self.rows = {r['address']: r for f in fragments for r in f['instructions']}
        self.allowed.update(self.rows)
        hooks = (0x141420f70, 0x1415a8e80, 0x1415ae4a0, 0x1415b8a70, 0x141428640, 0x141432680)
        pages = {p & ~4095 for r in self.rows.values() for p in (r['address'], *r['rip_references'])}
        pages.update(address & ~4095 for address in hooks)
        for page in pages:
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            try: offset = image.offset(page - image.pe.base)
            except ValueError: continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.enum = self.base + 0x8000
        array = self.base + 0x9000
        for index, member in enumerate(members):
            handle = self.name(member['name'])
            self.uc.mem_write(array + index * 16, struct.pack('<Qq', handle, member['value']))
        self.uc.mem_write(self.enum + 0x40, struct.pack('<QI', array, len(members)))
        self.uc.mem_write(self.enum + 0x50, bytes((int(scoped),)))

    def name(self, text):
        for handle, value in self.names.items():
            if value == text: return handle
        handle = len(self.names) + 1
        self.names[handle] = text
        return handle

    def literal(self, pointer, unit):
        data = bytearray()
        for i in range(256):
            value = bytes(self.uc.mem_read(pointer + i * unit, unit))
            if value == bytes(unit): return data.decode('ascii' if unit == 1 else 'utf-16le')
            data.extend(value)
        raise ValueError('Platform literal bound')

    def hook(self, uc, address, size, user):
        if address in self.allowed: return
        a, b, c = [uc.reg_read(reg) for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        result = 0
        if address == 0x141420f70:
            self.string(a, self.literal(b, 1)); result = a
        elif address == 0x1415a8e80:
            uc.mem_write(a, struct.pack('<Q', self.name(self.literal(b, 2)))); result = a
        elif address == 0x1415ae4a0:
            result = int(self.names[a].lower() == self.literal(b, 2).lower())
        elif address == 0x1415b8a70:
            handle = int.from_bytes(uc.mem_read(a, 8), 'little')
            self.string(b, self.names[handle]); result = b
        elif address == 0x141428640:
            result = self.text(a).find(self.literal(b, 2)) & 0xffffffff
        elif address == 0x141432680:
            self.string(b, self.text(a)[c:]); result = b
        else:
            return super().hook(uc, address, size, user)
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(stack, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)

    def call(self, address, *args):
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP, self.stack)
        for reg, value in zip((x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8), args):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(address, self.stop, count=10000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop: raise ValueError('Platform context instruction budget')
        return self.uc.reg_read(x.UC_X86_REG_RAX)


def build():
    source_path = native.ROOT / 'code-clues/headless-device-identity.json'
    source = json.loads(source_path.read_text('utf-8'))
    raw = Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    record_offset = image.offset(0x14b117630 - image.pe.base)
    record = raw[record_offset:record_offset + 48]
    package, _, name_a, name_b, members_pointer = struct.unpack_from('<QQQQQ', record)
    count = struct.unpack_from('<H', record, 0x2c)[0]
    if package != 0x1445ba280 or name_a != name_b or count != 5: raise ValueError('Enum construction descriptor changed')
    name_offset = image.offset(name_a - image.pe.base)
    if raw[name_offset:name_offset + 10] != b'ENnOsType\0': raise ValueError('Platform enum identity changed')
    enums, _ = native.native.extract(raw)
    members = enums['ENnOsType']
    expected_offset = image.offset(members_pointer - image.pe.base)
    if len(members) != count or [row['descriptor_offset'] for row in members] != [expected_offset + i * 16 for i in range(count)]:
        raise ValueError('Enum descriptor does not select recovered member array')
    addresses = (SELECTOR, PLATFORM, LOOKUP, VALUE, 0x1445d23b0, 0x1445bdfe0)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in addresses})
    cases = []
    for scoped in (False, True):
        em = Replay(raw, image, source, fragments, members, scoped)
        selector = em.call(SELECTOR)
        if selector != 3: raise ValueError('Compiled Windows selector changed')
        for key in (selector, 0, 1, 2, 4, 99):
            em.call(LOOKUP, em.enum, em.output, key)
            output = em.text(em.output)
            member = next((row['name'] for row in members if row['value'] == key), '')
            expected = member.split('::')[-1] if scoped else member
            if output != expected: raise ValueError('Platform lookup output differs')
            cases.append(dict(scoped_fixture=scoped, key=key, selector=selector, output=output))
    return dict(source=source['source'], source_sha256=source['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256=hashlib.sha256((HERE / 'replay-device-key-lifecycle.py').read_bytes()).hexdigest(),
        record=dict(address=hex(0x14b117630), file_offset=record_offset, bytes=record.hex(),
            sha256=hashlib.sha256(record).hexdigest(), name='ENnOsType', members_address=hex(members_pointer),
            count=count, enum_form_byte=record[0x2f], flags_byte=record[0x2e]),
        members=members, fragments=fragments, cases=cases,
        limitations=['UEnum construction, name pool, comparison/search/substring are fixtures.',
            'Object scoped flag is explicit in each scenario; native constructor backend not executed.',
            'No active reflection object, OS inputs, complete Version packet or game network.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/version-platform-context-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
