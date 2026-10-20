"""Native ID204 reader with its real leaf constructor and archive primitives."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('start_reader_base', HERE / 'replay-world-move-finish-reader.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.x
CTOR, READER, TABLE = 0x1458429f0, 0x145845140, 0x14991a080


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
        self.start_ranges = [r for f in manifest['functions'] if f['name'] == 'WorldMoveStartResult_Read'
                             for r in f['ranges']]
        if not self.start_ranges:
            raise ValueError('Missing Ghidra start reader source')
        for r in self.start_ranges:
            lo, hi = int(r['start'], 16), int(r['end_exclusive'], 16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset'] + hi - lo]).hexdigest() != r['sha256']:
                raise ValueError('Start reader source changed')
            self.ranges.append((lo, hi))
            for page in range(lo & ~4095, (hi + 4095) & ~4095, 4096):
                self.map_source_page(page)
        offset = self.image.offset(CTOR - self.image.pe.base)
        raw = self.raw[offset:offset + 28]
        if raw.hex() != '488d0589760d0448890133c0488941106689413048894138488bc1c3':
            raise ValueError('Reviewed start constructor leaf changed')
        self.constructor = dict(address=CTOR, file_offset=offset, bytes=raw.hex())
        self.ranges.append((CTOR, CTOR + 28))
        self.map_source_page(CTOR & ~4095)
        offset = self.image.offset(TABLE - self.image.pe.base)
        table = self.raw[offset:offset + 64]
        if struct.unpack_from('<Q', table, 0x20)[0] != READER:
            raise ValueError('Start reader table binding changed')
        getter = struct.unpack_from('<Q', table, 0x28)[0]
        off = self.image.offset(getter - self.image.pe.base)
        leaf = self.raw[off:off + 6]
        if leaf != bytes.fromhex('b8cc000000c3'):
            raise ValueError('Start result ID getter changed')
        self.binding = dict(table=TABLE, file_offset=offset, bytes=table.hex(),
                            id_getter=getter, id_getter_bytes=leaf.hex(), packet_id=204)
        # Bind the packet to its name and the game dispatcher, independently
        # of its apparent position among neighbouring packet tables.
        name_getter = struct.unpack_from('<Q', table, 0x38)[0]
        roots = {self.image.roots[self.image.containing(a)] for a in (name_getter, 0x14678f833)}
        fragments = native.decode_ranges(self.image, roots)
        rows = {r['address']: r for f in fragments for r in f['instructions']}
        name_row = rows[0x14584c1f9]
        if name_getter != 0x14584c1f0 or name_row['rip_references'] != [0x14990eca8]:
            raise ValueError('Start result name reference changed')
        off = self.image.offset(0x14990eca8 - self.image.pe.base)
        name_bytes = b'PktWorldMoveStartResult\0'
        if self.raw[off:off + len(name_bytes)] != name_bytes:
            raise ValueError('Start result name changed')
        handler_table = 0x149d7fe30
        off = self.image.offset(handler_table - self.image.pe.base)
        if struct.unpack_from('<Q', self.raw, off + 0x10)[0] != 0x1467a61a0:
            raise ValueError('Start result handler slot changed')
        if (rows[0x14678f833]['rip_references'] != [handler_table] or
                rows[0x14678f854]['direct_target'] != CTOR or
                rows[0x14678f867]['direct_target'] != 0x1467a7250):
            raise ValueError('Start result registration changed')
        for a, expected in ((0x14678f83a, 'qword ptr [rdi], rax'), (0x14678f85e, 'r8, rdi'),
                            (0x14678f861, 'rdx, rax'), (0x14678f864, 'rcx, rsi')):
            if (rows[a]['mnemonic'], rows[a]['operands']) != ('mov', expected):
                raise ValueError('Start result registration arguments changed')
        self.binding.update(name='PktWorldMoveStartResult', name_getter=name_getter,
                            name_reference=name_row, handler_table=handler_table, handler=0x1467a61a0,
                            registration=[rows[a] for a in (0x14678f833, 0x14678f83a, 0x14678f854,
                                                           0x14678f85e, 0x14678f861, 0x14678f864, 0x14678f867)])

    def read_start(self, data):
        if len(data) > 64:
            raise ValueError('Start fixture byte bound')
        self.heap = self.scratch + 0x10000
        self.copy_sizes, self.io_entries, self.events = [], [], []
        self.map_storage, self.insertions = {}, []
        packet, archive, buffer = self.scratch + 0x1000, self.scratch + 0x3000, self.scratch + 0x8000
        self.uc.mem_write(packet, bytes(0x100))
        self.uc.mem_write(buffer, bytes(64))
        if data:
            self.uc.mem_write(buffer, data)
        self.call(CTOR, packet)
        if int.from_bytes(self.uc.mem_read(packet, 8), 'little') != TABLE:
            raise ValueError('Native constructor did not install start result table')
        self.call(0x144aa6260, archive, buffer, len(data), 1, 0)
        stack, stop = self.scratch + 0x30000, self.scratch + 0x3f000
        self.uc.mem_write(stack, struct.pack('<Q', stop))
        for register, value in ((x.UC_X86_REG_RSP, stack), (x.UC_X86_REG_RCX, packet), (x.UC_X86_REG_RDX, archive)):
            self.uc.reg_write(register, value)
        self.uc.emu_start(READER, stop, count=100000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != stop:
            raise ValueError('Start reader instruction budget')
        fields = {hex(o): int.from_bytes(self.uc.mem_read(packet + o, size), 'little')
                  for o, size in ((0x10, 4), (0x14, 4), (0x30, 1), (0x31, 1), (0x38, 8))}
        return dict(payload_hex=data.hex(), returned=self.uc.reg_read(x.UC_X86_REG_AL),
                    consumed=int.from_bytes(self.uc.mem_read(archive + 0x30, 8), 'little') - buffer,
                    fields=fields, vector_hex=bytes(self.uc.mem_read(packet + 0x18, 24)).hex())


def build():
    em = Emulator()
    cases = []
    for code in (0, 1, 0xffffffff):
        for enum in (0, 21, 22, 255):
            for flag in (0, 255):
                data = struct.pack('<IIfffBBQ', code, 0x89abcdef, 1.5, -2.25, -0., enum, flag, 0xfedcba9876543210)
                result = em.read_start(data)
                expected = {'0x10': code, '0x14': 0x89abcdef, '0x30': min(enum, 22),
                            '0x31': int(bool(flag)), '0x38': 0xfedcba9876543210}
                if (result['returned'], result['consumed'], result['fields'], result['vector_hex']) != (
                        1, 30, expected, struct.pack('<ddd', 1.5, -2.25, -0.).hex()):
                    raise ValueError('Native start reader layout mismatch')
                cases.append(result)
    short = [em.read_start(data[:size]) for size in range(30)]
    if any(c['returned'] or c['consumed'] > len(bytes.fromhex(c['payload_hex'])) for c in short):
        raise ValueError('Short start body accepted or overconsumed')
    trailing = em.read_start(data + b'\xa5')
    if (trailing['returned'], trailing['consumed']) != (1, 30):
        raise ValueError('Native start reader consumption changed')
    manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
    names = {'WorldMoveReserveResult_Handler', 'WorldMoveStartResult_Handler', 'WorldMoveReserveResult_Receive',
             'WorldMoveStartResult_Receive', 'WorldMoveReserve_Request', 'WorldMoveStart_Request'}
    functions = [f for f in manifest['functions'] if f['name'] in names]
    if len(functions) != len(names):
        raise ValueError('Missing static movement source functions')
    roots = {em.image.roots[em.image.containing(int(f['address'], 16))] for f in functions}
    fragments = native.decode_ranges(em.image, roots)
    service_slots = []
    for slot, target in ((0x60, 0x145dc29c0), (0x68, 0x145dc2e60), (0x70, 0x145dc2930)):
        offset = em.image.offset(0x1499f11f0 + slot - em.image.pe.base)
        raw = em.raw[offset:offset + 8]
        if struct.unpack('<Q', raw)[0] != target:
            raise ValueError('Movement service slot changed')
        service_slots.append(dict(slot=slot, target=target, file_offset=offset, bytes=raw.hex()))
    return dict(source=em.bindings['source'], sha256=em.bindings['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256=hashlib.sha256((HERE / 'replay-world-move-finish-reader.py').read_bytes()).hexdigest(),
                ranges=em.start_ranges, constructor=em.constructor, binding=em.binding,
                static_service_slots=service_slots, static_service_fragments=fragments,
                cases=cases, short=short, trailing=trailing, network_ready=False,
                limitations=['Native constructor, whole reader, vector conversion and archive primitives execute.',
                             'Inherited bounded archive/math backends; no server session or world coordinate semantics verified.',
                             'The native reader consumes its own body and does not reject trailing bytes; portable framing must enforce exact consumption.'])


if __name__ == '__main__':
    report = build()
    output = native.ROOT / 'code-clues/world-move-start-reader-replay.json'
    output.write_text(json.dumps(report, indent=2) + '\n', 'utf-8')
    print(json.dumps(dict(output=str(output), cases=len(report['cases']), short=len(report['short']),
                          sha256=hashlib.sha256(output.read_bytes()).hexdigest())))
