"""ID110 -> native record lookup/find/accessor with bounded hash-table fixtures.

The registry getter is an explicit capture: no live table or TLS initialization.
The player vtable and unrelated handler services remain inherited fixtures.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('selected_record_base', HERE / 'replay-character-select-handler.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.x
LOOKUP, FIND, REGISTRY, ACCESSOR = 0x1458819c0, 0x145889510, 0x145889c80, 0x141482990


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
        names = {'SelectedPlayer_RecordLookup', 'SelectedPlayer_RecordFind'}
        self.record_ranges = [r for f in manifest['functions'] if f['name'] in names for r in f['ranges']]
        if len(self.record_ranges) != 2:
            raise ValueError('Missing record lookup source')
        for r in self.record_ranges:
            lo, hi = int(r['start'], 16), int(r['end_exclusive'], 16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset'] + hi - lo]).hexdigest() != r['sha256']:
                raise ValueError('Record lookup source changed')
            self.ranges.append((lo, hi))
            for page in range(lo & ~4095, (hi + 4095) & ~4095, 4096):
                self.map_source_page(page)
        off = self.image.offset(ACCESSOR - self.image.pe.base)
        raw = self.raw[off:off + 5]
        if raw.hex() != '488b4108c3':
            raise ValueError('Record descriptor accessor changed')
        self.accessor = dict(address=ACCESSOR, file_offset=off, bytes=raw.hex())
        table_address = 0x1499e1a68
        off = self.image.offset(table_address - self.image.pe.base)
        table = self.raw[off:off + 0xa8]
        if tuple(struct.unpack_from('<Q', table, slot)[0] for slot in (0x60, 0x80, 0xa0)) != (
                0x14292acb0, 0x145d65a60, 0x145206320):
            raise ValueError('Selected-player table changed')
        setter = 0x14292acb0
        setter_off = self.image.offset(setter - self.image.pe.base)
        setter_raw = self.raw[setter_off:setter_off + 7]
        if setter_raw.hex() != '889140010000c3':
            raise ValueError('Selected-player slot60 changed')
        self.static_player_binding = dict(table_address=table_address, table_file_offset=off,
                                         table_bytes=table.hex(), setter_address=setter,
                                         setter_file_offset=setter_off, setter_bytes=setter_raw.hex())
        self.ranges.append((ACCESSOR, ACCESSOR + 5))
        self.map_source_page(ACCESSOR & ~4095)
        self.map_source_page(REGISTRY & ~4095)
        self.handler_hooks.difference_update((LOOKUP, ACCESSOR))
        self.registry = 0x24000000
        self.uc.mem_map(self.registry, 0x10000)

    def hook(self, uc, address, size, user):
        if self.handler_phase and address == REGISTRY:
            self.events.append(dict(action='registry_fixture_capture'))
            self.finish(self.registry)
            return
        if self.handler_phase and address == LOOKUP:
            self.events.append(dict(action='native_record_lookup', key=uc.reg_read(x.UC_X86_REG_EDX)))
        return super().hook(uc, address, size, user)

    def configure(self, keys, dynamic, empty=False):
        root = self.registry
        self.uc.mem_write(root, bytes(0x10000))
        records = root + 0x1000
        self.uc.mem_write(root + 0x18, struct.pack('<Q', records))
        self.uc.mem_write(root + 0x20, struct.pack('<I', len(keys)))
        self.uc.mem_write(root + 0x4c, struct.pack('<I', len(keys) if empty else 0))
        # One bucket deliberately forces every key into a collision chain.
        self.uc.mem_write(root + 0x50, struct.pack('<i', 0 if keys else -1))
        self.uc.mem_write(root + 0x58, struct.pack('<Q', root + 0x800 if dynamic else 0))
        self.uc.mem_write(root + 0x60, struct.pack('<I', 1))
        self.uc.mem_write(root + 0x800, struct.pack('<i', 0 if keys else -1))
        for index, key in enumerate(keys):
            self.uc.mem_write(records + index * 0x1c8, struct.pack('<I', key))
            self.uc.mem_write(records + index * 0x1c8 + 0x1c0,
                              struct.pack('<i', index + 1 if index + 1 < len(keys) else -1))


def build():
    em = Emulator()
    cases = []
    profiles = (((), False), ((7,), False), ((3, 7, 0xffffffff), False),
                ((3, 7, 0xffffffff), True))
    for keys, dynamic in profiles:
        for key in (0, 3, 7, 9, 0xffffffff):
            em.configure(keys, dynamic)
            data = bytearray(base.base.profile_body('', 0))
            # Empty first FString: wire byte 23 is main object +0x30.
            struct.pack_into('<I', data, 23, key)
            fixture = dict(gate_state=0, metadata=False, platform=False,
                           ui_present=False, ui_same=False, service_flag=0)
            result = em.execute(bytes(data), fixture)
            pointer = struct.unpack('<Q', bytes(em.uc.mem_read(em.context + 0x1138, 8)))[0]
            expected = em.registry + 0x1008 + keys.index(key) * 0x1c8 if key in keys else 0
            if pointer != expected or result['state']['raw10'] != key:
                raise ValueError('ID110 record lookup/copy mismatch')
            calls = [e['key'] for e in result['events'] if e['action'] == 'native_record_lookup']
            if calls != [key]:
                raise ValueError('ID110 did not use the transferred key')
            cases.append(dict(keys=list(keys), dynamic_buckets=dynamic, key=key,
                              record_pointer=pointer, state=result['state'], events=result['events']))
    # Equal live/deleted counts take the early empty-table return even if
    # backing bucket/record memory still contains an otherwise matching key.
    em.configure((7,), False, empty=True)
    em.handler_phase = True
    em.events = []
    stack, stop = em.scratch + 0x30000, em.scratch + 0x3f000
    em.uc.mem_write(stack, struct.pack('<Q', stop))
    for reg, value in ((x.UC_X86_REG_RSP, stack), (x.UC_X86_REG_RCX, em.registry), (x.UC_X86_REG_EDX, 7)):
        em.uc.reg_write(reg, value)
    em.uc.emu_start(FIND, stop, count=10000)
    if em.uc.reg_read(x.UC_X86_REG_RIP) != stop or em.uc.reg_read(x.UC_X86_REG_RAX):
        raise ValueError('Empty-table native return mismatch')
    return dict(schema_version=1, source=em.bindings['source'], sha256=em.bindings['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256=hashlib.sha256((HERE / 'replay-character-select-handler.py').read_bytes()).hexdigest(),
                ranges=em.record_ranges, accessor=em.accessor, static_player_binding=em.static_player_binding,
                cases=cases, empty_table_return=0,
                native_execution=True, network_ready=False, field_semantics_verified=False,
                limitations=['Registry data, initialized singleton and player vtable are fixtures.',
                             'Record names and World.Id/world-position semantics are not established.',
                             'Unrelated backend boundaries are inherited captures; no game or network session.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/selected-player-record-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                          cases=len(report['cases']))))
