"""ID110 through the allocating derived manager factory and its override.

The real derived slot58 runs; its settings application slot60 is captured.
Registry lookup is absent, preserving the explicit bounded backend profile.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('derived_post_manager_base', HERE / 'replay-character-select-post-manager.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.x
FACTORY, TABLE, OVERRIDE = 0x145cadba0, 0x1499e88c0, 0x145cb9e90
QUERY, LOOKUP, APPLY = 0x145ccad50, 0x145b03920, 0x145cc64e0
FIELD, GETTER = 0x14558fa40, 0x145564550
FLAG = 0x14b51f6b0


class Emulator(base.Emulator):
    expected_table = TABLE

    def __init__(self):
        super().__init__()
        manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
        names = {'CharacterSelect_PostManagerDerivedConstruct', 'CharacterSelect_PostManagerDerived58',
                 'CharacterSelect_PostManagerDerived38'}
        self.derived_ranges = [r for f in manifest['functions'] if f['name'] in names for r in f['ranges']]
        if len(self.derived_ranges) != 3:
            raise ValueError('Missing derived manager Ghidra source')
        for r in self.derived_ranges:
            lo, hi = int(r['start'], 16), int(r['end_exclusive'], 16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset'] + hi - lo]).hexdigest() != r['sha256']:
                raise ValueError('Derived manager source changed')
            self.ranges.append((lo, hi))
            for page in range(lo & ~4095, (hi + 4095) & ~4095, 4096):
                self.map_source_page(page)
        off = self.image.offset(TABLE - self.image.pe.base)
        table = self.raw[off:off + 0x70]
        if tuple(struct.unpack_from('<Q', table, n)[0] for n in (0x38, 0x58, 0x60)) != (QUERY, OVERRIDE, APPLY):
            raise ValueError('Derived manager dispatch changed')
        self.derived_table = dict(address=TABLE, file_offset=off, bytes=table.hex())
        self.leaves = []
        for address, length in ((FIELD, 23), (GETTER, 8)):
            off = self.image.offset(address - self.image.pe.base)
            raw = self.raw[off:off + length]
            if address == FIELD and raw.hex() != '80facd720333c0c30fb6c2488d04404803c08b44c154c3':
                raise ValueError('Reviewed manager value getter changed')
            if address == GETTER and raw != bytes.fromhex('488b0541ee0006c3'):
                raise ValueError('Reviewed secondary singleton getter changed')
            self.leaves.append(dict(address=address, file_offset=off, bytes=raw.hex()))
            self.ranges.append((address, address + length))
            self.map_source_page(address & ~4095)
        off = self.image.offset(GETTER - self.image.pe.base)
        self.secondary_global = GETTER + 7 + struct.unpack_from('<i', self.raw, off + 3)[0]
        for address in (TABLE, LOOKUP, APPLY, FLAG, self.secondary_global, 0x1468e4100):
            self.map_source_page(address & ~4095)
        self.manager_hooks.remove(self.query)
        self.alloc_null = False
        self.secondary_value = 0

    def construct_manager(self):
        self.uc.mem_write(self.secondary_global, struct.pack('<Q', self.context + 0x1e000))
        self.uc.mem_write(self.context + 0x1e018, bytes([self.secondary_value]))
        self.uc.mem_write(FLAG, b'\xa5')
        self.invoke(FACTORY, 0)
        if self.uc.reg_read(x.UC_X86_REG_RAX) != self.context + 0xa000:
            raise ValueError('Derived factory result differs from allocated object')
        if bytes(self.uc.mem_read(self.context + 0xc730, 8)) != bytes(8):
            raise ValueError('Derived extra field was not cleared')

    def hook(self, uc, address, size, user):
        if self.handler_phase and address == 0x1468e4100:
            size_arg = uc.reg_read(x.UC_X86_REG_RCX)
            if size_arg != 0x2738:
                raise ValueError('Derived factory allocation size changed')
            self.finish(0 if self.alloc_null else self.context + 0xa000)
            return
        if self.handler_phase and address == QUERY:
            if uc.reg_read(x.UC_X86_REG_RCX) != self.context + 0xa000:
                raise ValueError('Derived policy query receiver')
            self.query_count += 1
        if self.handler_phase and address == LOOKUP:
            descriptor = uc.reg_read(x.UC_X86_REG_RCX)
            if uc.reg_read(x.UC_X86_REG_RDX) & 255 > 204:
                raise ValueError('Derived policy index outside record count')
            uc.mem_write(descriptor, bytes(16))
            self.finish(descriptor)
            return
        if self.handler_phase and address == OVERRIDE:
            if uc.reg_read(x.UC_X86_REG_RCX) != self.context + 0xa000:
                raise ValueError('Derived slot58 receiver')
            self.events.append(dict(action='native_derived_slot58'))
        if self.handler_phase and address == APPLY:
            a, b, c, d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX,
                                                 x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
            sp = uc.reg_read(x.UC_X86_REG_RSP)
            tail = tuple(uc.mem_read(sp + offset, 1)[0] for offset in (0x28, 0x30, 0x38))
            if (a, b & 255, c & 255, d & 255, tail) != (self.context + 0xa000, 27, self.secondary_value, 1, (0, 1, 1)):
                raise ValueError('Derived settings application arguments changed')
            self.events.append(dict(action='derived_slot60_capture', index=b & 255, value=c & 255,
                                    arg4=d & 255, trailing=list(tail)))
            self.finish(0)
            return
        return super().hook(uc, address, size, user)


def build():
    em = Emulator()
    cases = []
    for mode in ('empty', 'active', 'disabled', 'zero-count', 'null-pointer'):
        for value in (0, 1, 255):
            em.secondary_value = value
            case = em.execute_manager(mode=mode)
            case['secondary_value'] = value
            case['flag'] = em.uc.mem_read(FLAG, 1)[0]
            cases.append(case)
    for code, gate in ((1, 0), (0x1197, 0), (0x1197, 1)):
        em.secondary_value = 255
        case = em.execute_manager(code=code, gate_state=gate, mode='active')
        case.update(secondary_value=255, flag=em.uc.mem_read(FLAG, 1)[0])
        cases.append(case)
    for case in cases:
        accepted = case['code'] == 0 or (case['code'] == 0x1197 and case['gate_state'] == 0)
        events = [e for e in case['events'] if e['action'] == 'derived_slot60_capture']
        if len(events) != int(accepted) or (events and events[0]['value'] != case['secondary_value']):
            raise ValueError('Derived override did not apply secondary value')
        if case['flag'] != (int(case['mode'] != 'empty') if accepted else 0xa5):
            raise ValueError('Derived override boolean did not use entry71 value')
        callbacks = [e for e in case['events'] if e['action'] == 'post_manager_callback_capture']
        if len(callbacks) != (203 if accepted and case['mode'] == 'active' else 0):
            raise ValueError('Base refresh changed after derived override')
    em.alloc_null = True
    em.invoke(FACTORY, 0)
    if em.uc.reg_read(x.UC_X86_REG_RAX):
        raise ValueError('Derived allocation failure did not return null')
    return dict(source=em.bindings['source'], sha256=em.bindings['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256=hashlib.sha256((HERE / 'replay-character-select-post-manager.py').read_bytes()).hexdigest(),
                derived_ranges=em.derived_ranges, table=em.derived_table, leaves=em.leaves,
                cases=cases, null_allocation_return=0, network_ready=False, reserve_trigger_verified=False,
                limitations=['Actual allocating factory/base constructor/derived vptr/getter/ID110 handler/derived slot58/base refresh execute.',
                             'Allocation returns bounded storage; missing policy registry/accessor and configuration backend are captures.',
                             'Derived slot60 records arguments; its side effects, live registration and ID201 trigger are not verified.'])


if __name__ == '__main__':
    report = build()
    output = native.ROOT / 'code-clues/character-select-derived-manager-replay.json'
    output.write_text(json.dumps(report, indent=2) + '\n', 'utf-8')
    print(json.dumps(dict(output=str(output), cases=len(report['cases']),
                          sha256=hashlib.sha256(output.read_bytes()).hexdigest())))
