"""Whole slider handler and value store; engine lookup/rendering are fixtures."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def run():
    spec = importlib.util.spec_from_file_location('slider_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec); spec.loader.exec_module(archive)
    hooks = (0x141436fb0, 0x141483160, 0x141425e40, 0x1464368f0, 0x14142a330,
        0x146447e50, 0x14644a0b0, 0x146456050, 0x145679e40)
    fixtures = dict.fromkeys(hooks)
    h = archive.make_harness(extra_addresses=(0x14642d340, 0x1464568b0), fixtures=fixtures)
    exports = {}
    for run_name, sha in [('run-149218135db0', '865d2bd50a1179f2ce30ffc235fbf38ead94b6ef865fcc4a28694706c625d67d'),
                          ('run-591e487095e6', '1218e6bdd0b07828910f6b15f37046e270804d374e1c28a891ea5b28ab9cb4c7')]:
        evidence = h.comparison / 'details' / run_name / 'details.json'
        if h.audit.sha256(evidence) != sha:
            raise ValueError('Slider Ghidra export changed')
        exports[str(evidence)] = sha
    uc, x = h.uc, h.x
    screen, owner, slider, slot, actor, names = [h.scratch + n for n in
        (0x10000, 0x12000, 0x13000, 0x15000, 0x16000, 0x17000)]
    table = 0x149ca7190
    raw_offset = h.image.offset(table - h.image.pe.base)
    for offset, target in ((0x80, 0x14644a0b0), (0x20, 0x146456050)):
        if struct.unpack_from('<Q', h.raw, raw_offset + offset)[0] != target:
            raise ValueError('Slider owner vtable changed')
    page = table & ~4095
    if not any(a <= page <= b for a, b, _ in uc.mem_regions()):
        uc.mem_map(page, 4096)
        uc.mem_write(page, h.raw[h.image.offset(page - h.image.pe.base):][:4096])
    state, events = {}, []

    def text(at):
        pointer, count, capacity = struct.unpack('<Qii', bytes(uc.mem_read(at, 16)))
        if not 0 <= count <= capacity <= 64: raise ValueError('Slider text bound')
        return bytes(uc.mem_read(pointer, max(0, count - 1) * 2)).decode('utf-16le') if count else ''

    def fixture(machine):
        at = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c = [machine.reg_read(reg) for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        result = None
        if at == 0x141436fb0:
            if not 0 <= b <= 64: raise ValueError('Slider FString allocation bound')
            pointer = state['heap']; state['heap'] += 0x100
            machine.mem_write(pointer, bytes(b * 2))
            machine.mem_write(a, struct.pack('<Qii', pointer, b, b)); result = a
        elif at == 0x141425e40:
            if a != len(state['key']) or bytes(machine.mem_read(b, a * 2)).decode('utf-16le') != state['key']:
                raise ValueError('Slider hash input differs')
            events.append('hash'); result = 0x12345678
        elif at == 0x1464368f0:
            if a != owner + 0x38 or b != 0x12345678 or text(c) != state['key']:
                raise ValueError('Slider map slot lookup contract')
            events.append('slot_lookup'); result = slot
        elif at == 0x14142a330:
            if a != slot or c != len(state['key']): raise ValueError('Slider record key copy contract')
            events.append('key_copy'); result = a
        elif at == 0x146447e50:
            if a != owner + 8: raise ValueError('Slider JSON source differs')
            events.append('json_capture')
            machine.mem_write(b, struct.pack('<Qii', names + 0x100, 3, 3)); result = b
        elif at == 0x14644a0b0: result = actor if state['actor'] else 0
        elif at == 0x145679e40:
            if a != (actor + 0x670 if state['actor'] else 0) or text(b + 0x10) != '{}':
                raise ValueError('Slider preview appearance contract')
            if bytes(machine.mem_read(b, 1)) != bytes((state['gender'],)):
                raise ValueError('Slider preview gender differs')
            events.append('preview_capture')
        elif at == 0x146456050: events.append('refresh_capture')
        elif at == 0x141483160:
            if not names <= a < h.scratch + 0x30000: raise ValueError('Slider free capture bound')
        else: raise ValueError('Unknown slider fixture')
        if result is not None: machine.reg_write(x.UC_X86_REG_RAX, result)
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)

    for at in hooks: fixtures[at] = fixture
    cases = []
    for key in ('Height', 'Shape', ''):
        for scale, value in ((100, 0), (100, 37), (100, 100), (100, -25), (100, 125), (3, 1), (255, 254)):
            for present in (False, True):
                events.clear(); state.update(key=key, heap=h.scratch + 0x20000, actor=present, gender=1)
                uc.mem_write(screen, bytes(0xd00)); uc.mem_write(owner - 16, b'\xa5' * 0xa8)
                uc.mem_write(owner, struct.pack('<Q', table)); uc.mem_write(owner + 0x30, b'\x01')
                uc.mem_write(screen + 0xc90, struct.pack('<Q', owner))
                uc.mem_write(screen + 0xc48, struct.pack('<i', scale))
                uc.mem_write(slider, bytes(0xb40)); uc.mem_write(slider + 0xaa0, struct.pack('<q', value))
                data = key.encode('utf-16le') + b'\0\0'
                uc.mem_write(names, data); uc.mem_write(names + 0x100, '{}\0'.encode('utf-16le'))
                uc.mem_write(slider + 0x970, struct.pack('<Qii', names, len(key) + 1, len(key) + 1))
                uc.mem_write(slot - 16, b'\xa5' * 0x50)
                before_owner = bytes(uc.mem_read(owner - 16, 0xa8))
                h.call(0x14642d340, screen, slider, budget=200000)
                expected = struct.pack('<f', value / scale)
                actual = bytes(uc.mem_read(slot + 0x10, 4))
                if actual != expected: raise ValueError('Slider normalized float differs')
                if bytes(uc.mem_read(owner - 16, 0xa8)) != before_owner:
                    raise ValueError('Slider handler overwrote owner outside slot fixture')
                around = bytes(uc.mem_read(slot - 16, 0x50))
                if around[:32] != b'\xa5' * 32 or around[36:] != b'\xa5' * (0x50 - 36):
                    raise ValueError('Slider value store crossed bounds')
                if events != ['hash', 'slot_lookup', 'key_copy', 'json_capture', 'preview_capture', 'refresh_capture']:
                    raise ValueError('Slider event order differs')
                cases.append(dict(key=key, scale=scale, value=value, actor_present=present,
                    stored_float_hex=actual.hex(), events=events.copy(), guards_unchanged=True))
    # Both early exits must not resolve a map slot or serialize appearance.
    for widget_present, owner_present in ((False, True), (True, False)):
        events.clear(); uc.mem_write(screen + 0xc90, struct.pack('<Q', owner if owner_present else 0))
        h.call(0x14642d340, screen, slider if widget_present else 0, budget=200000)
        if events: raise ValueError('Slider absent input produced events')
        cases.append(dict(widget_present=widget_present, owner_present=owner_present, events=[]))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        native_execution=True, network_used=False, cases=cases, ghidra_exports=exports,
        dependencies={name: h.audit.sha256(HERE / name) for name in ('replay-release-archive-input.py',
            'build-native-entry-code.py', 'extract-native-enums.py', 'build-object-zero-init-code.py', 'requirements-native.txt')},
        limits=['Whole slider handler and native float store helper execute; actual divide uses float32.',
            'Hash, map slot lookup/insert, FString copy/allocation/free, JSON engine, Actor lookup/rendering and refresh are fixtures/captures.',
            'Synthetic keys and slider scales; neither real UI range nor selected preset is established.',
            'The handler does not clamp the captured values; upstream slider clamp is separate and not executed here.',
            'Zero scale and nonfinite values are not covered; no game or character creation.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-appearance-slider', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
