"""Execute appearance reset with native sparse iteration and bounded frees."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def run():
    spec = importlib.util.spec_from_file_location('appearance_reset_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec); spec.loader.exec_module(archive)
    hooks = (0x141483160, 0x1418cab30, 0x1414d8680, 0x141433ef0)
    fixtures = dict.fromkeys(hooks)
    h = archive.make_harness(extra_addresses=(0x146456560, 0x143060690, 0x14142e7d0), fixtures=fixtures)
    evidence = h.comparison / 'details/run-2d15d3017ebd/details.json'
    if h.audit.sha256(evidence) != '33addde274986e37eae7a189109e6fb77c3ce81cda4b7c4deb74b8efba9d75bc':
        raise ValueError('Appearance reset export changed')
    clear_evidence = h.comparison / 'details/run-b6794322d508/details.json'
    if h.audit.sha256(clear_evidence) != 'bfee5b4de16d285f38052b0f269171408059b055997f0a6374dd146a918d2f1e':
        raise ValueError('Appearance map clear export changed')
    leaf, table = 0x1464568a0, 0x149ca7190
    off = h.image.offset(leaf - h.image.pe.base)
    if h.raw[off:off + 16] != bytes.fromhex('4883c108e9b7fcffffcccccccccccccc'):
        raise ValueError('Appearance this-adjusting leaf changed')
    if struct.unpack_from('<Q', h.raw, h.image.offset(table - h.image.pe.base) + 0xa0)[0] != leaf:
        raise ValueError('Appearance reset vtable binding changed')
    # Explicitly reviewed ADD RCX,8; JMP body; following bytes are INT3 padding.
    h.ranges.append((leaf, leaf + 9))
    uc, x = h.uc, h.x
    owner, entries, bits, text = [h.scratch + n for n in (0x10000, 0x11000, 0x14000, 0x15000)]
    data = owner + 8
    frees, events = [], []

    def fixture(machine):
        at = machine.reg_read(x.UC_X86_REG_RIP)
        a, b = [machine.reg_read(reg) for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX)]
        if at == 0x141483160:
            if not text <= a < text + 0x1000: raise ValueError('Appearance free capture bound')
            frees.append(a)
        elif at == 0x1418cab30:
            if a != data + 0x30: raise ValueError('Appearance map preparation contract')
            events.append('map_prepare')
        elif at == 0x1414d8680:
            if a != data + 0x30 or b != 0: raise ValueError('Appearance storage resize contract')
            machine.mem_write(a, struct.pack('<Qii', 0, 0, 0))
            events.append('storage_release')
        else:
            raise ValueError('Unexpected bit allocation resize in bounded reset')
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)

    for at in hooks: fixtures[at] = fixture
    cases = []
    for count, occupied in ((0, ()), (1, (0,)), (4, (0, 2, 3)), (35, (0, 31, 32, 34))):
        for gender in (0, 1, 255):
            for buckets in (0, 1):
                frees.clear(); events.clear()
                uc.mem_write(owner - 16, b'\xa5' * (0x88 + 32))
                uc.mem_write(data + 0x10, struct.pack('<Qii', text, 2, 2))
                uc.mem_write(data + 0x28, bytes((gender,)))
                uc.mem_write(data + 0x30, bytes(0x50))
                uc.mem_write(data + 0x30, struct.pack('<Qii', entries if count else 0, count, count))
                uc.mem_write(data + 0x58, struct.pack('<ii', count, 128))
                uc.mem_write(data + 0x78, struct.pack('<i', buckets))
                words = [0] * max(1, (count + 31) // 32)
                expected = [text]
                for slot in occupied:
                    words[slot // 32] |= 1 << (slot % 32)
                    first, second = text + 0x10 + slot * 0x20, text + 0x20 + slot * 0x20
                    uc.mem_write(entries + slot * 0x30, struct.pack('<QiiQii', first, 2, 2, second, 2, 2) + bytes(16))
                    expected += [second, first]
                if count > 32:
                    uc.mem_write(bits, struct.pack('<' + 'I' * len(words), *words))
                    uc.mem_write(data + 0x50, struct.pack('<Q', bits))
                else: uc.mem_write(data + 0x40, struct.pack('<I', words[0]))
                before = bytes(uc.mem_read(data, 0x80))
                try: h.call(leaf, owner, budget=200000)
                except h.env.unicorn.UcError as error:
                    raise ValueError('Appearance reset fault at ' + hex(uc.reg_read(x.UC_X86_REG_RIP))) from error
                after = bytes(uc.mem_read(data, 0x80))
                if frees != expected: raise ValueError('Appearance reset free order differs')
                if after[:10] != bytes(10) or after[0x10:0x23] != bytes(0x13):
                    raise ValueError('Appearance scalar/string reset differs')
                if after[0x28:0x30] != before[0x28:0x30]: raise ValueError('Appearance reset overwrote gender')
                if struct.unpack_from('<i', after, 0x58)[0] != 0: raise ValueError('Appearance map not empty')
                if bytes(uc.mem_read(owner - 16, 24)) != b'\xa5' * 24 or bytes(uc.mem_read(owner + 0x88, 16)) != b'\xa5' * 16:
                    raise ValueError('Appearance reset guard changed')
                cases.append(dict(slots=count, occupied=list(occupied), gender=gender, buckets=buckets,
                    appearance=list(after[:10]), voice=after[0x20], map_slots_after=0,
                    frees=len(frees), events=events.copy(), gender_preserved=True, guards_unchanged=True))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        ghidra_evidence_sha256=h.audit.sha256(evidence), native_execution=True, network_used=False, cases=cases,
        map_clear_evidence_sha256=h.audit.sha256(clear_evidence),
        dependencies={name: h.audit.sha256(HERE / name) for name in
            ('replay-release-archive-input.py', 'build-native-entry-code.py', 'extract-native-enums.py',
             'build-object-zero-init-code.py', 'requirements-native.txt')},
        limits=['Whole reset and native sparse iterator execute through the reviewed this-adjusting leaf.',
            'Free, map preparation and storage resize are bounded fixtures; allocator ownership is not proven.',
            'Hash bucket counts 0/1 only; the separate >=2 hash rebuild branch is not covered.',
            'Reset empties parameters; later preview/preset/UI writes and final producer are not covered.',
            'Synthetic sparse entries, including external bit storage; no game or character creation.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-appearance-reset', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
