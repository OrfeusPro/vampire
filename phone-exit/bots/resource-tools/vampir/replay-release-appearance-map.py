"""Native appearance map lookup/insertion/update, with preallocated storage."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def run():
    spec = importlib.util.spec_from_file_location('appearance_map_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec); spec.loader.exec_module(archive)
    hooks = (0x141425e40, 0x14145f2c0, 0x141426780, 0x14142a330, 0x141483160)
    fixtures = dict.fromkeys(hooks)
    h = archive.make_harness(extra_addresses=(0x1464568b0, 0x1464368f0, 0x141c347f0,
        0x146436670, 0x141429760), fixtures=fixtures)
    exports = {}
    for run_name, sha in [('run-848ae1fda595', '7b7c0ee9850d31512fa18de2b32269ee4b321438b70043a77295052ecad92d46'),
                          ('run-7e832ccdbecf', '201f6b0f63ad81d478002a443f0d29440cd693adcd8c026db85aa3941b88f5f6'),
                          ('run-591e487095e6', '1218e6bdd0b07828910f6b15f37046e270804d374e1c28a891ea5b28ab9cb4c7'),
                          ('run-63252b970223', '612b9d67bb0cd1864dcc0ca037cd03ba178e3d773a42abd3c31b9f4efbf58e99')]:
        path = h.comparison / 'details' / run_name / 'details.json'
        if h.audit.sha256(path) != sha: raise ValueError('Appearance map export changed')
        exports[str(path)] = sha
    uc, x = h.uc, h.x
    owner, storage, buckets, name, input_string = [h.scratch + n for n in
        (0x10000, 0x11000, 0x14000, 0x15000, 0x16000)]
    mapping = owner + 0x30
    state, events = {}, []

    def u16(pointer, maximum=64):
        for length in range(maximum):
            if bytes(uc.mem_read(pointer + length * 2, 2)) == b'\0\0':
                return bytes(uc.mem_read(pointer, length * 2)).decode('utf-16le')
        raise ValueError('Appearance map UTF16 bound')

    def text(at):
        pointer, count, capacity = struct.unpack('<Qii', bytes(uc.mem_read(at, 16)))
        if not 0 <= count <= capacity <= 64: raise ValueError('Appearance map FString bound')
        return u16(pointer) if count else ''

    def write_text(at, value):
        data = value.encode('utf-16le') + b'\0\0'
        pointer = state['heap']; state['heap'] += 0x100
        if state['heap'] > h.scratch + 0x3f000: raise ValueError('Appearance map heap bound')
        uc.mem_write(pointer, data)
        uc.mem_write(at, struct.pack('<Qii', pointer, len(value) + 1, len(value) + 1))

    def hash_key(value):
        return 0 if state['collision'] else sum(value.encode('utf-16le'))

    def fixture(machine):
        at = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c = [machine.reg_read(reg) for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        result = None
        if at == 0x141425e40:
            if a > 64: raise ValueError('Appearance hash capture bound')
            value = bytes(machine.mem_read(b, a * 2)).decode('utf-16le') if a else ''
            result = hash_key(value)
        elif at == 0x14145f2c0:
            # Only exact ASCII keys are tested; do not infer engine case folding.
            left, right = u16(a), u16(b)
            result = 0 if left == right else 1
            events.append('compare')
        elif at == 0x141426780: write_text(a, text(b)); result = a
        elif at == 0x14142a330:
            if c > 64: raise ValueError('Appearance value key copy bound')
            write_text(a, bytes(machine.mem_read(b, c * 2)).decode('utf-16le') if c else ''); result = a
        elif at == 0x141483160:
            if not name <= a < h.scratch + 0x3f000: raise ValueError('Appearance map free bound')
        else: raise ValueError('Unknown appearance map fixture')
        if result is not None: machine.reg_write(x.UC_X86_REG_RAX, result)
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)

    for at in hooks: fixtures[at] = fixture
    cases = []
    keys = ('Height', 'Chest', 'Pelvis', 'Shape', 'Waist', 'Thigh', 'Head')
    for collision in (False, True):
        state.update(heap=h.scratch + 0x20000, collision=collision)
        uc.mem_write(owner - 16, b'\xa5' * 0xb0)
        uc.mem_write(mapping, bytes(0x50))
        uc.mem_write(mapping, struct.pack('<Qii', storage, 0, 64))
        uc.mem_write(mapping + 0x28, struct.pack('<iiii', 0, 128, -1, 0))
        uc.mem_write(mapping + 0x40, struct.pack('<Qi', buckets, 64))
        uc.mem_write(buckets, b'\xff' * 256)
        uc.mem_write(storage - 16, b'\xa5' * (64 * 0x30 + 32))
        expected = {}
        for key, value in list(zip(keys, (0.0, 0.125, -0.25, 0.5, 1.0, 1.25, -0.0))) + [('Height', 0.75), ('Shape', -2.5), ('Head', 0.25)]:
            events.clear()
            uc.mem_write(name, key.encode('utf-16le') + b'\0\0')
            uc.mem_write(input_string, struct.pack('<Qii', name, len(key) + 1, len(key) + 1))
            uc.reg_write(x.UC_X86_REG_XMM2, int.from_bytes(struct.pack('<f', value), 'little'))
            h.call(0x1464568b0, owner, input_string, budget=200000)
            expected[key] = struct.pack('<f', value).hex()
            count = struct.unpack('<i', bytes(uc.mem_read(mapping + 8, 4)))[0]
            free_count = struct.unpack('<i', bytes(uc.mem_read(mapping + 0x34, 4)))[0]
            if count != len(expected) or free_count != 0: raise ValueError('Appearance map duplicate or free count differs')
            actual = {}
            for slot in range(count):
                at = storage + slot * 0x30
                primary, secondary = text(at), text(at + 0x10)
                if primary != secondary: raise ValueError('Appearance map key/value names differ')
                actual[primary] = bytes(uc.mem_read(at + 0x20, 4)).hex()
            if actual != expected: raise ValueError('Appearance map values differ')
            bits = struct.unpack('<I', bytes(uc.mem_read(mapping + 0x10, 4)))[0]
            if bits != (1 << count) - 1: raise ValueError('Appearance map occupation bits differ')
            if bytes(uc.mem_read(owner - 16, 0x40)) != b'\xa5' * 0x40:
                raise ValueError('Appearance map crossed owner prefix')
            if bytes(uc.mem_read(storage - 16, 16)) != b'\xa5' * 16 or bytes(uc.mem_read(storage + 64 * 0x30, 16)) != b'\xa5' * 16:
                raise ValueError('Appearance map storage guard changed')
            cases.append(dict(collision=collision, key=key, stored_float_hex=expected[key],
                slots=count, values=actual, comparisons=len(events), guards_unchanged=True))
        # A synthetic valid sparse map spanning the 31/32 bit boundary, with a
        # free chain 0..33 and the sole live entry at 34. No resize is needed.
        uc.mem_write(mapping, bytes(0x50))
        uc.mem_write(mapping, struct.pack('<Qii', storage, 35, 64))
        uc.mem_write(mapping + 0x10, struct.pack('<II', 0, 4))
        uc.mem_write(mapping + 0x28, struct.pack('<iiii', 35, 128, 0, 34))
        uc.mem_write(mapping + 0x40, struct.pack('<Qi', buckets, 64))
        uc.mem_write(buckets, b'\xff' * 256)
        uc.mem_write(storage - 16, b'\xa5' * (64 * 0x30 + 32))
        for free in range(34):
            uc.mem_write(storage + free * 0x30, struct.pack('<ii', free - 1, free + 1 if free < 33 else -1))
        live = storage + 34 * 0x30
        write_text(live, 'Height'); write_text(live + 0x10, 'Height')
        uc.mem_write(live + 0x20, struct.pack('<f', 0.5))
        bucket = hash_key('Height') & 63
        uc.mem_write(live + 0x28, struct.pack('<iI', -1, bucket))
        uc.mem_write(buckets + bucket * 4, struct.pack('<i', 34))
        expected = {'Height': struct.pack('<f', 0.5).hex()}
        expected_slots = {'Height': 34}
        for key, value, expected_slot in (('Height', 0.75, 34), ('Chest', 0.25, 0), ('Pelvis', -0.25, 1)):
            events.clear()
            uc.mem_write(name, key.encode('utf-16le') + b'\0\0')
            uc.mem_write(input_string, struct.pack('<Qii', name, len(key) + 1, len(key) + 1))
            uc.reg_write(x.UC_X86_REG_XMM2, int.from_bytes(struct.pack('<f', value), 'little'))
            h.call(0x1464568b0, owner, input_string, budget=200000)
            expected[key] = struct.pack('<f', value).hex(); expected_slots[key] = expected_slot
            bits = int.from_bytes(uc.mem_read(mapping + 0x10, 8), 'little')
            if bits != sum(1 << slot for slot in expected_slots.values()):
                raise ValueError('Sparse appearance map reuse bits differ')
            if struct.unpack('<i', bytes(uc.mem_read(mapping + 8, 4)))[0] != 35:
                raise ValueError('Sparse appearance map reuse extended storage')
            free_count = struct.unpack('<i', bytes(uc.mem_read(mapping + 0x34, 4)))[0]
            if free_count != 35 - len(expected): raise ValueError('Sparse appearance free count differs')
            actual = {text(storage + slot * 0x30): bytes(uc.mem_read(storage + slot * 0x30 + 0x20, 4)).hex()
                for slot in range(35) if bits & (1 << slot)}
            if actual != expected: raise ValueError('Sparse appearance map reuse values differ')
            if any(text(storage + slot * 0x30 + 0x10) != name for name, slot in expected_slots.items()):
                raise ValueError('Sparse appearance map reuse value key differs')
            guards = (bytes(uc.mem_read(owner - 16, 0x40)) == b'\xa5' * 0x40
                and bytes(uc.mem_read(storage - 16, 16)) == b'\xa5' * 16
                and bytes(uc.mem_read(storage + 64 * 0x30, 16)) == b'\xa5' * 16)
            if not guards: raise ValueError('Sparse appearance reuse crossed guards')
            cases.append(dict(collision=collision, key=key, stored_float_hex=expected[key], slots=35,
                values=actual, free_count=free_count, occupied_slots=sorted(expected_slots.values()),
                comparisons=len(events), guards_unchanged=True))
    # Predicate is a reviewed ten-byte leaf, absent from unwind-root exports.
    predicate = 0x1464479f0
    offset = h.image.offset(predicate - h.image.pe.base)
    if h.raw[offset:offset + 16] != bytes.fromhex('0fb6013842480f94c0c3cccccccccccc'):
        raise ValueError('Preset predicate leaf boundary changed')
    page = predicate & ~4095
    if not any(a <= page <= b for a, b, _ in uc.mem_regions()):
        uc.mem_map(page, 4096); uc.mem_write(page, h.raw[h.image.offset(page - h.image.pe.base):][:4096])
    h.ranges.append((predicate, predicate + 10))
    predicate_cases = []
    for wanted in (0, 1, 2, 3, 4, 5, 100, 255):
        for row_type in (0, 1, 2, 3, 4, 5, 100, 255):
            uc.mem_write(name, bytes((wanted,))); uc.mem_write(input_string + 0x48, bytes((row_type,)))
            result = h.call(predicate, name, input_string) & 255
            if bool(result) != (wanted == row_type): raise ValueError('Preset type predicate differs')
            predicate_cases.append(dict(wanted=wanted, row_type=row_type, matches=bool(result)))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        native_execution=True, network_used=False, ghidra_exports=exports, cases=cases, predicate_cases=predicate_cases,
        dependencies={name: h.audit.sha256(HERE / name) for name in ('replay-release-archive-input.py',
            'build-native-entry-code.py', 'extract-native-enums.py', 'build-object-zero-init-code.py', 'requirements-native.txt')},
        limits=['Whole value helper, lookup, sparse insertion/update and occupation-bit append execute.',
            'String hash/compare/copy/free are fixtures with exact ASCII equality; engine case folding is not established.',
            'Preallocated 64 slots, 128 bits, 64 buckets; no capacity growth, rehash or allocator ownership claim.',
            'Free-list reuse uses a synthetic 35-slot map with one live entry; no native delete operation is claimed.',
            'Seven source-observed group names are explicit input values, not an actually loaded engine cache.',
            'Predicate byte equality executes; actual selected preset resource and its values are not established.',
            'No JSON, producer, game, authorization or character creation.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-appearance-map', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']), predicate_cases=len(report['predicate_cases']))))
