"""Execute current InitProperties with explicit source-class size boundaries."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def run():
    spec = importlib.util.spec_from_file_location('preset_copy_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec); spec.loader.exec_module(archive)
    hooks = dict.fromkeys((0x14174cc70, 0x141403c50))
    h = archive.make_harness(extra_addresses=(0x1417daa00,), fixtures=hooks)
    exports = {}
    for name, expected in (
        ('run-d156ab446138', '269c2a6b770cbc23877e87eef0c307f437bacefc5546a6fe7d432dedf95730f9'),
        ('run-8d3476afb3ca', '6ccc08da7e16914ec25df902900a55e91eb462920a15f59da0946cc012274a0a'),
        ('run-5ec4a8b50550', '241744686e1b958ff818da0b6cbfe675f10b6f7da64cd3aa3df96dd1cafbed85')):
        path = h.comparison / 'details' / name / 'details.json'
        if h.audit.sha256(path) != expected: raise ValueError('Preset default-copy export changed')
        exports[str(path)] = expected
    uc, x = h.uc, h.x
    obj, source, actual_class, source_class, prop = [h.scratch + n for n in
        (0x10000, 0x11000, 0x12000, 0x13000, 0x14000)]
    events = []

    def fixture(machine):
        events.append(hex(machine.reg_read(x.UC_X86_REG_RIP)))
        machine.reg_write(x.UC_X86_REG_RAX, 0)
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)

    for address in hooks: hooks[address] = fixture
    cases = []
    # General path models copying from a distinct parent class. Native optimized
    # path uses the actual class as source. Both compare the property end to size.
    for optimized in (False, True):
        for size in (0x30, 0x34, 0x78):
            for offset, width, count in ((0x2c, 4, 1), (0x30, 4, 1), (0x40, 4, 1),
                                         (0x50, 4, 1), (0x70, 1, 1), (0x2c, 4, 2)):
                events.clear()
                uc.mem_write(obj - 16, b'\xa5' * (0x78 + 32))
                uc.mem_write(source, bytes(range(0x78)))
                for address in (actual_class, source_class, prop): uc.mem_write(address, bytes(0x180))
                uc.mem_write(obj + 8, struct.pack('<I', 0x10))  # CDO flag, no transient copy.
                uc.mem_write(obj + 0x10, struct.pack('<Q', actual_class))
                uc.mem_write(actual_class + 0xd4, struct.pack('<I', 0x10000080))
                uc.mem_write(actual_class + 0x70, struct.pack('<Q', prop))
                uc.mem_write(prop + 0x30, struct.pack('<iiQ', count, width, 1 << 30))
                uc.mem_write(prop + 0x44, struct.pack('<i', offset))
                selected_class = actual_class if optimized else source_class
                uc.mem_write(selected_class + 0x58, struct.pack('<I', size))
                before = bytes(uc.mem_read(obj - 16, 0x78 + 32))
                h.call(0x1417daa00, obj, selected_class, source, 0, budget=100000)
                expected = bytearray(before)
                copied = offset + width * count <= size
                if copied: expected[16 + offset:16 + offset + width * count] = bytes(range(offset, offset + width * count))
                if bytes(uc.mem_read(obj - 16, len(expected))) != bytes(expected):
                    raise ValueError('Native default copy crossed source size or changed another byte')
                if events != ['0x14174cc70', '0x141403c50']:
                    raise ValueError('Unexpected default-copy fixture order')
                cases.append(dict(optimized=optimized, source_size=size, offset=offset,
                    width=width, count=count, copied=copied, guards_unchanged=True))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        native_execution=True, network_used=False, entry='0x1417daa00', cases=cases,
        ghidra_exports=exports,
        dependencies={name: h.audit.sha256(HERE / name) for name in
            ('replay-release-archive-input.py', 'build-native-entry-code.py',
             'extract-native-enums.py', 'build-object-zero-init-code.py', 'requirements-native.txt')},
        limits=['Whole InitProperties executes for synthetic native-class/property fixtures with POD-copy flag.',
            'Two initial bookkeeping hooks and bounded CRT memcpy are fixtures; property metadata and source bytes are synthetic.',
            'General parent-copy and optimized non-CDO-source branches are covered; virtual property copy, transient and own-CDO branches are not.',
            'Allocator zero branch and DataAsset size 0x30 are static evidence, not native allocator execution.',
            'Does not execute full CDO creation, constructors, property deserialization or later overrides; omitted preset integers remain unresolved.',
            'No game, authorization or network.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-preset-default-copy', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
