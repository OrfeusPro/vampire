"""Whole ordinary preset construction with source-bound schema and explicit metadata."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def run():
    archive = load('preset_object_archive', 'replay-release-archive-input.py')
    presets = load('preset_object_schema', 'extract-release-creation-presets.py')
    hooks = dict.fromkeys((0x1417e6110, 0x141483610, 0x1417d69b0, 0x14174cb20,
        0x14154ad50, 0x1487eac40, 0x141640fc0, 0x1416212b0, 0x141404a00,
        0x1416267a0, 0x141421c50))
    h = archive.make_harness(extra_addresses=(0x1417e6cb0, 0x1417ca780, 0x1417d2880,
        0x1454d6800, 0x143b5fa80, 0x1417cbc10, 0x1417cbe90, 0x141638a20,
        0x1417dd530, 0x1417daa00, 0x1417dda00, 0x14174fce0, 0x14174ba30,
        0x14174cc70, 0x1417d6b00), fixtures=hooks)
    uc, x = h.uc, h.x
    def at(address, count):
        offset = h.image.offset(address - h.image.pe.base)
        return h.raw[offset:offset + count]
    def mapped(address):
        page = address & ~4095
        if not any(a <= page <= b for a, b, _ in uc.mem_regions()):
            uc.mem_map(page, 4096); uc.mem_write(page, at(page, 4096))
    for address, code in ((0x141403c50, 'c20000'), (0x14140e3d0, '488d4108c3'),
        (0x14142a6c0, '48ff21'), (0x141632690, '448b4108f7d28bc24123c0413bc07404f0215108c3')):
        code = bytes.fromhex(code)
        if at(address, len(code)) != code: raise ValueError('Preset object reviewed leaf changed')
        mapped(address); h.ranges.append((address, address + len(code)))
    for table in (0x148a4c688, 0x1489e6448): mapped(table)
    overrides = []
    for offset in range(0, 0x2b0, 8):
        child = struct.unpack('<Q', at(0x1498514e8 + offset, 8))[0]
        parent = struct.unpack('<Q', at(0x148aa2ab8 + offset, 8))[0]
        if child != parent: overrides.append(dict(offset=offset, child=hex(child), parent=hex(parent)))
    if overrides != [dict(offset=0, child='0x145456a70', parent='0x14187df70')]:
        raise ValueError('Preset/DataAsset virtual comparison window changed')
    exports = {}
    for name, expected in (
        ('run-a9f0f96bdeb3', '895810a930e1e3dfd258c21f9607dac470e1ed00ffd192def4fa641119743d2d'),
        ('run-4dc9ed45997b', '31a525fd278305c809a76de6f0841513ad54357345f1fc904d314bc5fbe81a61'),
        ('run-5ec4a8b50550', '241744686e1b958ff818da0b6cbfe675f10b6f7da64cd3aa3df96dd1cafbed85'),
        ('run-d156ab446138', '269c2a6b770cbc23877e87eef0c307f437bacefc5546a6fe7d432dedf95730f9'),
        ('run-0fc58b2f30f3', '5866927a72e3deed60490ccc12bebc63dffc47a4fad916dca4fc6ae65c84c844')):
        path = h.comparison / 'details' / name / 'details.json'
        if h.audit.sha256(path) != expected: raise ValueError('Preset object export changed')
        exports[str(path)] = expected
    fields = [row for row in presets.schema(h.native.ROOT)['asset'] if row['flags'] != 0]
    instructions = {row['address']: row for fragment in h.fragments for row in fragment['instructions']}
    anchors = []
    for address, target in ((0x1417e6db4, 0x1417e6110), (0x1417e6f1e, 0x1417d2880),
                            (0x1417e6f30, 0x1417cbe90)):
        row = instructions.get(address)
        if not row or not row['call'] or row['direct_target'] != target:
            raise ValueError('Ordinary constructor call anchor changed')
        anchors.append(dict(address=hex(address), target=hex(target), bytes=row['bytes']))
    obj, source, cls, context, entries, initializer, parameters, chunks, chunk, parent, properties = [
        h.scratch + n for n in (0x10000, 0x11000, 0x12000, 0x13000, 0x14000,
            0x15000, 0x16000, 0x17000, 0x18000, 0x19000, 0x1c000)]
    gs = 0x30000000
    uc.mem_map(gs, 0x110000); uc.reg_write(x.UC_X86_REG_GS_BASE, gs)
    uc.mem_write(gs + 0x58, struct.pack('<Q', gs + 0x1000))
    uc.mem_write(gs + 0x1000, struct.pack('<Q', gs + 0x2000))
    uc.mem_write(gs + 0x2000 + 0x101184, struct.pack('<i', 1))
    for address in (0x14b6a7c20,): uc.mem_write(address, bytes(4))
    for address in (0x14b3e1b28, 0x14b3cf484, 0x14b3c6b5c): uc.mem_write(address, struct.pack('<i', 1))
    for address in (0x14b3ce8c0, 0x14b3e1b25, 0x14b2f3172): uc.mem_write(address, bytes(1))
    events, allocated, initializers_seen = [], [], []
    def fixture(machine):
        address = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c, d = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX,
            x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        events.append(hex(address)); result = 0
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        if address == 0x141483610: result = context
        elif address == 0x1417d69b0:
            count = int.from_bytes(machine.mem_read(context + 0x18, 4), 'little')
            if count != 1: raise ValueError('Preset current-initializer stack differs')
            result = int.from_bytes(machine.mem_read(entries, 8), 'little')
            initializers_seen.append(dict(object=int.from_bytes(machine.mem_read(result, 8), 'little'),
                copy_defaults=machine.mem_read(result + 0x11, 1)[0],
                defaults=int.from_bytes(machine.mem_read(result + 8, 8), 'little')))
        elif address == 0x1417e6110:
            if (a, b, c, d) != (cls, 0, 0, 0xb): raise ValueError('Ordinary allocation arguments differ')
            machine.mem_write(obj, bytes(0x78))
            machine.mem_write(obj + 8, struct.pack('<IIQ', 0x20b, 0, cls))
            reused_out = int.from_bytes(machine.mem_read(sp + 0x38, 8), 'little')
            if not h.stack - 0x800 <= reused_out < h.stack: raise ValueError('Allocation reuse output outside caller stack')
            machine.mem_write(reused_out, bytes(1)); result = obj; allocated.append(obj)
        elif address == 0x141404a00 and (a or b): raise ValueError('Nonempty delegate cleanup not covered')
        elif address == 0x1416267a0 and b: raise ValueError('Nonempty initializer cleanup not covered')
        machine.reg_write(x.UC_X86_REG_RAX, result)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)
    for address in hooks: hooks[address] = fixture
    cases = []
    for poison in (0, 0xa5, 0xff):
        for modified_template in (False, True):
            for link_mode in ('empty', 'all', 'alternate'):
                for address, size in ((cls, 0x400), (parent, 0x180), (context, 0x40),
                    (entries, 64), (source, 0x78), (parameters, 0x88), (properties, 17 * 0x80)):
                    uc.mem_write(address, bytes(size))
                uc.mem_write(cls, struct.pack('<Q', 0x148a4c688))
                for offset, value in ((0x40, parent), (0xb0, 0x1454d6800), (0x110, source)):
                    uc.mem_write(cls + offset, struct.pack('<Q', value))
                uc.mem_write(cls + 0x58, struct.pack('<I', 0x78))
                uc.mem_write(cls + 0xd4, struct.pack('<I', 0x10000001))
                uc.mem_write(context + 0x10, struct.pack('<QII', entries, 0, 8))
                uc.mem_write(chunks, struct.pack('<Q', chunk)); uc.mem_write(chunk, bytes(24))
                uc.mem_write(0x14b3e1c30, struct.pack('<Q', chunks))
                uc.mem_write(0x14b3e1c44, struct.pack('<I', 1))
                uc.mem_write(source + 8, struct.pack('<IIQ', 0x231, 0, cls))
                initializers_seen.clear()
                uc.mem_write(h.stack + 0x28, bytes(8))
                h.call(0x1417ca780, initializer, source, parent, 0, budget=100000)
                h.call(0x1454d6800, initializer, budget=100000)
                h.call(0x1417cbe90, initializer, budget=200000)
                native_defaults = bytes(uc.mem_read(source + 0x30, 0x41))
                if native_defaults != bytes(36) + struct.pack('<7fB', *([0.5] * 7), 0):
                    raise ValueError('Zero-allocation CDO model defaults differ')
                uc.mem_write(h.stack + 0x28, bytes(8))
                if h.call(0x1417d6b00, cls, 0, 0, 0, budget=100000) != source:
                    raise ValueError('Simple archetype selector did not return class CDO')
                if modified_template:
                    for i, field in enumerate(fields):
                        fmt, value = ('<i', i + 100) if i < 9 else ('<f', (i - 8) / 16) if i < 16 else ('<B', 3)
                        uc.mem_write(source + field['offset'], struct.pack(fmt, value))
                included = [] if link_mode == 'empty' else list(range(17)) if link_mode == 'all' else list(range(0, 17, 2))
                for position, i in enumerate(included):
                    prop = properties + i * 0x80; field = fields[i]
                    uc.mem_write(prop + 0x30, struct.pack('<iiQ', 1, 1 if i == 16 else 4, 1 << 30))
                    uc.mem_write(prop + 0x44, struct.pack('<i', field['offset']))
                    following = properties + included[position + 1] * 0x80 if position + 1 < len(included) else 0
                    uc.mem_write(prop + 0x60, struct.pack('<Q', following))
                uc.mem_write(cls + 0x88, struct.pack('<Q', properties + included[0] * 0x80 if included else 0))
                uc.mem_write(parameters, struct.pack('<QQQII', cls, 0, 0, 0xb, 0))
                uc.mem_write(parameters + 0x28, struct.pack('<Q', source))
                uc.mem_write(obj - 16, bytes((poison,)) * (0x78 + 32))
                events.clear(); allocated.clear(); h.call(0x1417e6cb0, parameters, budget=300000)
                if allocated != [obj]: raise ValueError('Unexpected allocation count')
                if initializers_seen != [dict(object=source, copy_defaults=0, defaults=parent),
                                         dict(object=obj, copy_defaults=1, defaults=source)]:
                    raise ValueError('Native ordinary initializer defaults/copy flag differ')
                expected = bytearray(native_defaults)
                for i in included:
                    field = fields[i]; width = 1 if i == 16 else 4; off = field['offset'] - 0x30
                    expected[off:off + width] = uc.mem_read(source + field['offset'], width)
                if bytes(uc.mem_read(obj + 0x30, 0x41)) != bytes(expected):
                    raise ValueError('Ordinary native defaults transfer differs')
                if int.from_bytes(uc.mem_read(obj + 8, 4), 'little') != 0xb:
                    raise ValueError('Ordinary object not completed')
                if bytes(uc.mem_read(context + 0x18, 4)) != bytes(4) or bytes(uc.mem_read(context + 0x28, 4)) != bytes(4):
                    raise ValueError('Ordinary context not restored')
                if any(bytes(uc.mem_read(a, 16)) != bytes((poison,)) * 16 for a in (obj - 16, obj + 0x78)):
                    raise ValueError('Ordinary allocation guard changed')
                cases.append(dict(poison=poison, modified_template=modified_template, link_mode=link_mode,
                    copied_fields=[fields[i]['name'] for i in included], completed_flags=0xb,
                    ordinary_copy_flag=1, archetype_selected_class_CDO=True,
                    default_bytes=native_defaults.hex(), output_bytes=bytes(expected).hex(), guards_unchanged=True))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        native_execution=True, network_used=False, cases=cases, ghidra_exports=exports,
        source_fields=fields, call_anchors=anchors, vtable_comparison_window=0x2b0, vtable_overrides=overrides,
        dependencies={name: h.audit.sha256(HERE / name) for name in ('replay-release-archive-input.py',
            'extract-release-creation-presets.py', 'build-native-entry-code.py', 'extract-native-enums.py',
            'build-object-zero-init-code.py', 'requirements-native.txt')},
        limits=['Whole ordinary constructor 1417e6cb0 and nested initializer/base constructors/completion/postconstruct/InitProperties execute.',
            'Allocation is an explicit zeroing fixture for the statically verified fresh-allocation branch; native allocator is not executed.',
            'Class/property lists, no config/empty subobjects, cached TLS and object-array metadata are fixtures. Property offsets come from current native descriptors; runtime POD flags/list membership are synthetic.',
            'TLS/current-initializer lookup, empty cleanup, bookkeeping, feature query, selector boolean and security check are fixtures; immediate completion only.',
            'Modified template values are deliberate controls. Native-default vector is conditional on the zero-allocation model, not live CDO memory.',
            'Whole archetype selector 1417d6b00 also executes for null outer/zero flags only; outer-specific and superclass selection are not covered.',
            'No package loader, property deserialization, late overrides, JSON, game, authorization or network.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-preset-object', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
