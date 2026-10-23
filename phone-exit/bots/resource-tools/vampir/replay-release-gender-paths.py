"""Native enum-value/name selection and FString suffix trimming for appearance."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def run():
    spec = importlib.util.spec_from_file_location('gender_path_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec); spec.loader.exec_module(archive)
    hooks = (0x144aabaf0, 0x1415be5c0, 0x14142e100, 0x14142c590, 0x141433420, 0x141483160, 0x1487f7a1f)
    fixtures = dict.fromkeys(hooks)
    h = archive.make_harness(extra_addresses=(0x145671130, 0x14566c5e0, 0x1416dd790,
        0x1416dd6b0, 0x141434a50, 0x141438260), fixtures=fixtures)
    exports = {}
    for run_name, sha in [('run-29d6ad1c7c55', '4310f3e2818acc70b48594790eea46aa9f996529ceaf782fce06ba36cd60d2e2'),
                          ('run-c1cdaeaa2d5d', '91313b2e519a3672685d7895ec3525cf7c61dd5b0446c38733ba8dbf817b4941'),
                          ('run-a765429bb389', '17d731903385244bf3ebe84b5f537b4e21ca2a43cabc888bde4cedd4594baa49')]:
        path = h.comparison / 'details' / run_name / 'details.json'
        if h.audit.sha256(path) != sha: raise ValueError('Gender path export changed')
        exports[str(path)] = sha
    def at(address, count):
        off = h.image.offset(address - h.image.pe.base)
        return h.raw[off:off + count]
    def ascii_at(address): return at(address, 128).split(b'\0')[0].decode('ascii')
    params = at(0x14b197320, 48)
    name_at, cpp_name_at, rows_at = struct.unpack_from('<QQQ', params, 16)
    count = struct.unpack_from('<H', params, 44)[0]
    if ascii_at(name_at) != 'EGenderType' or cpp_name_at != name_at or count != 3 or params[47] != 2:
        raise ValueError('Gender enum params differ')
    enums = []
    for i in range(count):
        pointer, value = struct.unpack('<Qq', at(rows_at + i * 16, 16))
        enums.append(dict(name=ascii_at(pointer), value=value))
    if enums != [dict(name='EGenderType::' + name, value=value) for name, value in [('Male', 0), ('Female', 1), ('Max', 2)]]:
        raise ValueError('Gender enum values differ')
    thunk = at(0x1487f7a1f, 6)
    if thunk[:2] != b'\xff\x25': raise ValueError('Gender memmove thunk changed')
    imported = h.imports.import_at(h.raw, h.image, 0x1487f7a1f + 6 + struct.unpack_from('<i', thunk, 2)[0])
    if (imported['dll'].lower(), imported['name']) != ('vcruntime140.dll', 'memmove'):
        raise ValueError('Gender memmove import differs')
    uc, x = h.uc, h.x
    enum, rows, output = [h.scratch + n for n in (0x10000, 0x11000, 0x12000)]
    uc.mem_write(enum, bytes(0x60)); uc.mem_write(enum + 0x40, struct.pack('<Qi', rows, count))
    uc.mem_write(enum + 0x50, b'\x02')
    for i, row in enumerate(enums): uc.mem_write(rows + i * 16, struct.pack('<Qq', i + 1, row['value']))
    state, captured = {}, []

    def literal(pointer):
        for count in range(128):
            if bytes(uc.mem_read(pointer + count * 2, 2)) == b'\0\0':
                return bytes(uc.mem_read(pointer, count * 2)).decode('utf-16le')
        raise ValueError('Gender UTF16 bound')

    def text(pointer):
        data, count, capacity = struct.unpack('<Qii', bytes(uc.mem_read(pointer, 16)))
        if not 0 <= count <= capacity <= 128: raise ValueError('Gender FString bound')
        return literal(data) if count else ''

    def assign(pointer, value):
        data = value.encode('utf-16le') + b'\0\0'
        heap = state['heap']; state['heap'] += 0x200
        if state['heap'] > h.scratch + 0x30000: raise ValueError('Gender heap bound')
        uc.mem_write(heap, data); uc.mem_write(pointer, struct.pack('<Qii', heap, len(value) + 1, len(value) + 1))

    def fixture(machine):
        current = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c = [machine.reg_read(reg) for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        result = None
        if current == 0x144aabaf0: result = enum if state['present'] else 0
        elif current == 0x1415be5c0:
            token = int.from_bytes(machine.mem_read(a, 8), 'little')
            if not 1 <= token <= count: raise ValueError('Gender FName token outside source enum')
            assign(b, enums[token - 1]['name']); result = b
        elif current == 0x14142e100:
            if literal(b) != '::' or c != 2: raise ValueError('Gender namespace search contract')
            result = text(a).find('::') & 0xffffffff
        elif current == 0x14142c590:
            if c > 128: raise ValueError('Gender substring copy bound')
            assign(a, bytes(machine.mem_read(b, c * 2)).decode('utf-16le')); result = a
        elif current == 0x141433420:
            format_text, suffix = literal(b), literal(c)
            if format_text not in ('Customize/DT_CustomizePreset%s', 'Customize/DT_CustomizeBoneGroup%s'):
                raise ValueError('Gender path format differs')
            captured.append(dict(format=format_text, suffix=suffix))
            assign(a, format_text.replace('%s', suffix)); result = a
        elif current == 0x1487f7a1f:
            if c > 256 or not all(h.scratch <= p <= h.scratch + 0x40000 - c for p in (a, b)):
                raise ValueError('Gender memmove capture bound')
            machine.mem_write(a, bytes(machine.mem_read(b, c))); result = a
        elif current == 0x141483160:
            if not h.scratch + 0x20000 <= a < h.scratch + 0x30000: raise ValueError('Gender free capture bound')
        else: raise ValueError('Unknown gender fixture')
        if result is not None: machine.reg_write(x.UC_X86_REG_RAX, result)
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)

    for address in hooks: fixtures[address] = fixture
    cases = []
    for function, pattern in ((0x145671130, 'Customize/DT_CustomizePreset'), (0x14566c5e0, 'Customize/DT_CustomizeBoneGroup')):
        for present in (False, True):
            for value in range(256):
                state.update(heap=h.scratch + 0x20000, present=present); captured.clear()
                uc.mem_write(output - 16, b'\xa5' * 48)
                result = h.call(function, output, value, budget=200000)
                suffix = ('M', 'F', 'M')[value] if present and value < 3 else ''
                if result != output or text(output) != pattern + suffix:
                    raise ValueError('Gender path differs from source-bound enum selection')
                if captured != [dict(format=pattern + '%s', suffix=suffix)]:
                    raise ValueError('Gender path suffix capture differs')
                if bytes(uc.mem_read(output - 16, 16)) != b'\xa5' * 16 or bytes(uc.mem_read(output + 16, 16)) != b'\xa5' * 16:
                    raise ValueError('Gender path output guard changed')
                cases.append(dict(function=hex(function), enum_present=present, value=value,
                    suffix=suffix, path=pattern + suffix, guards_unchanged=True))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        native_execution=True, network_used=False, enum_params=hex(0x14b197320), enum_rows=enums,
        ghidra_exports=exports, memmove_import=imported, cases=cases,
        dependencies={name: h.audit.sha256(HERE / name) for name in ('replay-release-archive-input.py',
            'build-native-entry-code.py', 'extract-native-enums.py', 'build-object-zero-init-code.py', 'requirements-native.txt')},
        limits=['Whole two path helpers, enum value/index/name selection and native FString trim/substring execute.',
            'UEnum/FName tokens are source-bound fixtures; FName-to-string, namespace search, string allocation/copy/free, formatting and CRT memmove are bounded captures/fixtures.',
            'Max=2 yields M, not rejection; this sentinel is not a valid creation gender. Missing enum/unmatched byte yields an unsuffixed path.',
            'Paths do not prove active cache/resource loading, current UI scale/min/max or CDO integer defaults.',
            'No authorization, game or character creation.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-gender-paths', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
