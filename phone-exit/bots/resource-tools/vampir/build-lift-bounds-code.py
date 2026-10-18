"""Verify PointLinks local-bounds consumer and root-component reads in the client."""
import hashlib, importlib.util, json, os, struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main(root):
    spec = importlib.util.spec_from_file_location('lift_bounds_native', HERE / 'build-native-entry-code.py')
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    source = json.loads((root / 'code-clues/native-enums.json').read_text('utf-8'))
    exe = Path(source['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest() != source['sha256']:
        raise ValueError('Changed client EXE')
    im = native.Image(exe)
    fragments = native.decode_ranges(im, {im.roots[im.containing(a)] for a in [0x1454fd410, 0x14550d6c0]})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    expected = [
        (0x1454fd432, 'lea', 'rax, [rip + 0x4383947]'),
        (0x1454fd439, 'mov', 'qword ptr [rsi], rax'),
        (0x14550d6f8, 'mov', 'rdi, rcx'),
        (0x14550d749, 'cmp', 'dword ptr [rcx + 0x3e8], r8d'),
        (0x14550d772, 'mov', 'rax, qword ptr [rdi + 0x3e0]'),
        (0x14550d779, 'lea', 'rcx, [rcx + 0x70]'),
        (0x14550d77f, 'movsd', 'xmm1, qword ptr [rcx + rax - 0x30]'),
        (0x14550d785, 'minsd', 'xmm1, qword ptr [rbx]'),
        (0x14550d7a9, 'maxsd', 'xmm0, xmm6'),
        (0x14550d7c8, 'minsd', 'xmm1, qword ptr [rcx + rax - 0x18]'),
        (0x14550d7ee, 'maxsd', 'xmm6, xmm0'),
        (0x14550d80d, 'cmp', 'edx, dword ptr [rdi + 0x3e8]'),
        (0x14550d9fa, 'mov', 'rax, qword ptr [rdi + 0x1b8]'),
        (0x14550da0c, 'add', 'rax, 0x1d0'),
        (0x14550da19, 'movups', 'xmm8, xmmword ptr [rax + 0x50]'),
        (0x14550da1e, 'movups', 'xmm12, xmmword ptr [rax + 0x40]'),
        (0x14550da23, 'movups', 'xmm10, xmmword ptr [rax]'),
        (0x14550da27, 'movups', 'xmm4, xmmword ptr [rax + 0x10]'),
    ]
    anchors = []
    for address, mnemonic, operands in expected:
        row = rows[address]
        if (row['mnemonic'], row['operands']) != (mnemonic, operands):
            raise ValueError('Changed lift bounds anchor')
        anchors.append(row)
    vtable = rows[0x1454fd432]['rip_references'][0]
    slot_offset = im.offset(vtable - im.pe.base) + 199 * 8
    if struct.unpack_from('<Q', exe, slot_offset)[0] != 0x14550d6c0:
        raise ValueError('Changed lift bounds vtable slot')
    descriptors = []
    for va, name, offset in [(0x14987d370, 'PointLinks', 0x3e0), (0x1490c1370, 'Left', 0x40), (0x1490c13b0, 'Right', 0x58), (0x149168fe0, 'RootComponent', 0x1b8)]:
        pos = im.offset(va - im.pe.base)
        raw = exe[pos:pos + 56]
        no = im.offset(struct.unpack_from('<Q', raw)[0] - im.pe.base)
        if exe[no:no + len(name) + 1] != name.encode() + b'\0' or struct.unpack_from('<I', raw, 50)[0] != offset:
            raise ValueError('Changed bounds property descriptor')
        descriptors.append(dict(name=name, address=va, file_offset=pos, bytes=raw.hex(), object_offset=offset))
    report = dict(source=source, native_anchors=anchors, native_fragments=fragments, native_descriptors=descriptors,
                  vtable_slot=dict(table_address=vtable, index=199, file_offset=slot_offset, bytes=exe[slot_offset:slot_offset + 8].hex(), target=0x14550d6c0),
                  point_link_stride=0x70, local_endpoint_offsets=[0x40, 0x58], root_storage_read_offset=0x1d0,
                  world_endpoint_formula_verified=False, runtime_walkability_verified=False,
                  limitations=['Min/max accumulation of both endpoints verifies a bounds consumer, not navigation export or traversal.',
                               'The same method later reads RootComponent storage at +0x1d0; exact cached transform layout/update lifecycle and endpoint projection remain unresolved.',
                               'Vtable slot number is evidence for this client build; no symbolic method name assigned.'])
    path = root / 'maps/navigation-study/lift-blueprints/bounds-code.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(native_anchors=len(anchors), sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report


if __name__ == '__main__':
    main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir')))
