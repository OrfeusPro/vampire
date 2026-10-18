"""Verify post-constructor template selection and property copy in the client."""
import hashlib, importlib.util, json, os, struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main(root):
    def module(name, file):
        s = importlib.util.spec_from_file_location(name, HERE / file)
        m = importlib.util.module_from_spec(s)
        s.loader.exec_module(m)
        return m
    native = module('template_copy_native', 'build-native-entry-code.py')
    imports = module('template_copy_imports', 'build-object-zero-init-code.py')
    source = json.loads((root / 'code-clues/native-enums.json').read_text('utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Changed client EXE')
    im = native.Image(data)
    addresses = [0x1417c61a0, 0x1417d7840, 0x1417d4d10, 0x143ac1400, 0x143a537b0]
    fragments = native.decode_ranges(im, {im.roots[im.containing(a)] for a in addresses})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    expected = [
        (0x1417c626d, 'cmp', 'qword ptr [rdi + 8], 0'),
        (0x1417c6288, 'call', '0x1416aaaf0'),
        (0x1417c628d, 'mov', 'rax, qword ptr [rbx + 0x110]'),
        (0x1417c6294, 'mov', 'qword ptr [rdi + 8], rax'),
        (0x1417c62b4, 'mov', 'rcx, rdi'),
        (0x1417c62b7, 'call', '0x1417d7840'),
        (0x1417d79e1, 'cmp', 'byte ptr [rdi + 0x11], 0'),
        (0x1417d79e5, 'je', '0x1417d7a25'),
        (0x1417d79fe, 'mov', 'r8, qword ptr [rdi + 8]'),
        (0x1417d7a09, 'test', 'r8, r8'),
        (0x1417d7a0c, 'jne', '0x1417d7a15'),
        (0x1417d7a0e, 'mov', 'r8, qword ptr [r13 + 0x110]'),
        (0x1417d7a1d, 'mov', 'rcx, qword ptr [rdi]'),
        (0x1417d7a20, 'call', '0x1417d4d10'),
        (0x1417d7a80, 'mov', 'rdx, qword ptr [rbx + rdx + 8]'),
        (0x1417d7a88, 'mov', 'r8, rdx'),
        (0x1417d7a8b, 'mov', 'rcx, rbp'),
        (0x1417d7a92, 'call', '0x1417d4d10'),
        (0x1417d7aba, 'add', 'rbx, 0x10'),
        (0x1417d4d25, 'mov', 'rbp, r8'),
        (0x1417d4d2b, 'mov', 'r14, rcx'),
        (0x1417d4dfd, 'movsxd', 'r9, dword ptr [rbx + 0x30]'),
        (0x1417d4e01, 'movsxd', 'r11, dword ptr [rbx + 0x34]'),
        (0x1417d4e08, 'movsxd', 'r8, dword ptr [rbx + 0x44]'),
        (0x1417d4e17, 'lea', 'rdx, [r8 + rbp]'),
        (0x1417d4e1b, 'lea', 'r10, [r8 + r14]'),
        (0x1417d4e24, 'bt', 'rcx, 0x1e'),
        (0x1417d4e29, 'jae', '0x1417d4e3c'),
        (0x1417d4e2b, 'mov', 'r8, r9'),
        (0x1417d4e2e, 'mov', 'rcx, r10'),
        (0x1417d4e31, 'imul', 'r8, r11'),
        (0x1417d4e35, 'call', '0x1487a2e19'),
        (0x1417d4e48, 'call', 'qword ptr [rax + 0x100]'),
        (0x1417d4ed5, 'call', '0x1487a2e19'),
        (0x1417d5046, 'call', '0x1487a2e19'),
        (0x1417d5070, 'call', 'qword ptr [rax + 0x398]'),
        (0x1417d7c2c, 'call', 'qword ptr [rax + 0x58]'),
        (0x1417d7c88, 'call', 'qword ptr [rax + 0x50]'),
        (0x143ac140e, 'lea', 'rax, [rip + 0x566e9d3]'),
        (0x143ac1415, 'mov', 'qword ptr [rbx], rax'),
        (0x143a537b9, 'call', '0x1417d7d10'),
        (0x143a537be, 'mov', 'rcx, qword ptr [rbx + 0x90]'),
        (0x143a537db, 'jmp', '0x1438002a0'),
    ]
    anchors = []
    for address, mnemonic, operands in expected:
        row = rows[address]
        if (row['mnemonic'], row['operands']) != (mnemonic, operands):
            raise ValueError('Changed template copy anchor at ' + hex(address))
        anchors.append(row)
    offset = im.offset(0x87a2e19)
    trampoline = data[offset:offset + 6]
    if trampoline[:2] != b'\xff\x25':
        raise ValueError('Changed template copy import trampoline')
    target = 0x1487a2e19 + 6 + struct.unpack_from('<i', trampoline, 2)[0]
    binding = imports.import_at(data, im, target)
    if binding['name'] != 'memcpy' or binding['dll'].lower() != 'vcruntime140.dll':
        raise ValueError('Copy target is not named memcpy')
    scene_vtable = rows[0x143ac140e]['rip_references'][0]
    slots = []
    for byte_offset, expected_target in [(0x50, 0x143a537b0), (0x58, 0x1413fe190)]:
        pos = im.offset(scene_vtable - im.pe.base) + byte_offset
        if struct.unpack_from('<Q', data, pos)[0] != expected_target:
            raise ValueError('Changed SceneComponent post-init slot')
        slots.append(dict(table_address=scene_vtable, byte_offset=byte_offset, file_offset=pos,
                          bytes=data[pos:pos + 8].hex(), target=expected_target))
    empty_pos = im.offset(0x13fe190)
    if data[empty_pos:empty_pos + 3] != b'\xc2\x00\x00':
        raise ValueError('Changed empty SceneComponent callback')
    report = dict(source=source, native_anchors=anchors, native_fragments=fragments,
                  trampoline=dict(address=0x1487a2e19, file_offset=offset, bytes=trampoline.hex(), target=target),
                  import_binding=binding,
                  scene_post_init_slots=slots, empty_callback=dict(address=0x1413fe190, file_offset=empty_pos, bytes='c20000'),
                  copy_model=dict(target_object_register='r14', source_object_register='rbp',
                                  property_offset_storage=0x44, size_factor_storages=[0x30, 0x34],
                                  raw_copy_property_flag_bit=30, alternate_property_callback_slot=0x100),
                  template_copy_branch_verified=True, final_rotation_default_verified=False,
                  limitations=['Generic native property copy and template selection branches verified; specific RelativeRotation runtime FProperty and source CDO bytes have not been resolved.',
                               'Initial class descriptor bytes are not the constructed runtime FProperty layout; offsets/flags must not be interchanged.',
                               'Conditional/deferred initialization, per-property copy callbacks, post-init virtual callbacks and runtime overrides remain; no omitted value filled.'])
    path = root / 'maps/navigation-study/lift-blueprints/object-template-copy-code.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(anchors=len(anchors), import_name=binding['name'], sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report


if __name__ == '__main__':
    main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir')))
