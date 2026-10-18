"""Preserve verified SceneComponent constructor defaults, without applying archetypes."""
import hashlib, importlib.util, json, os, struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main(root):
    spec = importlib.util.spec_from_file_location('scene_defaults_native', HERE / 'build-native-entry-code.py')
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    source = json.loads((root / 'code-clues/native-enums.json').read_text('utf-8'))
    exe = Path(source['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest() != source['sha256']:
        raise ValueError('Changed client EXE')
    im = native.Image(exe)
    roots = {im.roots[im.containing(a)] for a in [0x1454fd410, 0x1437d4d80, 0x143ac1400]}
    fragments = native.decode_ranges(im, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    anchors = []
    expected = [
        (0x1454fd4eb, 'call', '0x1437d4d80'),
        (0x1454fd4f0, 'mov', 'r9, rax'),
        (0x1454fd4f8, 'mov', 'r8, rax'),
        (0x1454fd506, 'call', '0x141746350'),
        (0x1454fd50b, 'mov', 'qword ptr [rsi + 0x3c0], rax'),
        (0x1437d4de7, 'lea', 'rax, [rip - 0x53e]'),
        (0x1437d4dee, 'mov', 'qword ptr [r11 - 0x30], rax'),
        (0x143ac1406, 'mov', 'rbx, rcx'),
        (0x143ac1409, 'call', '0x143a28f20'),
        (0x143ac1423, 'xor', 'eax, eax'),
        (0x143ac142c, 'mov', 'qword ptr [rbx + 0xb0], rax'),
        (0x143ac1495, 'movabs', 'rax, 0x3ff0000000000000'),
        (0x143ac1517, 'mov', 'qword ptr [rbx + 0x158], rax'),
        (0x143ac151e, 'mov', 'qword ptr [rbx + 0x160], rax'),
        (0x143ac1525, 'mov', 'qword ptr [rbx + 0x168], rax'),
    ]
    for address, mnemonic, operands in expected:
        row = rows[address]
        if (row['mnemonic'], row['operands']) != (mnemonic, operands):
            raise ValueError('Changed SceneComponent constructor anchor')
        anchors.append(row)
    literal = rows[0x1437d4dc6]
    name = 'SceneComponent'.encode('utf-16le') + b'\0\0'
    if len(literal['rip_references']) != 1:
        raise ValueError('Ambiguous SceneComponent class literal')
    no = im.offset(literal['rip_references'][0] - im.pe.base)
    if exe[no:no + len(name)] != name:
        raise ValueError('Changed SceneComponent class name')
    anchors.append(literal)
    # Leaf wrapper has no unwind range: verify every byte, including the tail jump.
    wo = im.offset(0x37d48b0)
    wrapper = exe[wo:wo + 20]
    if wrapper != bytes.fromhex('488b014885c0740b488bd1488bc8e93dcb2e00c3'):
        raise ValueError('Changed SceneComponent constructor wrapper')
    if 0x1437d48c3 + struct.unpack_from('<i', wrapper, 15)[0] != 0x143ac1400:
        raise ValueError('Changed SceneComponent constructor target')
    descriptors = []
    for va, prop, offset in [(0x14912a300, 'AttachParent', 0xb0), (0x14912a500, 'RelativeScale3D', 0x158)]:
        pos = im.offset(va - im.pe.base)
        raw = exe[pos:pos + 56]
        pn = im.offset(struct.unpack_from('<Q', raw)[0] - im.pe.base)
        if exe[pn:pn + len(prop) + 1] != prop.encode() + b'\0' or struct.unpack_from('<I', raw, 50)[0] != offset:
            raise ValueError('Changed SceneComponent property offset')
        descriptors.append(dict(name=prop, address=va, file_offset=pos, bytes=raw.hex(), name_offset=pn, object_offset=offset))
    report = dict(source=source, native_anchors=anchors, native_fragments=fragments,
                  class_literal=dict(file_offset=no, bytes=name.hex()),
                  constructor_wrapper=dict(address=0x1437d48b0, file_offset=wo, bytes=wrapper.hex(), target=0x143ac1400),
                  native_descriptors=descriptors,
                  constructor_defaults=dict(AttachParent=None, RelativeScale3D=[1.0, 1.0, 1.0]),
                  applied_to_instances=False, world_transforms_verified=False,
                  limitations=['Defaults describe native construction before Blueprint/archetype/instance/runtime overrides.',
                               'RelativeLocation/RelativeRotation zero defaults and absolute flags are not established here.',
                               'No missing serialized value is filled, no endpoint is projected and no route is certified.'])
    path = root / 'maps/navigation-study/lift-blueprints/scene-native-defaults.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(native_anchors=len(anchors), sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report


if __name__ == '__main__':
    main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir')))
