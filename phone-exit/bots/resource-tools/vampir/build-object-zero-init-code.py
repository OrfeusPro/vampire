"""Verify the default-subobject allocation path and named memset import.

This proves a zeroing branch, not the final state of a SceneComponent or its CDO.
"""
import hashlib, importlib.util, json, os, struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def import_at(data, image, target):
    pe = struct.unpack_from('<I', data, 60)[0]
    rva, size = struct.unpack_from('<II', data, pe + 24 + 112 + 8)
    if not rva or not 20 <= size <= 1048576:
        raise ValueError('Unsupported import directory')
    start = image.offset(rva)
    def string(rva):
        pos = image.offset(rva)
        end = data.find(b'\0', pos, pos + 1024)
        if end < 0:
            raise ValueError('Unterminated import string')
        return pos, data[pos:end + 1], data[pos:end].decode('ascii')
    for offset in range(start, start + size - 19, 20):
        raw = data[offset:offset + 20]
        if len(raw) != 20:
            raise ValueError('Truncated import descriptor')
        original, stamp, forwarder, dll, first = struct.unpack('<IIIII', raw)
        if not any(raw):
            break
        if not first or not dll:
            raise ValueError('Invalid import descriptor')
        if target < image.pe.base + first or (target - image.pe.base - first) % 8:
            continue
        index = (target - image.pe.base - first) // 8
        if index > 65535:
            continue
        # Walk to the candidate to ensure it is before the table terminator.
        for i in range(index + 1):
            tp = image.offset((original or first) + i * 8)
            value = struct.unpack_from('<Q', data, tp)[0]
            if not value:
                break
        else:
            if value >> 63:
                raise ValueError('Ordinal import has no verified name')
            dp, db, dll_name = string(dll)
            np, nb, name = string(value + 2)
            return dict(dll=dll_name, name=name, descriptor_offset=offset, descriptor_bytes=raw.hex(),
                        thunk_offset=tp, thunk_bytes=data[tp:tp + 8].hex(), iat_address=target,
                        dll_offset=dp, dll_bytes=db.hex(), name_offset=np, name_bytes=nb.hex())
    raise ValueError('IAT address not resolved to a named import')


def main(root):
    spec = importlib.util.spec_from_file_location('zero_init_native', HERE / 'build-native-entry-code.py')
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    source = json.loads((root / 'code-clues/native-enums.json').read_text('utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Changed client EXE')
    im = native.Image(data)
    addresses = [0x141746350, 0x1417cd8a0, 0x1417e0fc0, 0x1417e0420]
    fragments = native.decode_ranges(im, {im.roots[im.containing(a)] for a in addresses})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    anchors = []
    expected = [
        (0x14174640f, 'call', '0x1417cd8a0'),
        (0x1417cdbc9, 'lea', 'rcx, [rbp - 0x60]'),
        (0x1417cdbcd, 'call', '0x1417e0fc0'),
        (0x1417e10b8, 'mov', 'rcx, r14'),
        (0x1417e10c4, 'call', '0x1417e0420'),
        (0x1417e10c9, 'mov', 'rsi, rax'),
        (0x1417e10dc, 'cmp', 'byte ptr [rsp + 0x40], r13b'),
        (0x1417e10e1, 'jne', '0x1417e1248'),
        (0x1417e10ed, 'mov', 'r14, qword ptr [r14 + 0xb0]'),
        (0x1417e1238, 'call', 'r14'),
        (0x1417e1240, 'call', '0x1417c61a0'),
        (0x1417e0454, 'xor', 'esi, esi'),
        (0x1417e046b, 'mov', 'r12d, esi'),
        (0x1417e050a, 'mov', 'r14d, dword ptr [rbx + 0x58]'),
        (0x1417e050e, 'mov', 'dword ptr [rsp + 0x64], r14d'),
        (0x1417e055a, 'mov', 'r14d, dword ptr [rdx + 0x58]'),
        (0x1417e0561, 'mov', 'dword ptr [rsp + 0x64], r14d'),
        (0x1417e099e, 'mov', 'r12b, 1'),
        (0x1417e0bbb, 'mov', 'rcx, rdi'),
        (0x1417e0bbe, 'test', 'r12b, r12b'),
        (0x1417e0bc1, 'jne', '0x1417e0c52'),
        (0x1417e0bc7, 'movsxd', 'r8, dword ptr [rsp + 0x64]'),
        (0x1417e0bcc, 'xor', 'edx, edx'),
        (0x1417e0bce, 'call', '0x1487a2e25'),
    ]
    for address, mnemonic, operands in expected:
        row = rows[address]
        if (row['mnemonic'], row['operands']) != (mnemonic, operands):
            raise ValueError('Changed object zero-init anchor at ' + hex(address))
        anchors.append(row)
    offset = im.offset(0x87a2e25)
    trampoline = data[offset:offset + 6]
    if trampoline[:2] != b'\xff\x25':
        raise ValueError('Changed zero-init import trampoline')
    target = 0x1487a2e25 + 6 + struct.unpack_from('<i', trampoline, 2)[0]
    binding = import_at(data, im, target)
    if (binding['dll'].lower(), binding['name']) != ('vcruntime140.dll', 'memset'):
        raise ValueError('Zero-init target is not named memset')
    report = dict(source=source, native_anchors=anchors, native_fragments=fragments,
                  trampoline=dict(address=0x1487a2e25, file_offset=offset, bytes=trampoline.hex(), target=target),
                  import_binding=binding, zeroing_branch_verified=True, final_rotation_default_verified=False,
                  limitations=['The allocation branch calls named memset(destination,0,length) before the class constructor; object-reuse branches may skip it.',
                               'Class constructor and initializer finalization run afterwards. This report does not prove they leave RelativeRotation unchanged.',
                               'No missing rotation filled; this is not proof of effective CDO, attachment state, level frame or walkability.'])
    path = root / 'maps/navigation-study/lift-blueprints/object-zero-init-code.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(anchors=len(anchors), import_name=binding['name'], sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report


if __name__ == '__main__':
    main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir')))
