"""Verify named world-transform getters and the SceneComponent cache write path."""
import hashlib, importlib.util, json, os, struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main(root):
    spec = importlib.util.spec_from_file_location('component_native', HERE / 'build-native-entry-code.py')
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    import capstone
    source = json.loads((root / 'code-clues/native-enums.json').read_text('utf-8'))
    exe = Path(source['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest() != source['sha256']:
        raise ValueError('Changed client EXE')
    im = native.Image(exe)
    roots = {im.roots[im.containing(a)] for a in [0x1437d7ac0, 0x1437d7b00, 0x1437d7b40, 0x1437d7b80, 0x1425a78a0, 0x143af8c00]}
    fragments = native.decode_ranges(im, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    bindings = []
    for offset, name, wrapper in [(0x91315f0, 'K2_GetComponentLocation', 0x1437d7ac0),
                                  (0x9131600, 'K2_GetComponentRotation', 0x1437d7b00),
                                  (0x9131610, 'K2_GetComponentScale', 0x1437d7b40),
                                  (0x9131620, 'K2_GetComponentToWorld', 0x1437d7b80)]:
        name_va, target = struct.unpack_from('<QQ', exe, offset)
        no = im.offset(name_va - im.pe.base)
        if target != wrapper or exe[no:no + len(name) + 1] != name.encode() + b'\0':
            raise ValueError('Changed named component getter binding')
        bindings.append(dict(name=name, name_offset=no, name_bytes=exe[no:no + len(name) + 1].hex(),
                             registration_offset=offset, registration_bytes=exe[offset:offset + 16].hex(), wrapper=wrapper))
    # Small leaf getters have no unwind record: retain every decoded byte through ret.
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    leaves = []
    for address, end in [(0x143ae5a60, 0x143ae5a7a), (0x143ae5b30, 0x143ae5b4a), (0x143ae5b50, 0x143ae5b95)]:
        pos = im.offset(address - im.pe.base)
        raw = exe[pos:pos + end - address]
        decoded = list(cs.disasm(raw, address))
        if not decoded or decoded[-1].mnemonic != 'ret' or sum(i.size for i in decoded) != len(raw):
            raise ValueError('Changed component leaf function boundary')
        instructions = [dict(address=i.address, mnemonic=i.mnemonic, operands=i.op_str, bytes=i.bytes.hex(), file_offset=pos + i.address - address) for i in decoded]
        rows.update({r['address']: r for r in instructions})
        leaves.append(dict(address=address, file_offset=pos, bytes=raw.hex(), instructions=instructions))
    anchors = []
    expected = [
        (0x1437d7ae3, 'call', '0x143ae5a60'),
        (0x1437d7b23, 'call', '0x143ae5a80'),
        (0x1437d7b63, 'call', '0x143ae5b30'),
        (0x1437d7bb8, 'call', '0x143ae5b50'),
        (0x143ae5a60, 'movups', 'xmm0, xmmword ptr [rcx + 0x1f0]'),
        (0x143ae5a6d, 'movups', 'xmm1, xmmword ptr [rcx + 0x200]'),
        (0x143ae5b30, 'movups', 'xmm0, xmmword ptr [rcx + 0x210]'),
        (0x143ae5b3d, 'movups', 'xmm1, xmmword ptr [rcx + 0x220]'),
        (0x143ae5b50, 'movaps', 'xmm0, xmmword ptr [rcx + 0x1d0]'),
        (0x143ae5b8c, 'movaps', 'xmmword ptr [rdx + 0x40], xmm0'),
        (0x143ae5b90, 'movaps', 'xmmword ptr [rdx + 0x50], xmm1'),
        (0x1425a7a1a, 'mov', 'rdx, qword ptr [rbx + 0xb0]'),
        (0x1425a7a3f, 'call', '0x143af8c00'),
        (0x143af8c30, 'mov', 'rdi, rcx'),
        (0x143af8c5b, 'movups', 'xmm1, xmmword ptr [rdi + 0x128]'),
        (0x143af8c69, 'movups', 'xmm3, xmmword ptr [rdi + 0x158]'),
        (0x143af8ce5, 'movsd', 'xmm14, qword ptr [rdi + 0x138]'),
        (0x143af8c99, 'movsd', 'xmm8, qword ptr [rdi + 0x168]'),
        (0x143af8cf7, 'movaps', 'xmm15, xmm1'),
        (0x143af8d1c, 'movups', 'xmm6, xmmword ptr [rax]'),
        (0x143af8d1f, 'movups', 'xmm12, xmmword ptr [rax + 0x10]'),
        (0x143af8d63, 'mov', 'rsi, qword ptr [rdi + 0xb0]'),
        (0x143af8d71, 'test', 'rsi, rsi'),
        (0x143af8d74, 'je', '0x143af94de'),
        (0x143af94de, 'movaps', 'xmm5, xmm7'),
        (0x143af94e1, 'movaps', 'xmm7, xmm8'),
        (0x143af9619, 'movups', 'xmmword ptr [rdi + 0x1d0], xmm6'),
        (0x143af9625, 'movups', 'xmmword ptr [rdi + 0x1e0], xmm12'),
        (0x143af962d, 'movups', 'xmmword ptr [rdi + 0x1f0], xmm15'),
        (0x143af9635, 'movups', 'xmmword ptr [rdi + 0x200], xmm14'),
        (0x143af963d, 'movups', 'xmmword ptr [rdi + 0x210], xmm5'),
        (0x143af9644, 'movups', 'xmmword ptr [rdi + 0x220], xmm7'),
    ]
    for address, mnemonic, operands in expected:
        row = rows[address]
        if (row['mnemonic'], row['operands']) != (mnemonic, operands):
            raise ValueError('Changed component transform anchor at ' + hex(address))
        anchors.append(row)
    descriptors = []
    for va, name, offset in [(0x14912a300, 'AttachParent', 0xb0), (0x14912a480, 'RelativeLocation', 0x128), (0x14912a4c0, 'RelativeRotation', 0x140), (0x14912a500, 'RelativeScale3D', 0x158)]:
        pos = im.offset(va - im.pe.base)
        raw = exe[pos:pos + 56]
        no = im.offset(struct.unpack_from('<Q', raw)[0] - im.pe.base)
        if exe[no:no + len(name) + 1] != name.encode() + b'\0' or struct.unpack_from('<I', raw, 50)[0] != offset:
            raise ValueError('Changed component property')
        descriptors.append(dict(name=name, address=va, file_offset=pos, bytes=raw.hex(), object_offset=offset))
    report = dict(source=source, native_bindings=bindings, native_anchors=anchors, native_fragments=fragments, native_leaf_functions=leaves, native_descriptors=descriptors,
                  verified_storage=dict(component_to_world_offset=0x1d0, size=96, world_location_offset=0x1f0, world_scale_offset=0x210),
                  update_function=0x143af8c00, parentless_branch=0x143af94de,
                  world_endpoint_formula_verified=False, native_cdo_values_resolved=False, runtime_walkability_verified=False,
                  reference='https://dev.epicgames.com/documentation/unreal-engine/API/Runtime/Engine/USceneComponent',
                  limitations=['Named native getters establish world storage; no live client memory is read.',
                               'Parentless update copies relative translation/scale and caller-provided encoded rotation; no rotator conversion or attached-parent formula is implemented.',
                               'Native CDO/post-construction defaults and runtime state are not resolved; no missing instance values filled and no endpoints projected.'])
    path = root / 'maps/navigation-study/lift-blueprints/component-transform-code.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(native_bindings=len(bindings), native_anchors=len(anchors), sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report


if __name__ == '__main__':
    main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir')))
