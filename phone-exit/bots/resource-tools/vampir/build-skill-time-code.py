"""Verify the native cooldown display path; do not assign units to CSV fields."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    spec = importlib.util.spec_from_file_location('skill_time_native', HERE/'build-native-entry-code.py')
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    source = json.loads((native.ROOT/'code-clues/native-enums.json').read_text('utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256'] or native.capstone.__version__ != '5.0.6':
        raise ValueError('Changed executable or decoder')
    image = native.Image(data)
    addresses = [0x1466ab180, 0x146696010, 0x1466ba8d0, 0x1466b5ae0,
                 0x14568a410, 0x1456693b0, 0x145bb9f90, 0x145bba020,
                 0x1454df9e0, 0x145bbc820, 0x145bc6470]
    roots = {image.roots[image.containing(a)] for a in addresses}
    fragments = native.decode_ranges(image, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    expected = [
        (0x1466ab1bf, 'lea', 'rdx, [rip + 0x3682702]'),
        (0x1466ab1d0, 'lea', 'rdx, [rbx + 0xa98]'),
        (0x1466ab1df, 'call', '0x144a76510'),
        (0x14669602a, 'lea', 'rax, [rip + 0x36936ff]'),
        (0x146696031, 'mov', 'qword ptr [rbx], rax'),
        (0x1466ba96f, 'lea', 'rax, [rip + 0x215a]'),
        (0x1466b5d09, 'call', '0x14568a410'),
        (0x1466b5d14, 'cmovl', 'ebx, r15d'),
        (0x1466b5d27, 'divss', 'xmm0, xmm1'),
        (0x1466b5d33, 'lea', 'rdx, [rip + 0x333db36]'),
        (0x1466b5d47, 'call', '0x14142d840'),
        (0x1466b5d87, 'mov', 'rsi, qword ptr [r14 + 0xa98]'),
        (0x1466b5d9a, 'mov', 'rbx, qword ptr [rax + 0x10]'),
        (0x1466b5daa, 'call', 'rbx'),
        (0x14568a424, 'call', '0x1454df9e0'),
        (0x14568a457, 'call', 'qword ptr [rax + 0xb8]'),
        (0x14568a49b, 'mulss', 'xmm7, xmm0'),
        (0x14568a4a5, 'call', 'qword ptr [rax + 0xe8]'),
        (0x14568a4b7, 'call', 'qword ptr [rax + 0xc8]'),
        (0x14568a4d4, 'call', '0x1456693b0'),
        (0x14568a4df, 'mulss', 'xmm6, dword ptr [rip + 0x3304921]'),
        (0x14568a573, 'mulss', 'xmm0, dword ptr [rip + 0x3302bb5]'),
        (0x14568a57b, 'subss', 'xmm6, xmm0'),
        (0x14568a582, 'maxss', 'xmm6, xmm0'),
        (0x145bb9feb, 'mov', 'eax, dword ptr [rbx + 0xcc]'),
        (0x145bb9ffc, 'mov', 'eax, dword ptr [rax + 0x64]'),
        (0x145bba07b, 'mov', 'eax, dword ptr [rbx + 0xd0]'),
        (0x145bba08c, 'mov', 'eax, dword ptr [rax + 0x60]'),
        (0x145bc75cc, 'mov', 'dword ptr [rbx + 0xcc], eax'),
        (0x145bc75ef, 'mov', 'dword ptr [rbx + 0xd0], eax'),
        (0x145bbc897, 'lea', 'rax, [rip - 0x7e7e]'),
        (0x145bbc991, 'movaps', 'xmmword ptr [rip + 0x59b5118], xmm0'),
    ]
    anchors = []
    for address, mnemonic, operands in expected:
        row = rows[address]
        if (row['mnemonic'], row['operands']) != (mnemonic, operands):
            raise ValueError('Changed time anchor '+hex(address)+': '+row['operands'])
        anchors.append(row)

    def blob(address, raw):
        offset = image.offset(address-image.pe.base)
        if data[offset:offset+len(raw)] != raw:
            raise ValueError('Changed native bytes at '+hex(address))
        return dict(address=address, file_offset=offset, bytes=raw.hex())

    literals = [blob(0x149d2d8c8, 'TextSkillCoolTime\0'.encode('utf-16le')),
                blob(0x1499f3870, '%.1f\0'.encode('utf-16le'))]
    constants = []
    for address, bits, value in [(0x14898ee08, '6f12833a', 0.001),
                                 (0x14898d130, '17b7d138', 0.0001)]:
        raw = bytes.fromhex(bits)
        row = blob(address, raw)
        row.update(float32=struct.unpack('<f', raw)[0], intended_decimal=value)
        constants.append(row)
    # Leaf callback and factory trampoline have no RUNTIME_FUNCTION entries.
    leaf = [blob(0x1466bcad0, bytes.fromhex('440fb781840a00008b91800a0000e9fd8fffff')),
            blob(0x145bb4a20, bytes.fromhex('8b12488b09e9a64b0000'))]
    vtables = [blob(0x149d29730+0x530, struct.pack('<Q', 0x1466ab180)),
               blob(0x1499b9440+0xb8, struct.pack('<Q', 0x145bb9f90)),
               blob(0x1499b9440+0xc8, struct.pack('<Q', 0x145bba020))]
    catalog_path = native.ROOT/'ui-catalog/pakchunk500-Windows-8978.json'
    catalog = json.loads(catalog_path.read_text('utf-8'))
    control = next(c for c in catalog['controls'] if c['name'] == 'TextSkillCoolTime')
    if (catalog['name'], control['export'], control['sha256']) != (
            'WBP_SkillSummaryInfoT', 27,
            '40613d71d72c2a164313c7d113b894e4abfe1d9a92a1ba15b46d620fc63c0690'):
        raise ValueError('Changed cooldown widget')
    result = dict(source=source['source'], sha256=source['sha256'], anchors=anchors,
        fragments=fragments, literals=literals, constants=constants,
        leaf_code=leaf, vtable_slots=vtables,
        widget=dict(path=str(catalog_path), sha256=hashlib.sha256(catalog_path.read_bytes()).hexdigest(),
                    source=catalog['source'], entry=catalog['entry'], asset_sha256=catalog['asset_sha256'],
                    control=control),
        verified=dict(display_scale=0.001, display_format='%.1f',
            runtime_modifiers_present=True, level_overrides_present=True),
        csv_time_unit=None, shared_time_unit_verified=False,
        relations=[
            'WBP_SkillSummaryInfoT.TextSkillCoolTime → native widget+0xa98 → text setter',
            'widget callback → 0x1466b5ae0 → cooldown 0x14568a410 → divide by max(charge count,1) → %.1f',
            'cooldown 0x14568a410 → virtual getters b8/c8/e8 → helper 0x1456693b0 → float32 0.001 → modifiers',
            'Skill vtable b8/c8 → getters with level overrides; fallback record+0xcc/+0xd0',
        ],
        limitations=[
            'The scale is proved for this computed cooldown display path, not every duration in the client.',
            'The numeric format has no seconds suffix. An independent unit boundary is still required.',
            'The runtime factory is registered through a 64-byte callable; complete object population remains to be traced.',
            'Level override fields +0x64/+0x60 are read; their table provenance is not established here.',
            'Do not convert NPC or item skill times, TotalTime, Effect.Duration/Period or item CoolTime from this report alone.',
            'No Android or server runtime validation has been performed.',
        ])
    path = native.ROOT/'code-clues/skill-time-code.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(anchors=len(anchors), constants=len(constants),
        csv_time_unit=None, sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__ == '__main__':
    main()

