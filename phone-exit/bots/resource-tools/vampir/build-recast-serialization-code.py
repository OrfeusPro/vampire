"""Pin the client's Recast chunk serializers; do not infer a walkable graph.

Reads the client EXE and already extracted exports only. Envelope matches remain
candidates until the UObject property boundary and archive custom versions are decoded.
"""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def envelope_candidates(raw):
    """Find bounded version/length/count matches, without claiming a property schema."""
    result = []
    for offset in range(min(256, max(0, len(raw) - 15))):
        version, size, count = struct.unpack_from('<iQi', raw, offset)
        if 20 <= version <= 26 and size == len(raw) - offset - 4 and 0 <= count <= 100000:
            result.append(dict(offset=offset, version=version, length=size, tile_count=count,
                               property_boundary_verified=False))
    return result


def main():
    spec = importlib.util.spec_from_file_location('recast_native', HERE / 'build-native-entry-code.py')
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    root = native.ROOT
    source = json.loads((root / 'code-clues/native-enums.json').read_text('utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Changed client EXE')
    image = native.Image(data)
    functions = [0x1452c0380, 0x1452c22a0, 0x1452df1c0, 0x1452deff0,
                 0x1452df1f0, 0x1452ba8b0, 0x1452ba2a0, 0x141597dd0, 0x14159a480]
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in functions})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    anchors = []
    expected = [
        (0x1452c03e7, 'lea', 'rax, [rip + 0x1eb2]'),
        (0x1452c0415, 'mov', 'dword ptr [rsp + 0x20], 0x40'),
        (0x1452c041d, 'call', '0x1416a5d60'),
        (0x1452c22b9, 'lea', 'rax, [rip + 0x4470f48]'),
        (0x1452c22c0, 'mov', 'qword ptr [rbx], rax'),
        (0x1452df1de, 'call', '0x1452deff0'),
        (0x1452df002, 'call', '0x1417521e0'),
        (0x1452df00b, 'mov', 'dword ptr [rsp + 0x48], 0x1a'),
        (0x1452df020, 'mov', 'eax, dword ptr [r8]'),
        (0x1452df027, 'add', 'qword ptr [rdx], 4'),
        (0x1452df069, 'call', 'qword ptr [rax + 0x28]'),
        (0x1452df080, 'mov', 'rcx, qword ptr [rdx]'),
        (0x1452df088, 'add', 'qword ptr [rax], 8'),
        (0x1452df0be, 'cmp', 'r8d, 0x14'),
        (0x1452df0c4, 'cmp', 'r8d, 0x1a'),
        (0x1452df0d5, 'add', 'rdx, rdi'),
        (0x1452df0d8, 'call', 'qword ptr [r8 + 0x1a0]'),
        (0x1452df0fd, 'call', '0x1452df1f0'),
        (0x1452df145, 'sub', 'rcx, rdi'),
        (0x1452df148, 'mov', 'qword ptr [rsp + 0x50], rcx'),
        (0x1452df222, 'mov', 'eax, dword ptr [rcx]'),
        (0x1452df227, 'add', 'qword ptr [rdx], 4'),
        (0x1452df2c6, 'mov', 'eax, dword ptr [rdx]'),
        (0x1452df2f4, 'lea', 'r9, [rbp + 0x6f]'),
        (0x1452df306, 'call', '0x1452ba8b0'),
        (0x1452df32b, 'call', '0x1452ba2a0'),
        (0x1452bacb3, 'mov', 'dword ptr [rsi], ecx'),
        (0x1452bacb5, 'call', '0x145240ab0'),
        (0x1452bacba, 'mov', 'qword ptr [rdi], rax'),
        (0x1452bacc5, 'call', '0x1487a2e25'),
        (0x1452bb0f9, 'cmp', 'dword ptr [rbp + 0x40], 0x17'),
        (0x1452bc155, 'call', '0x141597dd0'),
        (0x1452bc15a, 'cmp', 'eax, 0x61'),
        (0x141597ddc, 'call', 'qword ptr [rax + 0x58]'),
        (0x141597def, 'call', '0x14159a480'),
        (0x141597df9, 'mov', 'eax, dword ptr [rax + 0x10]'),
        (0x141597e02, 'mov', 'eax, 0xffffffff'),
        (0x14159a4e1, 'movups', 'xmm0, xmmword ptr [r9]'),
        (0x14159a51e, 'je', '0x14159a52b'),
        (0x14159a520, 'add', 'rdx, 0x28'),
        (0x14159a529, 'xor', 'edx, edx'),
        (0x1452ba2cd, 'cmp', 'eax, 0x50'),
        (0x1452ba33d, 'js', '0x1452ba895'),
        (0x1452ba352, 'add', 'ecx, 0x50'),
        (0x1452ba888, 'add', 'rdx, 0x50'),
        (0x1452ba88f, 'call', 'qword ptr [rax + 0x170]'),
    ]
    for address, mnemonic, operands in expected:
        row = rows[address]
        if (row['mnemonic'], row['operands']) != (mnemonic, operands):
            raise ValueError('Changed Recast serialization anchor: ' + hex(address))
        anchors.append(row)
    row = rows[0x14159a557]
    offset = image.offset(row['rip_references'][0] - image.pe.base)
    label = ('Unused custom version' + '\0').encode('utf-16le')
    if data[offset:offset + len(label)] != label:
        raise ValueError('Changed custom-version container diagnostic')
    anchors.append(row)
    literals = []
    for address, value in [(0x1452c03c6, 'RecastNavMeshDataChunk'),
                           (0x1452c03d5, '/Script/NavigationSystem')]:
        row = rows[address]
        va = row['rip_references'][0]
        offset = image.offset(va - image.pe.base)
        raw = (value + '\0').encode('utf-16le')
        if data[offset:offset + len(raw)] != raw:
            raise ValueError('Changed Recast class literal')
        literals.append(dict(address=va, file_offset=offset, text=value, bytes=raw.hex()))
        anchors.append(row)
    vtable = 0x149733208
    bindings = []
    for slot, target in [(0xd8, 0x1452df1c0), (0xe0, 0x1452deff0)]:
        offset = image.offset(vtable + slot - image.pe.base)
        raw = data[offset:offset + 8]
        if struct.unpack('<Q', raw)[0] != target:
            raise ValueError('Changed Recast serializer vtable slot')
        bindings.append(dict(vtable=vtable, slot=slot, target=target, file_offset=offset, bytes=raw.hex()))
    guid_instruction = rows[0x1452bc14b]
    guid_va = guid_instruction['rip_references'][0]
    guid_offset = image.offset(guid_va - image.pe.base)
    guid = data[guid_offset:guid_offset + 16]
    anchors.append(guid_instruction)
    index_path = root / 'maps/navigation-study/generated-chunks/index.json'
    index_bytes = index_path.read_bytes()
    generated = json.loads(index_bytes)
    samples = []
    for package in generated['packages']:
        for entry in package['navigation_exports']:
            export = entry['export']
            if export['type'] != 'RecastNavMeshDataChunk':
                continue
            raw = (index_path.parent / entry['file']).read_bytes()
            if len(raw) != export['size'] or hashlib.sha256(raw).hexdigest() != export['sha256']:
                raise ValueError('Changed Recast export')
            samples.append(dict(archive=package['archive'], package=package['package_identity'],
                                file=entry['file'], export=export, candidates=envelope_candidates(raw)))
    report = dict(source=source['source'], sha256=source['sha256'], fragments=fragments,
        anchors=anchors, literals=literals, bindings=bindings,
        custom_version_key=dict(address=guid_va, file_offset=guid_offset, bytes=guid.hex(),
                                words=list(struct.unpack('<4I', guid)), name_verified=False,
                                archive_value_verified=False, branch_threshold=97),
        stream=dict(version_min=20, version_max=26, writer_version=26,
                    length_includes_own_uint64=True, tile_count='int32',
                    tile_size_is_serialized_byte_count=False,
                    tile_codec=0x1452ba8b0, cache_codec=0x1452ba2a0),
        generated_source_sha256=hashlib.sha256(index_bytes).hexdigest(), samples=samples,
        summary=dict(anchors=len(anchors), exports=len(samples),
                     unique_envelope_candidates=sum(len(s['candidates']) == 1 for s in samples),
                     payload_decoded=False, routes_verified=0, navigation_ready=False),
        limitations=['Envelope offsets are matches, not a decoded UObject property boundary.',
                     'Archive custom-version value is unresolved; do not hardcode its branch.',
                     'Tile buffers, polygons, active package version and connectivity remain undecoded.'])
    path = root / 'code-clues/recast-serialization-code.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(**report['summary'], report_sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report


if __name__ == '__main__':
    main()
