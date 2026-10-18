"""Verify native initial scale and PointLinks, plus absence of Blueprint overrides."""
import hashlib, importlib.util, json, os, struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main(root):
    def module(name, file):
        s = importlib.util.spec_from_file_location(name, HERE / file)
        m = importlib.util.module_from_spec(s)
        s.loader.exec_module(m)
        return m
    native = module('initial_native', 'build-native-entry-code.py')
    canvas = module('initial_reader', 'decode-canvas-slots.py')
    refs = module('initial_refs', 'decode-package-references.py')
    scene_builder = module('initial_scene', 'build-scene-native-defaults.py')
    scene = scene_builder.main(root)
    source = scene['source']
    exe = Path(source['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest() != source['sha256']:
        raise ValueError('Changed client EXE')
    im = native.Image(exe)
    fragments = native.decode_ranges(im, {im.roots[im.containing(a)] for a in [0x1454fd410, 0x1438367b0]})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    anchors = []
    expected = [
        (0x1454fd430, 'xor', 'edi, edi'),
        (0x1454fd491, 'lea', 'r14, [rsi + 0x3e0]'),
        (0x1454fd4cb, 'mov', 'qword ptr [r14], rdi'),
        (0x1454fd4d1, 'mov', 'qword ptr [r14 + 8], rdi'),
        (0x1454fd6c4, 'call', '0x1438369b0'),
        (0x1454fd6d0, 'xorps', 'xmm1, xmm1'),
        (0x1454fd6d3, 'movaps', 'xmmword ptr [rsp + 0x70], xmm0'),
        (0x1454fd6df, 'movaps', 'xmmword ptr [rsp + 0x90], xmm0'),
        (0x1454fd6e7, 'movaps', 'xmmword ptr [rsp + 0x80], xmm1'),
        (0x1454fd701, 'movsxd', 'rbx, dword ptr [r14 + 8]'),
        (0x1454fd705, 'lea', 'eax, [rbx + 1]'),
        (0x1454fd708, 'mov', 'dword ptr [r14 + 8], eax'),
        (0x1454fd71c, 'imul', 'rbx, rbx, 0x70'),
        (0x1454fd725, 'add', 'rbx, qword ptr [r14]'),
        (0x1454fd728, 'mov', 'rcx, rbx'),
        (0x1454fd72b, 'call', '0x1438367b0'),
        (0x1454fd730, 'movaps', 'xmm0, xmmword ptr [rsp + 0x70]'),
        (0x1454fd748, 'movups', 'xmmword ptr [rbx + 0x40], xmm0'),
        (0x1454fd74c, 'movsd', 'xmm1, qword ptr [rsp + 0x80]'),
        (0x1454fd755, 'movsd', 'qword ptr [rbx + 0x50], xmm1'),
        (0x1454fd75a, 'movups', 'xmm0, xmmword ptr [rsp + 0x88]'),
        (0x1454fd762, 'movups', 'xmmword ptr [rbx + 0x58], xmm0'),
        (0x1454fd766, 'movsd', 'xmm1, qword ptr [rsp + 0x98]'),
        (0x1454fd76f, 'movsd', 'qword ptr [rbx + 0x68], xmm1'),
        (0x1438368dc, 'movzx', 'eax, byte ptr [rdx + 0x28]'),
        (0x1438368e0, 'mov', 'byte ptr [rbx + 0x28], al'),
    ]
    for address, mnemonic, operands in expected:
        row = rows[address]
        if (row['mnemonic'], row['operands']) != (mnemonic, operands):
            raise ValueError('Changed initial PointLinks anchor')
        anchors.append(row)
    constants = []
    for address, expected_pair in [(0x1454fd6c9, (0., -50.)), (0x1454fd6d8, (50., 0.))]:
        row = rows[address]
        offset = im.offset(row['rip_references'][0] - im.pe.base)
        if struct.unpack_from('<dd', exe, offset) != expected_pair:
            raise ValueError('Changed default PointLinks coordinate')
        constants.append(dict(instruction=row, file_offset=offset, bytes=exe[offset:offset + 16].hex(), values=expected_pair))
    import capstone
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    offset = im.offset(0x38369b0)
    raw = exe[offset:offset + 0x42]
    instructions = [dict(address=i.address, mnemonic=i.mnemonic, operands=i.op_str, bytes=i.bytes.hex(), file_offset=offset + i.address - 0x1438369b0) for i in cs.disasm(raw, 0x1438369b0)]
    if not instructions or instructions[-1]['mnemonic'] != 'ret' or sum(len(bytes.fromhex(r['bytes'])) for r in instructions) != len(raw):
        raise ValueError('Changed link constructor boundary')
    if not any(r['address'] == 0x1438369e4 and r['operands'] == 'word ptr [rcx + 0x28], 0x200' and r['mnemonic'] == 'mov' for r in instructions):
        raise ValueError('Changed initial direction')
    folder = root / 'maps/navigation-study/lift-blueprints'
    bp_path = folder / 'index.json'
    settings_path = folder / 'instance-settings.json'
    archetype_path = folder / 'archetypes.json'
    bps = json.loads(bp_path.read_text('utf-8'))
    settings = json.loads(settings_path.read_text('utf-8'))
    archetypes = json.loads(archetype_path.read_text('utf-8'))
    bp_sha = hashlib.sha256(bp_path.read_bytes()).hexdigest()
    if settings['blueprint_index_sha256'] != bp_sha or archetypes['blueprint_index_sha256'] != bp_sha:
        raise ValueError('Different Blueprint snapshots')
    counts = {r['class_name']: r['own_property_count'] for r in settings['class_sources']}
    # Prefix counts include inheritance; do not infer them from instance names.
    if counts != {'BP_Lift_C': 2, 'BP_Lift_Test_C': 1, 'BP_Lift_Type01_C': 0}:
        raise ValueError('Changed Blueprint property prefixes')
    cdo_checks = []
    for bp in bps['blueprints']:
        parts = []
        for part in bp['parts']:
            data = (folder / part['file']).read_bytes()
            if hashlib.sha256(data).hexdigest() != part['sha256']:
                raise ValueError('Changed Blueprint package')
            parts.append(data)
        cls = bp['inheritance']['class_export']['name']
        prefix = 3 if cls == 'BP_Lift_Test_C' else 2
        cdo = next(r for r in bp['exports'] if r['name'] == 'Default__' + cls)
        table = refs.references(parts[0], dict(names=bp['names'], exports=bp['exports']))
        reference = table['references'][cdo['index']]
        template = table['references'].get(reference['template_index'])
        expected_template = '/Script/NnFramework.Default__NnLift' if cls == 'BP_Lift_C' else '/Game/RED/Blueprint/Lift/BP_Lift.Default__BP_Lift_C'
        if not template or template['path'] != expected_template:
            raise ValueError('Unexpected Blueprint CDO archetype')
        data = parts[1][cdo['offset'] - len(parts[0]):cdo['offset'] - len(parts[0]) + cdo['size']]
        if hashlib.sha256(data).hexdigest() != cdo['sha256']:
            raise ValueError('Changed Blueprint CDO')
        reader = canvas.Reader(data)
        fields = reader.header()
        if any(index == prefix + 6 for index, zero in fields):
            raise ValueError('Blueprint CDO overrides PointLinks; decode it first')
        cdo_checks.append(dict(class_name=cls, export=cdo, reference=reference, template=template, field_indices=fields, header_bytes=data[:reader.pos].hex(), point_links_property_index=prefix + 6, point_links_override_present=False))
    for definition in archetypes['scene_templates'].values():
        if definition['decoded']['properties'] or definition['decoded']['unknown_fields']:
            raise ValueError('Scene template overrides require decoding')
    link_schema = json.loads((folder / 'point-links.json').read_text('utf-8'))
    descriptors = []
    for name, expected_offset in [('Left', 0x40), ('Right', 0x58), ('Direction', 0x28)]:
        r = next(r for r in link_schema['native_link_properties'] if r['name'] == name)
        raw_descriptor = bytes.fromhex(r['descriptor_bytes'])
        if exe[r['descriptor_offset']:r['descriptor_offset'] + len(raw_descriptor)] != raw_descriptor or struct.unpack_from('<I', raw_descriptor, 50)[0] != expected_offset:
            raise ValueError('Changed initial link descriptor')
        descriptors.append(r)
    report = dict(source=source, native_anchors=anchors, native_fragments=fragments, coordinate_constants=constants,
                  link_constructor=dict(address=0x1438369b0, file_offset=offset, bytes=raw.hex(), instructions=instructions), native_descriptors=descriptors,
                  blueprint_index_sha256=hashlib.sha256(bp_path.read_bytes()).hexdigest(), settings_sha256=hashlib.sha256(settings_path.read_bytes()).hexdigest(),
                  archetypes_sha256=hashlib.sha256(archetype_path.read_bytes()).hexdigest(),
                  scene_defaults_sha256=hashlib.sha256((folder / 'scene-native-defaults.json').read_bytes()).hexdigest(),
                  blueprint_cdo_checks=cdo_checks, scene_scale_initial=scene['constructor_defaults']['RelativeScale3D'],
                  native_point_links_initial=[dict(properties=dict(Left=[0., -50., 0.], Right=[0., 50., 0.], Direction=0))],
                  effective_runtime_values_verified=False,
                  limitations=['Values are native initial settings with no serialized Blueprint overrides in the checked templates/CDOs; construction/runtime changes are not excluded.',
                               'RelativeRotation default is not established and must remain absent; other PointLink parameters are not filled.',
                               'Use only as explicitly sourced initial values in the conditional preview, never as a walkability guarantee.'])
    path = folder / 'initial-values.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(anchors=len(anchors), cdo_checks=len(cdo_checks), sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report


if __name__ == '__main__':
    main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir')))
