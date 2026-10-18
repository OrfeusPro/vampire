"""Version-bound Nocturne projection: decoded client math + independent old-frame checks.

Does not fit a transform to icons, execute the game, or establish walkability.
"""
import hashlib
import importlib.util
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('map_native', HERE / 'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def project(x, y, ground=615000, center=(0, 0), size=(10240, 10240)):
    values = [x, y, ground, *center, *size]
    if not all(math.isfinite(float(v)) for v in values) or ground <= 0 or min(size) <= 0:
        raise ValueError('Invalid projection parameters')
    return [(float(x) - center[0]) * size[0] / ground + size[0] / 2,
            (float(y) - center[1]) * size[1] / ground + size[1] / 2]


def screen_point(point, matrix):
    a, b, c = matrix[0]
    d, e, f = matrix[1]
    determinant = a * e - b * d
    if abs(determinant) < 1e-12:
        raise ValueError('Singular screenshot registration')
    x, y = point[0] - c, point[1] - f
    return [(e * x - b * y) / determinant, (-d * x + a * y) / determinant]


def inside(point, box):
    return box[0] <= point[0] <= box[2] and box[1] <= point[1] <= box[3]


def main():
    root = native.ROOT
    source = json.loads((root / 'code-clues/native-enums.json').read_text('utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Changed EXE')
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone5.0.6')
    image = native.Image(data)
    addresses = [0x145aa53e0, 0x1464bdfa0, 0x1464cc9a0, 0x1464c42f0, 0x1464c44f0, 0x146721ae0]
    roots = {image.roots[image.containing(a)] for a in addresses}
    fragments = native.decode_ranges(image, roots)
    rows = {r['address']: r for fr in fragments for r in fr['instructions']}
    # Exact reviewed operations. Every fragment has an independent raw-byte SHA.
    checks = {
        0x145aa5621: ('movss', 'dword ptr [rbx + 0x20], xmm0'),
        0x145aa5685: ('movss', 'dword ptr [rbx + 0x24], xmm0'),
        0x145aa56c2: ('movss', 'dword ptr [rbx + 0x28], xmm0'),
        0x1464bdfe1: ('movss', 'xmm0, dword ptr [rax + 0x24]'),
        0x1464bdfe9: ('movsd', 'qword ptr [rbx + 0xb10], xmm0'),
        0x1464bdffb: ('movss', 'xmm0, dword ptr [rax + 0x28]'),
        0x1464be003: ('movsd', 'qword ptr [rbx + 0xb18], xmm0'),
        0x1464be015: ('movss', 'xmm0, dword ptr [rax + 0x20]'),
        0x1464be01d: ('movsd', 'qword ptr [rbx + 0xb00], xmm0'),
        0x1464be0ed: ('mulsd', 'xmm0, qword ptr [rsp + 0x30]'),
        0x1464be0f3: ('divsd', 'xmm0, qword ptr [rbx + 0xb00]'),
        0x1464be0fb: ('movsd', 'qword ptr [rbx + 0xb20], xmm0'),
        0x1464ccbf7: ('subsd', 'xmm8, xmm6'),
        0x1464ccbff: ('subsd', 'xmm9, xmm7'),
        0x1464ccc0b: ('mulsd', 'xmm8, qword ptr [rax + 0xb28]'),
        0x1464ccc14: ('mulsd', 'xmm9, qword ptr [rax + 0xb20]'),
        0x1464ccc22: ('movsd', 'qword ptr [rbx + rax], xmm9'),
        0x1464ccc28: ('movsd', 'qword ptr [rbx + 0x18], xmm8'),
        0x1464c4388: ('addsd', 'xmm6, xmm0'),
        0x1464c43a1: ('addsd', 'xmm7, xmm0'),
        0x1464c4723: ('call', '0x146721ae0'),
    }
    for address, expected in checks.items():
        row = rows[address]
        if (row['mnemonic'], row['operands']) != expected:
            raise ValueError('Changed map math at ' + hex(address))
    literals = []
    for address, expected in [(0x145aa5603, 'GroundDistance'), (0x145aa5667, 'CenterX'),
                              (0x145aa56a4, 'CenterY')]:
        target = rows[address]['rip_references'][0]
        offset = image.offset(target - image.pe.base)
        actual = data[offset:offset + len(expected) + 1]
        if actual != expected.encode() + b'\0':
            raise ValueError('Changed map field literal')
        literals.append(dict(instruction=rows[address], file_offset=offset, text=expected))
    evidence = dict(source=source['source'], sha256=source['sha256'], capstone=native.capstone.__version__,
                    anchors=[rows[a] for a in checks], field_literals=literals, fragments=fragments,
                    observation='CenterX/Y → widget b10/b18; GroundDistance → b00/b08; map icon XY minus center times positive texture-size/ground scale; standard1 indexes centered about count//2.',
                    limitation='This is a reviewed static path in Windows cooked client code; all map modes and Android build equivalence are not established.')
    evidence_path = root / 'code-clues/map-projection-evidence.json'
    evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), 'utf-8')
    atlas = root / 'maps/atlas'
    index = json.loads((atlas / 'index.json').read_text('utf-8'))
    map_source = index['sources']['Map']
    if hashlib.sha256((root / 'table-study' / map_source['file']).read_bytes()).hexdigest() != map_source['sha256']:
        raise ValueError('Changed Map CSV')
    if hashlib.sha256((atlas / 'tables.json').read_bytes()).hexdigest() != index['tables_sha256']:
        raise ValueError('Changed atlas tables')
    assembly = json.loads((root / 'maps/nocturne-world.json').read_text('utf-8'))
    if assembly['layout']['swap'] or assembly['layout']['sx'] != 1 or assembly['layout']['sy'] != 1:
        raise ValueError('Changed tile arrangement')
    if assembly['size'] != [10240, 10240] or hashlib.sha256((root / 'maps' / assembly['image']).read_bytes()).hexdigest() != assembly['sha256']:
        raise ValueError('Changed atlas image')
    maps = [m['data'] for m in index['maps'] if m['data']['MapResource'] == 'Field/Nocturne']
    for m in maps:
        if [m[k] for k in ['GroundDistance', 'CenterX', 'CenterY', 'MapTextureReadingStandard', 'MiniMapTextureCount', 'WorldMapTextureCount']] != ['615000', '0', '0', '1', '5', '5']:
            raise ValueError('Changed Nocturne settings')
    if {m['Id'] for m in maps} != {'10', '11'}:
        raise ValueError('Changed Nocturne Map IDs')
    study_path = atlas / 'screenshot-study/index.json'
    study = json.loads(study_path.read_text('utf-8'))
    frame = next(f for f in study['frames'] if f['source_sha256'] == '6993646efeec8d89b770cf82b50f50d51e3e312a4ca81472e895e31950cc3e20')
    if study['atlas_sha256'] != assembly['sha256'] or hashlib.sha256(Path(frame['source']).read_bytes()).hexdigest() != frame['source_sha256']:
        raise ValueError('Changed registered screenshot')
    world_spec = next(w for w in index['worlds'] if w['id'] == '10011')
    world_bytes = (atlas / world_spec['file']).read_bytes()
    if hashlib.sha256(world_bytes).hexdigest() != world_spec['sha256']:
        raise ValueError('Changed historical-anchor world JSON')
    world = json.loads(world_bytes)
    gadgets = {g['Id']: g for g in world['GadgetSpawn']}
    # Manually reviewed icon regions, in original 1280x720 frame. No parameter is fitted to them.
    boxes = {'10011001': [625, 340, 665, 383], '10011101': [630, 588, 657, 616],
             '10011102': [465, 332, 495, 361], '10011104': [614, 540, 645, 571],
             '10011105': [548, 450, 579, 483], '10011106': [549, 377, 580, 408],
             '10011107': [556, 308, 587, 341]}
    validation = []
    for gid, box in boxes.items():
        row = gadgets[gid]
        pixel = project(float(row['BasePosX']), float(row['BasePosY']))
        screen = screen_point(pixel, frame['screenshot_to_atlas'])
        if not inside(screen, box):
            raise ValueError('Native formula misses screenshot icon: ' + gid)
        validation.append(dict(gadget_spawn=row, atlas_xy=pixel, predicted_screen_xy=screen,
                               manually_reviewed_icon_box=box, inside=True))
    report = dict(schema_version=1, resource='Field/Nocturne', map_ids=['10', '11'],
        map_records=maps, map_csv_sha256=index['sources']['Map']['sha256'],
        tables_sha256=index['tables_sha256'], atlas_image='maps/' + assembly['image'],
        atlas_sha256=assembly['sha256'], size=assembly['size'], ground_distance=615000,
        center=[0, 0], world_bounds=[-307500, -307500, 307500, 307500],
        world_to_pixel=[[10240 / 615000, 0, 5120], [0, 10240 / 615000, 5120]],
        formula='px = 5120 + X*10240/615000; py = 5120 + Y*10240/615000',
        native_evidence=dict(file='../../code-clues/map-projection-evidence.json', sha256=hashlib.sha256(evidence_path.read_bytes()).hexdigest()),
        screenshot_check=dict(source=frame['source'], sha256=frame['source_sha256'],
            registration_sha256=hashlib.sha256(study_path.read_bytes()).hexdigest(),
            method='Native formula unchanged; inverse terrain registration; manual icon-region containment, not subpixel icon localization.',
            source_copy='screenshot-study/' + frame['source_copy'], screenshot_to_atlas=frame['screenshot_to_atlas'],
            anchors=validation, calibration_parameters_fitted=0),
        native_static_verified=True, historical_local_screen_checked=True, fresh_android_verified=False,
        navigation_ready=False,
        limitations=['Only Map10/11 Nocturne, original 10240px assembly.',
            'Seven regions belong to one historical Krvna Nest frame, not seven independent frames or global Android verification.',
            'Gadget20001 MapIconId8001 is missing in current MapIcon CSV; visual lift constellation is corroboration, not a completed 8001→903 semantic link.',
            'NPC positions are table base positions; radius, PositionGroup, quest/server conditions and runtime visibility remain unevaluated.',
            'No pathfinding, collision or navigation readiness.'])
    (atlas / 'projection.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(map_ids=report['map_ids'], screenshot_regions=len(validation), formula=report['formula'], evidence=str(evidence_path)), ensure_ascii=False))


if __name__ == '__main__':
    main()
