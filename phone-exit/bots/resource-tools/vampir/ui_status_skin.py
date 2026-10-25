"""Source-bound HP/MP Image brushes and bounded PF_FloatRGBA export; no game calls."""
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct
import zlib

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


basic = load('status_basic', 'decode-basic-slot-candidates.py')
refs_tool = load('status_refs', 'decode-package-references.py')
STRUCTS = {
    'SlateBrush': (0x1418d9130, 0x14b0cedb0, ['TintColor', 'DrawAs', 'Tiling', 'Mirroring', 'ImageType',
        'ImageSize', 'Margin', 'ResourceObject', 'OutlineSettings', 'UVRegion', 'bIsDynamicallyLoaded', 'bHasUObject', 'ResourceName']),
    'DeprecateSlateVector2D': (0x141887510, 0x14b0ce1a8, []),
    'Margin': (0x141887570, 0x14b0cde40, ['Left', 'Top', 'Right', 'Bottom']),
    'Vector2f': (0x141621e60, 0x14b0c9a20, ['X', 'Y'])
}


def decode_frame_brush(raw):
    reader = basic.canvas.Reader(raw)
    fields = reader.header()
    if not fields or fields[0] != (0, False):
        raise ValueError('No explicit first Image.Brush')
    members = reader.header()
    if members != [(1, False), (4, False), (5, False), (6, False), (7, False)]:
        raise ValueError('Unreviewed HP frame Brush payload')
    draw_as, image_type = reader.read('<B'), reader.read('<B')
    size = reader.read('<ff')
    if reader.header() != [(0, False), (1, False), (2, False), (3, False)]:
        raise ValueError('Unreviewed frame Margin')
    margin = [reader.read('<f') for _ in range(4)]
    resource = reader.read('<i')
    if draw_as != 1 or image_type != 1 or resource >= 0 or any(not math.isfinite(x) or x <= 0 for x in size):
        raise ValueError('Unreviewed frame draw/resource mode')
    if any(not math.isfinite(x) or not 0 <= x <= .5 for x in margin):
        raise ValueError('Unreviewed nine-slice margins')
    return dict(draw_as=draw_as, image_type=image_type, image_size=size, margin=margin,
                resource_object=resource, brush_prefix_bytes=reader.pos,
                inherited_payload_hex=raw[reader.pos:].hex(), inherited_properties_decoded=False)


def decode_portrait_deferred(raw, names):
    reader = basic.canvas.Reader(raw)
    fields = reader.header()
    if not fields or fields[0] != (0, False) or (3, False) not in fields:
        raise ValueError('Unreviewed NkImage deferred resource layout')
    path_index, path_number = reader.read('<ii')
    object_index, object_number = reader.read('<ii')
    if path_number or object_number or not 0 <= path_index < len(names) or not 0 <= object_index < len(names) or reader.read('<i') != 0:
        raise ValueError('Unreviewed soft object subpath/name')
    path, name = names[path_index], names[object_index]
    if not path.startswith('/Game/') or path.rsplit('/', 1)[-1] != name:
        raise ValueError('Deferred resource names differ')
    return dict(asset_path=path, object_name=name, prefix_bytes=reader.pos,
                unread_payload_hex=raw[reader.pos:].hex(), runtime_loader_verified=False)


def png_chunk(kind, raw):
    return struct.pack('>I', len(raw)) + kind + raw + struct.pack('>I', zlib.crc32(kind + raw) & 0xffffffff)


def float_rgba_png(raw):
    marker = b'PF_FloatRGBA\0'
    if raw.count(marker) != 1:
        raise ValueError('Expected a single FloatRGBA format record')
    pos = raw.index(marker)
    if pos < 16:
        raise ValueError('Truncated texture header')
    width, height, slices = struct.unpack_from('<iii', raw, pos - 16)
    if not 0 < width <= 4096 or not 0 < height <= 4096 or slices != 1:
        raise ValueError('Unreviewed texture dimensions')
    length = width * height * 8
    end = raw.find(struct.pack('<iii', width, height, 1), pos + 16 + length)
    start = end - length
    if end < 0 or start < pos + len(marker):
        raise ValueError('Missing bounded float pixel payload')
    rgba = bytearray()
    for pixel in struct.iter_unpack('<4e', raw[start:end]):
        if any(not math.isfinite(x) or not 0 <= x <= 1 for x in pixel):
            raise ValueError('HDR/nonfinite channel needs a separate reviewed color policy')
        for i, value in enumerate(pixel):
            encoded = value if i == 3 else 12.92 * value if value <= .0031308 else 1.055 * value ** (1 / 2.4) - .055
            rgba.append(round(encoded * 255))
    rows = b''.join(b'\0' + rgba[y * width * 4:(y + 1) * width * 4] for y in range(height))
    png = b'\x89PNG\r\n\x1a\n' + png_chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0))
    png += png_chunk(b'sRGB', b'\0') + png_chunk(b'IDAT', zlib.compress(rows)) + png_chunk(b'IEND', b'')
    return png, dict(width=width, height=height, pixel_offset=start, pixel_bytes=length,
                     color_policy='linear_half_RGB_to_sRGB8_alpha_linear', hdr_clamped=False)


def prepare(root):
    request = root / 'knowledge/requests/6c79ab7fd65d32b8ee0c1f64a7f898282f5c88de6e621db566b3c23a07f21bb7/manifest.json'
    manifest = json.loads(request.read_bytes())
    parent_request = root / 'knowledge/requests/5ac6c9f1375d26d2027bcdd60dbd13d255fa2edd4209080203ada6239fd9321f/manifest.json'
    parent_manifest = json.loads(parent_request.read_bytes())
    requested = {int(f['address'], 16) for r in [manifest, parent_manifest] for f in r['functions']}
    if any(r['source_sha256'] != basic.SHA for r in [manifest, parent_manifest]) or not {s[0] for s in STRUCTS.values()} <= requested:
        raise ValueError('Missing reviewed frame struct request')
    raw = basic.source.checked(Path(manifest['source']), basic.SHA)
    image = basic.native.Image(raw)
    ranges = set()
    for getter, _, _ in STRUCTS.values():
        index = image.containing(getter)
        if index is None or image.pe.base + image.roots[index][0] != getter:
            raise ValueError('Struct getter boundary differs')
        ranges.add(image.roots[index])
    fragments = basic.native.decode_ranges(image, ranges)
    native = {}
    for name, (getter, address, names) in STRUCTS.items():
        block = raw[image.offset(address - image.pe.base):image.offset(address - image.pe.base) + 56]
        ptrs = struct.unpack('<7Q', block)
        text = image.offset(ptrs[3] - image.pe.base)
        fragment = next(f for f in fragments if f['instructions'][0]['address'] == getter)
        if address not in {r for ins in fragment['instructions'] for r in ins['rip_references']}:
            raise ValueError('Getter metadata reference differs')
        if raw[text:text + len(name) + 1] != name.encode() + b'\0' or ptrs[5] & 0xffff != len(names):
            raise ValueError('Struct name/count differs')
        if not names and (ptrs[1] != 0x141621e60 or ptrs[4] != 0 or (ptrs[5] >> 16) & 0xffff != 8):
            raise ValueError('Unreviewed slate vector inheritance/size')
        rows = []
        for i, field in enumerate(names):
            d = struct.unpack_from('<Q', raw, image.offset(ptrs[4] - image.pe.base) + i * 8)[0]
            at = image.offset(d - image.pe.base)
            n = image.offset(struct.unpack_from('<Q', raw, at)[0] - image.pe.base)
            if raw[n:n + len(field) + 1] != field.encode() + b'\0':
                raise ValueError('Brush descriptor array differs')
            if name in ['Margin', 'Vector2f'] and struct.unpack_from('<I', raw, at + 24)[0] & 255 != 10:
                raise ValueError('Expected float component descriptor')
            rows.append(dict(name=field, descriptor=hex(d), bytes=raw[at:at + 64].hex()))
        native[name] = dict(metadata=hex(address), bytes=block.hex(), fields=rows, fragment=fragment)
    image_metadata = image.offset(0x148fdfbe0 - image.pe.base)
    if struct.unpack_from('<Q', raw, image_metadata)[0] != 0x14357fc60 or struct.unpack_from('<Q', raw, image_metadata + 40)[0] != 0x148fdf820:
        raise ValueError('Image metadata differs')
    brush_descriptor = image.offset(0x148fdf4f0 - image.pe.base)
    if struct.unpack_from('<Q', raw, image.offset(0x148fdf820 - image.pe.base))[0] != 0x148fdf4f0 or struct.unpack_from('<Q', raw, brush_descriptor + 56)[0] != 0x1418d9130:
        raise ValueError('Image.Brush getter differs')
    native['image_brush_descriptor_hex'] = raw[brush_descriptor:brush_descriptor + 64].hex()
    nk_request = root / 'knowledge/requests/8b7e8b643d2fe043ff328c8de22998037b5a7b171a95c8ccd1c9ef531a7128f7/manifest.json'
    nk_manifest = json.loads(nk_request.read_bytes())
    if nk_manifest['source_sha256'] != basic.SHA or '0x144a34fa0' not in {f['address'] for f in nk_manifest['functions']}:
        raise ValueError('Missing NkImage getter request')
    nk_at = image.offset(0x149648810 - image.pe.base)
    nk_metadata = raw[nk_at:nk_at + 64]
    if struct.unpack_from('<Q', nk_metadata)[0] != 0x144a34fa0 or struct.unpack_from('<Q', nk_metadata, 40)[0] != 0x1496487a0:
        raise ValueError('NkImage metadata differs')
    nk_index = image.containing(0x144a34fa0)
    nk_fragment = basic.native.decode_ranges(image, {image.roots[nk_index]})[0]
    nk_refs = {r for i in nk_fragment['instructions'] for r in i['rip_references']}
    if not {0x149648632, 0x14357fc60} <= nk_refs:
        raise ValueError('NkImage class literal/Image parent differs')
    nk_fields = []
    for i, (name, flag) in enumerate(zip(['DeferredResourceObject', 'UnderlyingType', 'CachePolicy', 'AsyncLoad'], [16, 0, 30, 76])):
        pointer = struct.unpack_from('<Q', raw, image.offset(0x1496487a0 - image.pe.base) + i * 8)[0]
        at = image.offset(pointer - image.pe.base)
        pos = image.offset(struct.unpack_from('<Q', raw, at)[0] - image.pe.base)
        if raw[pos:pos + len(name) + 1] != name.encode() + b'\0' or struct.unpack_from('<I', raw, at + 24)[0] & 255 != flag:
            raise ValueError('NkImage property schema differs')
        nk_fields.append(dict(name=name, descriptor_hex=raw[at:at + 64].hex()))
    native['NkImage'] = dict(metadata_hex=nk_metadata.hex(), fields=nk_fields, fragment=nk_fragment,
                             serialized_own_fields=['DeferredResourceObject', 'CachePolicy', 'AsyncLoad'])
    inputs = {}
    def tracked(relative):
        data = (root / relative).read_bytes()
        inputs[relative] = basic.sha(data)
        return data
    tracked(request.relative_to(root).as_posix())
    tracked(parent_request.relative_to(root).as_posix())
    tracked(nk_request.relative_to(root).as_posix())
    catalog = json.loads(tracked('ui-catalog/pakchunk500-Windows-1747.json'))
    asset = tracked('ui-layout-study/pakchunk500-Windows-1747.uasset')
    body = tracked('ui-layout-study/pakchunk500-Windows-1747.uexp')
    if basic.sha(asset) != catalog['asset_sha256'] or basic.sha(body) != catalog['body_sha256']:
        raise ValueError('Status source differs')
    parsed = basic.source.inspector.exports(asset, body)
    references = refs_tool.references(asset, parsed)['references']
    brushes = {}
    for name in ['Image_224', 'Image']:
        entry = next(e for e in parsed['exports'] if e['name'] == name and e['type'] == 'Image')
        cls = references[entry['index']]['class_index']
        if references[cls]['path'] != '/Script/UMG.Image':
            raise ValueError('Frame Image class import differs')
        at = entry['offset'] - len(asset)
        data = body[at:at + entry['size']]
        brush = decode_frame_brush(data)
        ref = references[brush['resource_object']]
        if ref['path'] != '/Game/RED/UI/Resource/Texture/GameUI/ProgressBG_HP.ProgressBG_HP':
            raise ValueError('Different frame texture')
        brushes[name] = dict(brush, export=entry, resource_reference=ref)
    texture_asset = tracked('pak-extracted/pakchunk500-Windows/004004.uasset')
    texture_body = tracked('pak-extracted/pakchunk500-Windows/004005.uexp')
    texture_exports = basic.source.inspector.exports(texture_asset, texture_body)
    if not any(e['name'] == 'ProgressBG_HP' and e['type'] == 'Texture2D' for e in texture_exports['exports']):
        raise ValueError('Different texture asset')
    png, pixels = float_rgba_png(texture_body)
    portrait_asset = tracked('ui-layout-study/pakchunk500-Windows-2793.uasset')
    portrait_body = tracked('ui-layout-study/pakchunk500-Windows-2793.uexp')
    portrait_catalog = json.loads(tracked('ui-catalog/pakchunk500-Windows-2793.json'))
    if basic.sha(portrait_asset) != portrait_catalog['asset_sha256'] or basic.sha(portrait_body) != portrait_catalog['body_sha256']:
        raise ValueError('Portrait source differs')
    parsed_portrait = basic.source.inspector.exports(portrait_asset, portrait_body)
    portrait_refs = refs_tool.references(portrait_asset, parsed_portrait)['references']
    image_rows = json.loads((root / 'archive-image-latest.json').read_bytes())
    portrait_brushes, portrait_textures = {}, []
    for name in ['ImageBG', 'ImagePortrait', 'ImageFrame']:
        entry = next(e for e in parsed_portrait['exports'] if e['name'] == name and e['type'] == 'NkImage')
        if portrait_refs[portrait_refs[entry['index']]['class_index']]['path'] != '/Script/NkUMG.NkImage':
            raise ValueError('Portrait NkImage class differs')
        at = entry['offset'] - len(portrait_asset)
        deferred = decode_portrait_deferred(portrait_body[at:at + entry['size']], parsed_portrait['names'])
        matching = [r for r in image_rows if r['asset_path'] == deferred['asset_path']]
        if len(matching) != 1:
            raise ValueError('Ambiguous portrait deferred texture')
        texture = matching[0]
        if basic.sha(tracked(texture['file'])) != texture['sha256']:
            raise ValueError('Portrait texture bytes differ')
        portrait_brushes[name] = dict(deferred, export=entry)
        portrait_textures.append(texture)
    report = dict(schema=1, inputs=inputs, native_source_sha256=basic.SHA, native=native, brushes=brushes, pixels=pixels,
        portrait_brushes=portrait_brushes, portrait_textures=portrait_textures,
        tools={p.name: basic.sha(p.read_bytes()) for p in [Path(__file__), HERE / 'decode-canvas-slots.py', HERE / 'decode-package-references.py']},
        limits=['Static first Brush field only; inherited Image properties and runtime visibility remain open.',
                'Web nine-slice / color projection does not establish live shader or client compatibility.',
                'Portrait uses static source deferred paths; native async loading and dynamic character overrides remain unverified.'])
    identity = basic.sha(json.dumps(report, sort_keys=True).encode())
    folder = root / 'ui-status-skin' / identity
    folder.mkdir(parents=True, exist_ok=True)
    texture = dict(asset_path='/Game/RED/UI/Resource/Texture/GameUI/ProgressBG_HP',
        file=(folder / 'ProgressBG_HP.png').relative_to(root).as_posix(), sha256=basic.sha(png),
        width=pixels['width'], height=pixels['height'], origin='decoded-unreal-float-texture')
    report['texture'] = texture
    for name, value in [('ProgressBG_HP.png', png), ('index.json', json.dumps(report, ensure_ascii=False, sort_keys=True).encode())]:
        path = folder / name
        if path.exists() and path.read_bytes() != value:
            raise ValueError('Published status skin differs')
        if not path.exists():
            with path.open('xb') as stream:
                stream.write(value)
    inputs[(folder / 'index.json').relative_to(root).as_posix()] = basic.sha((folder / 'index.json').read_bytes())
    return report, texture, inputs
