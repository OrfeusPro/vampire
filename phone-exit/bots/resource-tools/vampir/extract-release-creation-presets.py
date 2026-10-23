"""Decode explicit current preset tables and their unique class-3 asset links."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
SHA = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
PREFIX = '/Game/RED/Blueprint/'
TABLES = tuple(PREFIX + 'DataTable/Customize/DT_CustomizePreset' + g for g in ('F', 'M'))
ASSET_FIELDS = ['HairIndex', 'HeadIndex', 'HairColorIndex', 'SkinColorIndex', 'DecalIndex',
    'DecalColorIndex', 'EyeColorLeftIndex', 'EyeColorRightIndex', 'EyeTexIndex',
    'Shape', 'Cheat', 'Height', 'Pelvis', 'Waist', 'Thigh', 'Head', 'VoiceType']


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def schema(root):
    native = load('preset_native_schema', 'build-native-entry-code.py')
    helpers = load('preset_resource_helpers_schema', 'extract-release-appearance-resources.py')
    source = root / 'client-code-snapshots' / SHA / 'ProjectRED-Win64-Shipping.exe'
    if helpers.digest(source) != SHA: raise ValueError('Preset EXE source changed')
    raw = source.read_bytes(); image = native.Image(raw)
    def at(address, length):
        offset = image.offset(address - image.pe.base)
        return raw[offset:offset + length]
    def descriptors(address, expected):
        pointers = struct.unpack('<' + 'Q' * len(expected), at(address, 8 * len(expected)))
        result = []
        for pointer, (name, flags, offset) in zip(pointers, expected):
            data = at(pointer, 56); name_at = struct.unpack_from('<Q', data)[0]
            if (at(name_at, len(name) + 1) != name.encode('ascii') + b'\0'
                    or struct.unpack_from('<I', data, 24)[0] != flags
                    or struct.unpack_from('<I', data, 50)[0] != offset):
                raise ValueError('Preset property descriptor differs')
            result.append(dict(name=name, flags=flags, offset=offset, descriptor=hex(pointer), bytes=data.hex()))
        return result
    base = descriptors(0x149858498, [('ID', 3, 8), ('PresetDataAsset', 18, 16), ('IconTexture', 16, 24), ('Order', 3, 64)])
    derived = descriptors(0x149a25788, [('UnderlyingType', 0, 0), ('RecommandClassType', 30, 72), ('Memo', 21, 80)])
    asset = descriptors(0x1498b5ff0, [(name, 3 if i < 9 else 10, 0x30 + 4 * i)
        for i, name in enumerate(ASSET_FIELDS[:16])] + [('UnderlyingType', 0, 0), ('VoiceType', 30, 112)])
    if struct.unpack('<Q', at(0x14b1cc1c8 + 8, 8))[0] != 0x14545dd00:
        raise ValueError('Preset row superclass changed')
    if struct.unpack('<Q', at(0x14b1b3060 + 32, 8))[0] != 0x149858498:
        raise ValueError('Preset base property array changed')
    return dict(source_sha256=SHA, base=base, derived=derived, asset=asset,
        row_wire_order=['RecommandClassType', 'Memo', 'ID', 'PresetDataAsset', 'IconTexture', 'Order'])


def table(body, names, references, struct_index):
    uv = load('preset_table_reader', 'decode-canvas-slots.py'); r = uv.Reader(body)
    if r.header() != [(0, False)] or r.read('<i') != struct_index or r.read('<I') != 0:
        raise ValueError('Unsupported preset table prefix')
    count = r.read('<i')
    if not 0 <= count <= 128: raise ValueError('Preset row count bound')
    def fname():
        index, number = r.read('<ii')
        if not 0 <= index < len(names) or not 0 <= number <= 1000000: raise ValueError('Preset FName bound')
        return names[index] + ('_' + str(number - 1) if number else '')
    def string():
        size = r.read('<i')
        if size == 0: return ''
        if not 0 < size <= 4096 or r.pos + size > len(body): raise ValueError('Preset FString bound')
        raw = body[r.pos:r.pos + size]; r.pos += size
        if not raw.endswith(b'\0') or b'\0' in raw[:-1]: raise ValueError('Invalid preset FString')
        return raw[:-1].decode('utf-8')
    rows = []
    for _ in range(count):
        name = fname(); properties = r.header()
        if [i for i, _ in properties] != list(range(6)): raise ValueError('Unsupported preset row field set')
        values = {}
        for index, zero in properties:
            if index == 0: values['class_type'] = 0 if zero else r.read('<B')
            elif index == 1: values['memo'] = '' if zero else string()
            elif index == 2: values['id'] = 0 if zero else r.read('<i')
            elif index == 3:
                ref = 0 if zero else r.read('<i')
                if not ref or str(ref) not in references: raise ValueError('Preset asset reference missing')
                reference = references[str(ref)]
                if reference['kind'] != 'import': raise ValueError('Unsupported local preset asset')
                values['asset'] = reference['path']
            elif index == 4: values['icon'] = None if zero else dict(package=fname(), asset=fname(), subpath=string())
            else: values['order'] = 0 if zero else r.read('<i')
        rows.append(dict(row=name, **values))
    if r.pos != len(body) or len({row['row'] for row in rows}) != len(rows):
        raise ValueError('Preset table trailing bytes or duplicate row')
    return rows


def asset(body):
    uv = load('preset_asset_reader', 'decode-canvas-slots.py'); r = uv.Reader(body)
    values = {name: None for name in ASSET_FIELDS}
    origins = {name: 'unresolved_CDO_integer' for name in ASSET_FIELDS}
    for name in ASSET_FIELDS[9:16]: values[name] = 0.5; origins[name] = 'native_constructor'
    values['VoiceType'] = 0; origins['VoiceType'] = 'native_constructor'
    seen = set()
    for index, zero in r.header():
        if index >= len(ASSET_FIELDS) or index in seen: raise ValueError('Unknown preset asset field')
        seen.add(index); name = ASSET_FIELDS[index]
        values[name] = 0 if zero else r.read('<i' if index < 9 else '<f' if index < 16 else '<B')
        origins[name] = 'serialized_zero' if zero else 'serialized'
    if r.read('<I') != 0 or r.pos != len(body): raise ValueError('Preset asset GUID/trailer differs')
    return dict(values=values, origins=origins, unresolved=[name for name, value in values.items() if value is None])


def constructor_defaults():
    native = load('preset_constructor_archive', 'replay-release-archive-input.py')
    hooks = dict.fromkeys((0x1417d69b0, 0x143b5fa80))
    h = native.make_harness(extra_addresses=(0x1454d6800,), fixtures=hooks)
    uc, x = h.uc, h.x
    pointer, obj = h.scratch + 0x10000, h.scratch + 0x11000
    def fixture(machine):
        if machine.reg_read(x.UC_X86_REG_RIP) == 0x1417d69b0: machine.reg_write(x.UC_X86_REG_RAX, 0)
        elif machine.reg_read(x.UC_X86_REG_RCX) != obj: raise ValueError('Preset base constructor argument differs')
        sp = machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RIP, int.from_bytes(machine.mem_read(sp, 8), 'little'))
        machine.reg_write(x.UC_X86_REG_RSP, sp + 8)
    for at in hooks: hooks[at] = fixture
    cases = []
    for poison in (0, 0xa5, 0xff):
        uc.mem_write(obj - 16, bytes((poison,)) * (0x78 + 32))
        uc.mem_write(pointer, struct.pack('<Q', obj)); h.call(0x1454d6800, pointer)
        floats = list(struct.unpack('<7f', bytes(uc.mem_read(obj + 0x54, 28))))
        if floats != [0.5] * 7 or bytes(uc.mem_read(obj + 0x70, 1)) != b'\0':
            raise ValueError('Preset constructor defaults differ')
        if bytes(uc.mem_read(obj + 0x30, 0x24)) != bytes((poison,)) * 0x24:
            raise ValueError('Preset constructor integer fields changed')
        if bytes(uc.mem_read(obj - 16, 16)) != bytes((poison,)) * 16 or bytes(uc.mem_read(obj + 0x78, 16)) != bytes((poison,)) * 16:
            raise ValueError('Preset constructor guard changed')
        cases.append(dict(poison=poison, floats=floats, voice=0, integer_bytes_preserved=True))
    return dict(native_execution=True, cases=cases,
        limits=['Base constructor/type lookup are fixtures; omitted integer defaults in the actual CDO remain unresolved.'])


def native_template(references, export):
    refs = {str(key): value for key, value in references['references'].items()}
    row = refs.get(str(export['index']))
    if not row or row['kind'] != 'export' or row['super_index'] != 0:
        raise ValueError('Preset export has unsupported superclass')
    cls = refs.get(str(row['class_index']), {})
    template = refs.get(str(row['template_index']), {})
    if cls.get('kind') != 'import' or cls.get('path') != '/Script/NnFramework.NnDataAssetForCustomizePreset':
        raise ValueError('Preset native class binding differs')
    if template.get('kind') != 'import' or template.get('path') != '/Script/NnFramework.Default__NnDataAssetForCustomizePreset':
        raise ValueError('Preset native CDO template binding differs')
    return dict(class_path=cls['path'], template_path=template['path'],
        class_index=row['class_index'], template_index=row['template_index'],
        export_table_bytes=row['table_bytes'])


def native_default_model():
    native = load('preset_default_object_model', 'replay-release-preset-object.py')
    path, report = native.run()
    vectors = {case['default_bytes'] for case in report['cases']}
    if report['source_sha256'] != SHA or len(vectors) != 1:
        raise ValueError('Preset native default model is ambiguous')
    raw = bytes.fromhex(vectors.pop())
    if len(raw) != 0x41: raise ValueError('Preset native default vector size differs')
    values = {}
    for i, name in enumerate(ASSET_FIELDS):
        values[name] = struct.unpack_from('<i' if i < 9 else '<f' if i < 16 else '<B', raw, i * 4)[0]
    return dict(report=str(path), source_sha256=SHA, values=values,
        model_only=True, verified_loaded_asset=False, limits=report['limits'])


def project_native_defaults(decoded, model):
    if model.get('source_sha256') != SHA or model.get('model_only') is not True:
        raise ValueError('Preset native default model provenance differs')
    inferred = list(decoded['unresolved']); values = dict(decoded['values']); origins = dict(decoded['origins'])
    for name in inferred:
        values[name] = model['values'][name]; origins[name] = 'native_zero_allocation_model'
    return dict(values=values, origins=origins, inferred_fields=inferred, model_only=True,
        verified_loaded_asset=False, report=model['report'])


def extract(index_path, directory_path, root):
    helpers = load('preset_named_helpers', 'extract-release-appearance-resources.py')
    if helpers.digest(index_path) != index_path.parent.name: raise ValueError('Preset record index hash changed')
    comparison = root / 'ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details'
    exports = {}
    for run, expected in [('run-0c0270dde1c5', '1da2dc05fa509742f80ba09cd93d32c324c40a577eb16632c151244570e32187'),
                          ('run-2e4ce3671ec8', '227beefd32196b24cbf89f2d81e6195bac686005d67f6fff97e77c2ecc0998cf'),
                          ('run-3cb7258f777e', '0c71553f62ed00205bca5ae915df559afdba04a2a2002fd8893ed323d0b454b8')]:
        path = comparison / run / 'details.json'
        if helpers.digest(path) != expected: raise ValueError('Preset schema export changed')
        exports[str(path)] = expected
    index = json.loads(index_path.read_text('utf-8')); source = Path(index['source']['path']); before = source.stat()
    if helpers.digest(source) != index['source']['sha256']: raise ValueError('Preset PAK source changed')
    reader_path = HERE.parent / 'rfnext/scan-pak.py'
    reader = helpers.load('preset_package_reader', reader_path)
    if (helpers.digest(reader_path) != index['dependencies']['reader_sha256']
            or helpers.digest(reader.ROOT / 'tools/oodle-data-shared.dll') != index['dependencies']['oodle_sha256']):
        raise ValueError('Preset pinned reader changed')
    package = load('preset_package_exports', 'inspect-ui.py'); references = load('preset_package_refs', 'decode-package-references.py')
    descriptors = schema(root); defaults = constructor_defaults(); model = native_default_model(); blobs = {}; packages = []
    def read_targets(targets):
        named = helpers.named_records(directory_path, index, targets)
        for target, entries in named.items():
            parts, evidence = [], []
            with source.open('rb') as stream:
                for part, (row, filename) in enumerate(entries):
                    if row.get('decode_status') != 'decoded' or row['encrypted'] or not 0 < row['uncompressed'] <= 1024 * 1024:
                        raise ValueError('Unsupported preset record')
                    header = reader.header(stream, row['offset'], index['index_offset'])
                    if not header or header['end'] != row['end']: raise ValueError('Preset record header changed')
                    data = reader.decode(stream, header)
                    if len(data) != row['uncompressed'] or helpers.hashlib.sha256(data).hexdigest() != row['decoded_sha256']:
                        raise ValueError('Preset decoded hash changed')
                    parts.append(data); filename_blob = row['decoded_sha256'] + ('.uasset' if part == 0 else '.uexp')
                    blobs[filename_blob] = data
                    evidence.append(dict(filename=filename, blob=filename_blob, sha256=row['decoded_sha256'], entry=row['entry']))
            parsed = package.exports(*parts); refs = references.references(parts[0], parsed)
            if refs['package_name'] != target or len(parsed['exports']) != 1: raise ValueError('Preset package identity differs')
            export = parsed['exports'][0]; start = export['offset'] - len(parts[0]); body = parts[1][start:start + export['size']]
            item = dict(package=target, parts=evidence, export=export, names=parsed['names'], references=refs)
            if target in TABLES:
                structs = [v for v in refs['references'].values() if v['name'] == 'RdDataTableRowForCustomizePreset']
                if export['type'] != 'DataTable' or len(structs) != 1: raise ValueError('Preset row struct missing')
                item['rows'] = table(body, parsed['names'], {str(k): v for k, v in refs['references'].items()}, structs[0]['index'])
            else:
                if export['type'] != 'NnDataAssetForCustomizePreset': raise ValueError('Preset asset class differs')
                item['native_template'] = native_template(refs, export)
                item['decoded'] = asset(body)
                item['native_default_projection'] = project_native_defaults(item['decoded'], model)
            packages.append(item)
    read_targets(TABLES)
    links = []
    for item in packages:
        selected = [row for row in item['rows'] if row['class_type'] == 3]
        if len(selected) != 1: raise ValueError('Class-3 preset is missing or ambiguous')
        ref = selected[0]['asset']; target, object_name = ref.rsplit('.', 1)
        if target.rsplit('/', 1)[-1] != object_name: raise ValueError('Preset object path differs')
        links.append(dict(table=item['package'], preset_id=selected[0]['id'], class_type=3, package=target))
    read_targets(tuple(link['package'] for link in links))
    after = source.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or helpers.digest(source) != index['source']['sha256']:
        raise ValueError('Preset PAK changed during extraction')
    for name, data in blobs.items():
        path = root / 'code-clues/appearance-resource-blobs' / name; path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open('xb') as stream: stream.write(data)
        except FileExistsError:
            if path.read_bytes() != data: raise ValueError('Existing preset blob corrupt') from None
    audit = load('preset_resource_audit', 'audit-client-release.py')
    dependencies = {str(path): helpers.digest(path) for path in (reader_path, Path(__file__),
        HERE / 'extract-release-appearance-resources.py', HERE / 'recover-pak-game-config.py', HERE / 'inspect-ui.py',
        HERE / 'decode-package-references.py', HERE / 'decode-canvas-slots.py', HERE / 'replay-release-archive-input.py',
        HERE / 'replay-release-preset-object.py')}
    report = dict(source=index['source'], source_sha256=SHA, record_index=str(index_path),
        record_index_sha256=helpers.digest(index_path), directory_manifest=str(directory_path),
        directory_manifest_sha256=helpers.digest(directory_path), schema=descriptors, constructor=defaults, native_default_model=model,
        packages=packages, selected_class3=links, dependencies=dependencies, ghidra_exports=exports,
        limits=['Derived row fields precede inherited fields; exact observed six-field layout, complete body consumption and references checked.',
            'Unique class-3 links in these current tables; active engine cache and F/M byte conversion are not executed here.',
            'Omitted float/voice values use reviewed native constructor; omitted integer CDO defaults stay explicitly unresolved.',
            'Separate native_default_projection infers omitted integers from the explicit zero-allocation native model; it is not loaded-asset verification and does not change decoded values.',
            'No game, authorization, JSON output, complete producer or character creation.'])
    path = audit.save_snapshot(root / 'code-clues/release-creation-presets', report)
    return path, report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record_index', type=Path); parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args(); path, report = extract(args.record_index, args.directory, args.root)
    print(json.dumps(dict(report=str(path), selected=report['selected_class3'])))
