"""Extract two explicit BoneGroup packages from a fresh full-SHA record index."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
TARGETS = tuple('/Game/RED/Blueprint/DataTable/Customize/DT_CustomizeBoneGroup' + suffix for suffix in ('F', 'M'))
LIMIT = 1024 * 1024


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
    return tool


def digest(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def decode_groups(body, names, row_struct_index):
    """Only the source-verified three-property BoneCustomizeGroup layout."""
    decoder = load('appearance_unversioned', HERE / 'decode-canvas-slots.py')
    r = decoder.Reader(body)
    if r.header() != [(0, False)] or r.read('<i') != row_struct_index or r.read('<I') != 0:
        raise ValueError('Unsupported appearance DataTable prefix')
    count = r.read('<i')
    if not 0 <= count <= 128: raise ValueError('Appearance group count bound')
    def name():
        index, number = r.read('<ii')
        if not 0 <= index < len(names) or number != 0:
            raise ValueError('Unsupported appearance FName')
        return names[index]
    def string():
        size = r.read('<i')
        if not 0 < size <= 256 or r.pos + size > len(body):
            raise ValueError('Appearance bone string bound')
        data = body[r.pos:r.pos + size]; r.pos += size
        if not data.endswith(b'\0') or b'\0' in data[:-1]:
            raise ValueError('Invalid appearance bone string')
        return data[:-1].decode('utf-8')
    rows = []
    for _ in range(count):
        row_name = name()
        if r.header() != [(0, False), (1, False), (2, False)]:
            raise ValueError('Unsupported appearance group property layout')
        group, identifier, bones = name(), r.read('<i'), r.read('<i')
        if not 0 <= bones <= 256 or not 0 < identifier <= 0x7fffffff:
            raise ValueError('Appearance group values out of bounds')
        rows.append(dict(row=row_name, group_name=group, id=identifier, bone_name_ids=[string() for _ in range(bones)]))
    if r.pos != len(body) or len({row['id'] for row in rows}) != len(rows) or len({row['row'] for row in rows}) != len(rows):
        raise ValueError('Appearance group trailing bytes or duplicate identity')
    return rows


def native_schema(root):
    sha = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
    source = root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
    if digest(source) != sha: raise ValueError('Appearance schema EXE changed')
    native = load('appearance_schema_native', HERE / 'build-native-entry-code.py')
    raw = source.read_bytes(); image = native.Image(raw)
    def at(address, length): return raw[image.offset(address - image.pe.base):][:length]
    if struct.unpack('<Q', at(0x14b1b2e30 + 0x20, 8))[0] != 0x14984b218:
        raise ValueError('Appearance struct property array changed')
    result = []
    expected = [('GroupName', 20, 8), ('ID', 3, 16), ('BoneNameIDs', 21, 0), ('BoneNameIDs', 22, 24)]
    for pointer, (name, flags, offset) in zip(struct.unpack('<4Q', at(0x14984b218, 32)), expected):
        data = at(pointer, 56); string_at = struct.unpack_from('<Q', data)[0]
        if (at(string_at, len(name) + 1) != name.encode() + b'\0'
                or struct.unpack_from('<I', data, 24)[0] != flags
                or struct.unpack_from('<I', data, 50)[0] != offset):
            raise ValueError('Appearance struct property descriptor changed')
        result.append(dict(name=name, gen_flags=flags, object_offset=offset, descriptor=hex(pointer), bytes=data.hex()))
    return dict(source_sha256=sha, properties=result, serialized_properties=['GroupName', 'ID', 'BoneNameIDs'])


def named_records(directory_path, index, targets=TARGETS):
    """Join authenticated names to fresh record offsets, never adjacent records."""
    if digest(directory_path) != directory_path.parent.name:
        raise ValueError('Appearance directory manifest hash changed')
    manifest = json.loads(directory_path.read_text('utf-8'))
    if (manifest.get('authoritative_directory_for_archive') is not True
            or manifest['archive_sha256'] != index['source']['sha256']
            or Path(manifest['source_archive']['path']).resolve() != Path(index['source']['path']).resolve()):
        raise ValueError('Appearance directory archive identity differs')
    directory_file = directory_path.parent / 'directory.json'
    encoded_file = directory_path.parent / 'encoded-entries.bin'
    if (digest(directory_file) != manifest['directory_paths_file_sha256']
            or digest(encoded_file) != manifest['encoded_entries_file_sha256']):
        raise ValueError('Appearance directory material hash changed')
    directory = json.loads(directory_file.read_text('utf-8'))
    entries = {row['path']: row for row in directory['entries']}
    if (len(entries) != len(directory['entries'])
            or len(entries) != manifest['main_metadata']['entry_count']):
        raise ValueError('Appearance directory identity/count differs')
    core = load('appearance_named_entry', HERE / 'recover-pak-game-config.py')
    encoded = encoded_file.read_bytes()
    result = {}
    for target in targets:
        parts = []
        for suffix in ('.uasset', '.uexp'):
            name = 'ProjectRED/Content/' + target.removeprefix('/Game/') + suffix
            if name not in entries: raise ValueError('Named appearance file missing')
            decoded = core.decode_small_entry(encoded, entries[name]['encoded_entry_offset'])
            matches = [row for row in index['entries'] if row['offset'] == decoded['offset']]
            if len(matches) != 1: raise ValueError('Named appearance record missing or ambiguous')
            row = matches[0]
            if any(row[a] != decoded[b] for a, b in
                    [('bytes', 'size'), ('uncompressed', 'usize'), ('method', 'method'), ('encrypted', 'encrypted')]):
                raise ValueError('Named appearance entry differs from fresh record')
            parts.append((row, name))
        result[target] = parts
    return result


def extract(index_path, root, directory_path):
    if digest(index_path) != index_path.parent.name:
        raise ValueError('Appearance record index hash changed')
    index = json.loads(index_path.read_text('utf-8'))
    source = Path(index['source']['path'])
    before = source.stat()
    if digest(source) != index['source']['sha256']:
        raise ValueError('Appearance source archive changed')
    named = named_records(directory_path, index)
    reader_path = HERE.parent / 'rfnext/scan-pak.py'
    if digest(reader_path) != index['dependencies']['reader_sha256']:
        raise ValueError('Appearance record reader changed')
    reader = load('appearance_pak_reader', reader_path)
    if digest(reader.ROOT / 'tools/oodle-data-shared.dll') != index['dependencies']['oodle_sha256']:
        raise ValueError('Appearance decoder changed')
    package = load('appearance_package', HERE / 'inspect-ui.py')
    references = load('appearance_references', HERE / 'decode-package-references.py')
    audit = load('appearance_resource_audit', HERE / 'audit-client-release.py')
    schema = native_schema(root)
    blobs, result = {}, []
    with source.open('rb') as stream:
        for target in TARGETS:
            parts, evidence = [], []
            for part, (row, filename) in enumerate(named[target]):
                if (row is None or row.get('decode_status') != 'decoded' or row['encrypted']
                        or not 0 < row['uncompressed'] <= LIMIT or row['bytes'] > LIMIT):
                    raise ValueError('Unsupported appearance package record')
                header = reader.header(stream, row['offset'], index['index_offset'])
                if not header or header['end'] != row['end']:
                    raise ValueError('Appearance header differs from fresh index')
                data = reader.decode(stream, header)
                if len(data) != row['uncompressed'] or hashlib.sha256(data).hexdigest() != row['decoded_sha256']:
                    raise ValueError('Appearance decoded hash changed')
                parts.append(data)
                suffix = '.uasset' if part == 0 else '.uexp'
                blob = root / 'code-clues/appearance-resource-blobs' / (row['decoded_sha256'] + suffix)
                blobs[blob] = data
                evidence.append(dict(entry=row['entry'], archive_filename=filename, file=str(blob), sha256=row['decoded_sha256'],
                    bytes=len(data), role='package_header' if part == 0 else 'package_body'))
            parsed = package.exports(*parts)
            refs = references.references(parts[0], parsed)
            if refs['package_name'] != target or len(parsed['exports']) != 1 or parsed['exports'][0]['type'] != 'DataTable':
                raise ValueError('Appearance package self identity or export differs')
            struct_refs = [row for row in refs['references'].values()
                if row['name'] == 'NnDataTableRowForBoneCustomizeGroup']
            if len(struct_refs) != 1:
                raise ValueError('Appearance DataTable row struct missing')
            export = parsed['exports'][0]
            start = export['offset'] - len(parts[0])
            groups = decode_groups(parts[1][start:start + export['size']], parsed['names'], struct_refs[0]['index'])
            result.append(dict(package=target, parts=evidence, exports=parsed['exports'], names=parsed['names'],
                row_struct_reference=struct_refs[0]['path'], body_ranges_accounted=True, groups=groups,
                archive_directory_pair_verified=True, rows_decoded=True))
    after = source.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or digest(source) != index['source']['sha256']:
        raise ValueError('Appearance archive changed during extraction')
    for path, data in blobs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open('xb') as output: output.write(data)
        except FileExistsError:
            if path.read_bytes() != data: raise ValueError('Existing appearance blob corrupt') from None
    report = dict(source=index['source'], record_index=str(index_path), record_index_sha256=digest(index_path),
        directory_manifest=str(directory_path), directory_manifest_sha256=digest(directory_path),
        tool_sha256=digest(Path(__file__)), native_schema=schema, dependencies={str(path): digest(path) for path in
            (reader_path, HERE / 'inspect-ui.py', HERE / 'decode-package-references.py', HERE / 'decode-canvas-slots.py',
             HERE / 'recover-pak-game-config.py', HERE / 'recover-release-game-config.py')}, packages=result,
        limits=['Fresh archive full SHA, record hashes and package self paths verified.',
            'Named uasset/uexp pairing uses the verified full directory and encoded entry offsets, not record adjacency.',
            'Historical key candidate decrypted SHA1-verified indexes; current EXE key callback binding remains unverified.',
            'Three-field row schema checked against current EXE descriptors; ranges/default floats not present in these rows.',
            'No runtime, game, network or character creation.'])
    path = audit.save_snapshot(root / 'code-clues/release-appearance-resources', report)
    return path, report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record_index', type=Path)
    parser.add_argument('--directory', type=Path, required=True, help='Full-SHA verified directory-only recovery manifest')
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    path, report = extract(args.record_index, args.root, args.directory)
    print(json.dumps(dict(report=str(path), packages=len(report['packages']), groups=[len(p['groups']) for p in report['packages']])))
