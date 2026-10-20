"""Join current cooked GameMode inheritance with source-bound native tables.

Reads public client files only. Does not infer an active world's GameMode from
an imported class, execute the client, or decode unversioned default properties.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
INDEX_SHA = 'a6660a69d4b045fd19b8880aae3d6bab9a30e087a0cac2a7da07f73f3566de34'
CLASSES = (
    ('RdGameModeInGame', 0x1468de1b0, 0x1468de1f6, 0x1468de205, 0x1468de217, 0x1468e2aa0, 0x149e0f1f0, 0x1468f1e90),
    ('RdGameModeInArena', 0x1468de400, 0x1468de446, 0x1468de455, 0x1468de467, 0x1468e2a20, 0x149e0fc10, 0x1468f1e90),
    ('RdGameModeInConquest', 0x1468de8f0, 0x1468de936, 0x1468de945, 0x1468de957, 0x1468e2a60, 0x149e10630, 0x1468f1e90),
    ('RdGameModeCharacterSelect', 0x1468e0810, 0x1468e0856, 0x1468e0865, 0x1468e0877, 0x1468e29a0, 0x149e0e7c8, 0x1468f1d70),
)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    native = load('world_owner_resource_native', HERE / 'build-native-entry-code.py')
    package = load('world_owner_resource_package', HERE / 'inspect-ui.py')
    references = load('world_owner_resource_refs', HERE / 'decode-package-references.py')
    reader_path = HERE.parent / 'rfnext/scan-pak.py'
    reader = load('world_owner_resource_reader', reader_path)
    root = native.ROOT
    candidates = list((root / 'release-snapshots').glob('*/record-indexes/*/' + INDEX_SHA + '/manifest.json'))
    if len(candidates) != 1:
        raise ValueError('Missing or ambiguous pinned current record index')
    index_path = candidates[0]
    index_raw = index_path.read_bytes()
    if digest(index_raw) != INDEX_SHA:
        raise ValueError('Record index changed')
    index = json.loads(index_raw)
    if (digest(reader_path.read_bytes()) != index['dependencies']['reader_sha256'] or
            digest((reader.ROOT / 'tools/oodle-data-shared.dll').read_bytes()) != index['dependencies']['oodle_sha256']):
        raise ValueError('Record decoder dependency changed')
    source = Path(index['source']['path'])
    before = source.stat()
    if digest(source.read_bytes()) != index['source']['sha256']:
        raise ValueError('Current GameMode PAK changed')
    blueprints = []
    prefix = '/Game/RED/Blueprint/GameMode/BP_GM_'
    with source.open('rb') as stream:
        for entry in index['entries']:
            if not any(p.startswith(prefix) for p in entry.get('paths', [])):
                continue
            parts, provenance = [], []
            # Adjacency is a candidate only: package parsing and export/CDO
            # identity below must also succeed before accepting the pair.
            for row in (entry, index['entries'][entry['entry'] + 1]):
                header = reader.header(stream, row['offset'], index['index_offset'])
                if (not header or header['encrypted'] or header['end'] != row['end'] or
                        not 0 < header['usize'] <= 2 * 1024 * 1024):
                    raise ValueError('GameMode record bounds changed')
                raw = reader.decode(stream, header)
                if len(raw) != row['uncompressed'] or digest(raw) != row['decoded_sha256']:
                    raise ValueError('GameMode decoded bytes changed')
                parts.append(raw)
                provenance.append(dict(entry=row['entry'], offset=row['offset'], end=row['end'],
                                       sha256=digest(raw), size=len(raw)))
            parsed = package.exports(*parts)
            refs = references.references(parts[0], parsed)
            classes = [r for r in refs['references'].values()
                       if r['kind'] == 'export' and r.get('super_index', 0) < 0]
            if not refs['package_name'].startswith(prefix) or len(classes) != 1:
                raise ValueError('Expected one GameMode generated class')
            cls = classes[0]
            short = refs['package_name'].rsplit('/', 1)[1]
            if cls['name'] != short + '_C' or not any(
                    e['name'] == 'Default__' + cls['name'] and e.get('class_index') == cls['index']
                    for e in refs['references'].values()):
                raise ValueError('GameMode class/default identity mismatch')
            parent = refs['references'][cls['super_index']]
            blueprints.append(dict(package=refs['package_name'], parts=provenance,
                                   generated_class=cls, superclass=parent,
                                   default_properties_decoded=False))
    after = source.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('PAK changed during extraction')
    if len(blueprints) != 8:
        raise ValueError('Expected eight current GameMode packages')

    manifest_raw = (root / 'ghidra/entry-manifest.json').read_bytes()
    manifest = json.loads(manifest_raw)
    raw = Path(manifest['source']).read_bytes()
    if digest(raw) != manifest['source_sha256']:
        raise ValueError('Native source changed')
    image = native.Image(raw)
    roots = {image.roots[image.containing(a)] for row in CLASSES for a in (row[1], row[5])}
    fragments = native.decode_ranges(image, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    links = []
    for name, register, name_site, package_site, ctor_site, ctor, table, callback in CLASSES:
        anchors = []
        for site, text in ((name_site, name), (package_site, '/Script/ProjectRED')):
            row = rows[site]
            if row['mnemonic'] != 'lea' or len(row['rip_references']) != 1:
                raise ValueError('Native registration literal instruction changed')
            pos = image.offset(row['rip_references'][0] - image.pe.base)
            expected = (text + '\0').encode('utf-16le')
            if raw[pos:pos + len(expected)] != expected:
                raise ValueError('Native class registration literal changed')
            anchors.append(row)
        if rows[ctor_site]['rip_references'] != [ctor]:
            raise ValueError('Registration constructor reference changed')
        anchors.append(rows[ctor_site])
        ctor_rows = [r for f in fragments if f['root_begin_rva'] + image.pe.base == ctor for r in f['instructions']]
        table_rows = [r for r in ctor_rows if table in r['rip_references']]
        if len(table_rows) != 1:
            raise ValueError('Constructor table assignment changed')
        anchors.extend(table_rows)
        following = rows[table_rows[0]['address'] + len(bytes.fromhex(table_rows[0]['bytes']))]
        if following['mnemonic'] == 'mov' and following['operands'] == 'qword ptr [rbx + 0x3e0], 0':
            anchors.append(following)
            following = rows[following['address'] + len(bytes.fromhex(following['bytes']))]
        if following['mnemonic'] != 'mov' or following['operands'] != 'qword ptr [rbx], rax':
            raise ValueError('Constructor does not store the table at the object start')
        anchors.append(following)
        pos = image.offset(table + 0x7b0 - image.pe.base)
        if struct.unpack_from('<Q', raw, pos)[0] != callback:
            raise ValueError('GameMode virtual slot changed')
        path = '/Script/ProjectRED.' + name
        matches = [b['package'] for b in blueprints if b['superclass']['path'] == path]
        if not matches:
            raise ValueError('Native class has no matching cooked superclass')
        links.append(dict(native_class=path, registration=register, constructor=ctor,
                          vtable=table, slot_offset=0x7b0, slot_target=callback,
                          slot_file_offset=pos, slot_bytes=raw[pos:pos + 8].hex(),
                          anchors=anchors, cooked_packages=matches))
    travel_fragments = native.decode_ranges(image, {image.roots[image.containing(0x14432beb0)]})
    travel_rows = [r for f in travel_fragments for r in f['instructions']]
    assignments = []
    for address, operands in ((0x14432c7b4, 'qword ptr [rbx + 0x158], r13'),
                              (0x14432cdab, 'qword ptr [r14 + 0x158], rbx')):
        position = next(i for i, r in enumerate(travel_rows) if r['address'] == address)
        row = travel_rows[position]
        if (row['mnemonic'], row['operands']) != ('mov', operands):
            raise ValueError('Travel owner assignment changed')
        assignments.append(dict(address=address, executed=False,
                                instructions=travel_rows[max(0, position - 22):position + 3]))
    report = dict(source=manifest['source'], source_sha256=manifest['source_sha256'],
                  manifest_sha256=digest(manifest_raw), source_pak=index['source'],
                  record_index=str(index_path), record_index_sha256=INDEX_SHA,
                  tool_sha256=digest(Path(__file__).read_bytes()),
                  package_reader_sha256=digest((HERE / 'inspect-ui.py').read_bytes()),
                  reference_reader_sha256=digest((HERE / 'decode-package-references.py').read_bytes()),
                  blueprints=blueprints, native_links=links, fragments=fragments,
                  travel_owner_assignments=assignments,
                  active_world_class_verified=False,
                  limitations=['Cooked superclass imports identify inheritance, not active world settings.',
                               'The engine provider at +0x1d8/slot +0x3d0 and world +0x158 assignment remain unexecuted.',
                               'No real session, world arrival or position semantics verified.'])
    output = root / 'code-clues/world-owner-resources.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps(dict(output=str(output), blueprints=len(blueprints), native_links=len(links),
                          sha256=digest(output.read_bytes()))))


if __name__ == '__main__':
    main()
