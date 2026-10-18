"""Prove SkillLevel cooldown replacements; keep values in original table units."""
import csv
import hashlib
import importlib.util
import io
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIELDS = {'MinCoolTime': 'ChangeMinCoolTime', 'MaxCoolTime': 'ChangeMaxCoolTime'}


def cooldown_at_level(skill, changes, level):
    """First inclusive range wins. Zero/empty replacement falls back to base."""
    if type(level) is not int or not 0 <= level <= 32767:
        raise ValueError('Skill level must be a nonnegative signed int16')
    selected = next((r for r in changes if r['SkillInfoId'] == skill['Id']
                     and int(r['MinLevel']) <= level <= int(r['MaxLevel'])), None)
    values, origins = {}, {}
    for field, replacement in FIELDS.items():
        raw = selected.get(replacement, '') if selected else ''
        use_change = bool(raw) and int(raw) != 0
        values[field] = raw if use_change else skill[field]
        origins[field] = dict(table='SkillLevel' if use_change else 'Skill',
            field=replacement if use_change else field,
            provenance=(selected if use_change else skill).get('provenance'))
    return dict(level=level, values=values, origins=origins, time_unit=None,
                runtime_cooldown_verified=False)


def main():
    spec = importlib.util.spec_from_file_location('level_native', HERE/'build-native-entry-code.py')
    native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
    source = json.loads((native.ROOT/'code-clues/native-enums.json').read_text('utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256'] or native.capstone.__version__ != '5.0.6':
        raise ValueError('Changed executable or decoder')
    image = native.Image(data)
    roots = {image.roots[image.containing(a)] for a in
             [0x145bc89c0, 0x145bb2570, 0x145bb9f90, 0x145bba020]}
    fragments = native.decode_ranges(image, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    expected = [
        (0x145bc8ef2, 'mov', 'dword ptr [rsi + 8], eax'),
        (0x145bc8f0e, 'mov', 'dword ptr [rsi + 0x18], eax'),
        (0x145bc8f2a, 'mov', 'dword ptr [rsi + 0x1c], eax'),
        (0x145bc944c, 'mov', 'dword ptr [rsi + 0x60], eax'),
        (0x145bc9468, 'mov', 'dword ptr [rsi + 0x64], eax'),
        (0x145bc95a0, 'mov', 'r8d, dword ptr [rdi + 8]'),
        (0x145bc9634, 'lea', 'rbx, [rcx + 8]'),
        (0x145bc9650, 'mov', 'qword ptr [rax + rsi*8], rdi'),
        (0x145bb2699, 'lea', 'rax, [rip + 0x3e07918]'),
        (0x145bb26a0, 'mov', 'qword ptr [rip + 0x55a5079], rax'),
        (0x145bb26a7, 'lea', 'rax, [rip + 0x3e079aa]'),
        (0x145bb26ae, 'mov', 'qword ptr [rip + 0x55a5073], rax'),
        (0x145bb25eb, 'mov', 'rdx, qword ptr [rip + 0x55a5156]'),
        (0x145bb9fb4, 'call', '0x145bb2570'),
        (0x145bb9fd8, 'cmp', 'dword ptr [rax + 0x18], ecx'),
        (0x145bb9fdb, 'jg', '0x145bb9fe2'),
        (0x145bb9fdd, 'cmp', 'dword ptr [rax + 0x1c], ecx'),
        (0x145bb9fe0, 'jge', '0x145bb9ffc'),
        (0x145bb9ffc, 'mov', 'eax, dword ptr [rax + 0x64]'),
        (0x145bb9fff, 'test', 'eax, eax'),
        (0x145bba001, 'jne', '0x145bba009'),
        (0x145bba003, 'mov', 'eax, dword ptr [rbx + 0xcc]'),
        (0x145bba044, 'call', '0x145bb2570'),
        (0x145bba08c, 'mov', 'eax, dword ptr [rax + 0x60]'),
        (0x145bba08f, 'test', 'eax, eax'),
        (0x145bba091, 'jne', '0x145bba099'),
        (0x145bba093, 'mov', 'eax, dword ptr [rbx + 0xd0]'),
    ]
    anchors = []
    for a, mnemonic, operands in expected:
        row = rows[a]
        if (row['mnemonic'], row['operands']) != (mnemonic, operands):
            raise ValueError('Changed level anchor '+hex(a)+': '+row['operands'])
        anchors.append(row)
    literals = []
    for a, name in [(0x145bc8a85, 'SkillLevel.csv'), (0x145bc8b41, 'SkillInfoId'),
                    (0x145bc8b55, 'MinLevel'), (0x145bc8b63, 'MaxLevel'),
                    (0x145bc8ba9, 'ChangeMinCoolTime'), (0x145bc8bb7, 'ChangeMaxCoolTime')]:
        row = rows[a]; offset = image.offset(row['rip_references'][0]-image.pe.base)
        raw = name.encode()+b'\0'
        if data[offset:offset+len(raw)] != raw:
            raise ValueError('Changed level field '+name)
        anchors.append(row)
        literals.append(dict(name=name, file_offset=offset, bytes=raw.hex()))
    slots = []
    for address, target in [(0x1499ba058+0x38, 0x145bc89c0),
                            (0x1499b9440+0xb8, 0x145bb9f90),
                            (0x1499b9440+0xc8, 0x145bba020)]:
        offset = image.offset(address-image.pe.base); raw = struct.pack('<Q', target)
        if data[offset:offset+8] != raw:
            raise ValueError('Changed SkillLevel vtable')
        slots.append(dict(address=address, file_offset=offset, bytes=raw.hex()))
    metadata = {m['entry']: m for m in json.loads(
        (native.ROOT/'table-study/index-pakchunk1-Windows.json').read_text('utf-8'))['tables']}
    sources = {}
    def table(name, entry):
        meta = metadata[entry]; raw = (native.ROOT/'table-study'/meta['file']).read_bytes()
        if hashlib.sha256(raw).hexdigest() != meta['sha256']:
            raise ValueError('Changed CSV '+name)
        reader = csv.DictReader(io.StringIO(raw.decode('utf-8-sig')))
        if reader.fieldnames != meta['header']:
            raise ValueError('Changed schema '+name)
        result = [dict(r, provenance=dict(table=name, entry=entry, csv_record=i+2))
                  for i, r in enumerate(reader)]
        if len(result) != meta['rows']:
            raise ValueError('Changed row count '+name)
        sources[name] = meta
        return result
    changes = table('SkillLevel', 1511)
    skills = {r['Id']: r for r in table('Skill', 1505)}
    profiles = []
    for row in changes:
        skill = skills[row['SkillInfoId']]
        lo, hi = int(row['MinLevel']), int(row['MaxLevel'])
        if lo > hi:
            raise ValueError('Reversed level range')
        profiles.append(dict(record=row, base=skill,
            levels=[cooldown_at_level(skill, changes, level) for level in sorted({max(0,lo-1),lo,hi,hi+1})]))
    # Scope is the checked atlas manifest, not every NPC shipped in the game.
    manifest_path = native.ROOT/'maps/atlas/monster-manifest.json'
    manifest = json.loads(manifest_path.read_text('utf-8')); affected = []
    npc_skills = set()
    for nid, meta in manifest['files'].items():
        raw = (manifest_path.parent/meta['file']).read_bytes()
        if hashlib.sha256(raw).hexdigest() != meta['sha256']:
            raise ValueError('Changed atlas NPC '+nid)
        npc_skills.update(json.loads(raw)['skills'])
    affected = sorted(npc_skills & {r['SkillInfoId'] for r in changes})
    result = dict(source=source['source'], sha256=source['sha256'], anchors=anchors,
        literals=literals, vtable_slots=slots, fragments=fragments, sources=sources,
        profiles=profiles, csv_time_unit=None,
        verified=dict(skill_id_join=True, inclusive_level_range=True, nonzero_replacement=True),
        atlas=dict(manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                   npcs=len(manifest['files']), unique_skills=len(npc_skills), affected_skill_ids=affected),
        relations=['SkillLevel.SkillInfoId → index → Skill.Id getters',
            'SkillLevel.ChangeMinCoolTime/+0x60 → Skill virtual slot0xc8; zero → base MinCoolTime/+0xd0',
            'SkillLevel.ChangeMaxCoolTime/+0x64 → Skill virtual slot0xb8; zero → base MaxCoolTime/+0xcc'],
        limitations=['Raw table units; no automatic seconds conversion or runtime cooldown prediction.',
            'Other Change fields preserved as source records; their getter semantics are outside this report.',
            'No replacement rows in this installed client does not prove absence of server changes.'])
    path = native.ROOT/'code-clues/skill-level-code.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(profiles=len(profiles), anchors=len(anchors), atlas=result['atlas'],
        sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__ == '__main__':
    main()
