"""Resolve exact cooked SceneComponent template chains; do not fill native defaults."""
import hashlib, importlib.util, json, os
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main(root):
    def module(name, file):
        spec = importlib.util.spec_from_file_location(name, HERE / file)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    package = module('archetype_package', 'inspect-ui.py')
    refs = module('archetype_refs', 'decode-package-references.py')
    scene = module('archetype_scene', 'decode-lift-placements.py')
    bpdir = root / 'maps/navigation-study/lift-blueprints'
    leveldir = root / 'maps/navigation-study/level'
    bpindex = bpdir / 'index.json'
    bps = json.loads(bpindex.read_text('utf-8'))
    definitions = {}
    packages = []

    def checked(path, digest):
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Changed archetype source: ' + str(path))
        return raw

    for bp in bps['blueprints']:
        a, b = [checked(bpdir / p['file'], p['sha256']) for p in bp['parts']]
        parsed = package.exports(a, b)
        table = refs.references(a, parsed)
        packages.append(dict(package_name=table['package_name'], package_name_offset=36,
                             package_name_bytes=table['package_name_bytes'], parts=bp['parts']))
        for export in parsed['exports']:
            if export['type'] != 'SceneComponent':
                continue
            row = table['references'][export['index']]
            template = table['references'].get(row['template_index'])
            if not template:
                raise ValueError('Scene archetype has no template')
            raw = b[export['offset'] - len(a):export['offset'] - len(a) + export['size']]
            decoded = scene.decode(raw)
            # An unknown field must not silently erase an attachment override.
            if decoded['properties'] or decoded['unknown_fields']:
                raise ValueError('Scene template now has explicit/unknown properties')
            if row['path'] in definitions:
                raise ValueError('Duplicate archetype path')
            definitions[row['path']] = dict(export=export, reference=row, template=template, decoded=decoded)
    levelpath = leveldir / 'index.json'
    level = json.loads(levelpath.read_text('utf-8'))
    parts = {p['role']: checked(leveldir / p['file'], p['sha256']) for p in level['parts']}
    parsed = package.exports(parts['asset'], parts['body'], max_exports=40000)
    table = refs.references(parts['asset'], parsed)
    placement_path = leveldir / 'lift-placements.json'
    placements = json.loads(placement_path.read_text('utf-8'))
    rows = []
    terminals = {'/Script/NnFramework.Default__NnLift.Scene', '/Script/Engine.Default__SceneComponent'}
    for lift in placements['lifts']:
        export = lift['scene_component']['export']
        checked(leveldir / lift['scene_component']['file'], export['sha256'])
        row = table['references'][export['index']]
        target = table['references'].get(row['template_index'])
        if not target:
            raise ValueError('Instance Scene has no template')
        chain = []
        path = target['path']
        seen = set()
        while path not in terminals:
            if path in seen or path not in definitions:
                raise ValueError('Cyclic/unresolved Scene archetype: ' + path)
            seen.add(path)
            definition = definitions[path]
            chain.append(path)
            path = definition['template']['path']
        rows.append(dict(parent=lift['parent'], scene_component=lift['scene_component'], reference=row,
                         template_reference=target, blueprint_template_chain=chain, native_terminal=path,
                         blueprint_chain_resolved=True, native_effective_defaults_resolved=False,
                         world_transform_verified=False, runtime_attachment_verified=False))
    report = dict(blueprint_index_sha256=hashlib.sha256(bpindex.read_bytes()).hexdigest(),
                  level_index_sha256=hashlib.sha256(levelpath.read_bytes()).hexdigest(),
                  placements_sha256=hashlib.sha256(placement_path.read_bytes()).hexdigest(),
                  packages=packages, scene_templates=definitions, instances=rows,
                  format_reference='https://dev.epicgames.com/documentation/unreal-engine/API/Runtime/CoreUObject/FObjectExport',
                  summary=dict(instances=len(rows), resolved_blueprint_chains=len(rows), scene_templates=len(definitions),
                               native_terminals=sorted({r['native_terminal'] for r in rows}), world_transforms_verified=0),
                  limitations=['TemplateIndex at +8 uses the validated legacy 96-byte export layout; the format definition is supported by Epic documentation, not native serialization tracing.',
                               'Package names and outer chains identify targets; parent class name is not used as an archetype join.',
                               'Blueprint Scene templates contain no explicit property overrides; native CDO/post-construction defaults still require verification.',
                               'No defaults applied to instance omissions; runtime attachment, movement, world endpoints and route walkability remain unresolved.'])
    path = bpdir / 'archetypes.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(summary=report['summary'], sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report


if __name__ == '__main__':
    main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir')))
