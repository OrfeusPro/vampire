"""Publish conditional lift geometry with explicit and sourced native initial values."""
import hashlib, importlib.util, json, os
from pathlib import Path

HERE = Path(__file__).resolve().parent


def calculate(placement, point_links, model, initial=None):
    placement = dict(placement)
    initial_fields = {}
    if initial:
        if 'RelativeScale3D' not in placement and 'scene_scale_initial' in initial:
            placement['RelativeScale3D'] = initial['scene_scale_initial']
            initial_fields['RelativeScale3D'] = initial['scene_scale_initial']
        if point_links is None and 'native_point_links_initial' in initial:
            point_links = initial['native_point_links_initial']
            initial_fields['PointLinks'] = initial['native_point_links_initial']
    required = ['RelativeLocation', 'RelativeRotation', 'RelativeScale3D']
    missing = [name for name in required if name not in placement]
    if point_links is None:
        missing.append('PointLinks')
    result = []
    if not missing:
        q = model.rotator_to_quaternion(placement['RelativeRotation'])
        for index, link in enumerate(point_links):
            p = link['properties']
            if not all(name in p for name in ['Left', 'Right']):
                missing.append('PointLinks endpoints')
                continue
            result.append(dict(index=index, left=model.transform_point(p['Left'], placement['RelativeLocation'], q, placement['RelativeScale3D']),
                               right=model.transform_point(p['Right'], placement['RelativeLocation'], q, placement['RelativeScale3D']),
                               direction=p.get('Direction'), world_coordinates_verified=False, walkable=None))
    return dict(missing=missing, initial_fields=initial_fields, calculated_links=result, world_transform_verified=False, runtime_walkability_verified=False)


def main(root):
    def module(name, file):
        s = importlib.util.spec_from_file_location(name, HERE / file)
        m = importlib.util.module_from_spec(s)
        s.loader.exec_module(m)
        return m
    model = module('lift_preview_math', 'lift-transform-math.py')
    decoder = module('lift_preview_placement', 'decode-lift-placements.py')
    link_decoder = module('lift_preview_links', 'decode-navigation-point-links.py')
    folder = root / 'maps/navigation-study'
    sources = {}
    def read(name, relative):
        path = folder / relative
        raw = path.read_bytes()
        sources[name] = dict(file='../navigation-study/' + relative, sha256=hashlib.sha256(raw).hexdigest())
        return json.loads(raw)
    placements = read('placements', 'level/lift-placements.json')
    links = read('point_links', 'lift-blueprints/point-links.json')
    archetypes = read('archetypes', 'lift-blueprints/archetypes.json')
    rotation = read('rotation_evidence', 'lift-blueprints/rotation-evidence.json')
    settings = read('instance_settings', 'lift-blueprints/instance-settings.json')
    initial = read('initial_values', 'lift-blueprints/initial-values.json') if (folder / 'lift-blueprints/initial-values.json').is_file() else None
    if initial:
        for key, expected in [('archetypes_sha256', sources['archetypes']['sha256']), ('settings_sha256', sources['instance_settings']['sha256'])]:
            if initial[key] != expected:
                raise ValueError('Rebuild initial values for changed source')
        if initial['scene_defaults_sha256'] != hashlib.sha256((folder / 'lift-blueprints/scene-native-defaults.json').read_bytes()).hexdigest():
            raise ValueError('Changed native Scene defaults')
    source = rotation['source']
    if hashlib.sha256(Path(source['source']).read_bytes()).hexdigest() != source['sha256']:
        raise ValueError('Changed client EXE')
    if rotation['model_sha256'] != hashlib.sha256((HERE / 'lift-transform-math.py').read_bytes()).hexdigest():
        raise ValueError('Rebuild rotation evidence for changed model')
    if links['instance_settings_sha256'] != hashlib.sha256((folder / 'lift-blueprints/instance-settings.json').read_bytes()).hexdigest():
        raise ValueError('Changed instance-settings source')
    if archetypes['placements_sha256'] != sources['placements']['sha256'] or rotation['placements_sha256'] != sources['placements']['sha256']:
        raise ValueError('Different placement snapshots')
    by_link = {r['parent']['export']['index']: r for r in links['instances']}
    by_archetype = {r['parent']['export']['index']: r for r in archetypes['instances']}
    by_settings = {r['parent']['export']['index']: r for r in settings['instances']}
    expected = {r['parent']['export']['index'] for r in placements['lifts']}
    if expected != set(by_link) or expected != set(by_archetype):
        raise ValueError('Different lift inventories')
    rows = []
    for lift in placements['lifts']:
        parent, component = lift['parent'], lift['scene_component']
        index = parent['export']['index']
        for spec in [parent, component]:
            raw = (folder / 'level' / spec['file']).read_bytes()
            if hashlib.sha256(raw).hexdigest() != spec['export']['sha256']:
                raise ValueError('Changed lift export')
        raw = (folder / 'level' / component['file']).read_bytes()
        p = decoder.decode(raw)
        if p['properties'] != lift['placement']['properties'] or p['unknown_fields']:
            raise ValueError('Changed/unknown scene placement')
        linked = by_link[index]
        setting = by_settings[index]
        serialized_links = None
        field_index = setting['blueprint_prefix_property_count'] + 6
        for field, zero in setting['field_indices']:
            if field == field_index:
                reader = link_decoder.canvas.Reader((folder / 'level' / parent['file']).read_bytes())
                reader.pos = setting['decoded_prefix_bytes']
                serialized_links = link_decoder.array(reader, zero)
        if json.loads(json.dumps(serialized_links)) != linked['point_links']:
            raise ValueError('PointLinks report differs from component bytes')
        if not linked['root_reference_verified'] or linked['actor_root_component'] != component['export']['index']:
            raise ValueError('Lift root mismatch')
        applicable_initial = initial if by_archetype[index]['native_terminal'] == '/Script/NnFramework.Default__NnLift.Scene' else None
        calculation = calculate(p['properties'], linked['point_links'], model, applicable_initial)
        rows.append(dict(id=str(index), name=parent['export']['name'], class_name=parent['export']['type'],
                         label='Лифт #' + str(index), placement=p['properties'], **calculation,
                         parent_source=parent, component_source=component, archetype=by_archetype[index]['template_reference']['path'],
                         assumption='Расчёт предполагает отсутствие привязки к другому объекту, смещения уровня и изменений после загрузки. Это ещё не подтверждено для игрового состояния.'))
    report = dict(schema_version=1, kind='conditional_lift_preview', sources=sources, lifts=rows,
                  summary=dict(lifts=len(rows), calculated_lifts=sum(bool(r['calculated_links']) for r in rows),
                               fully_explicit_lifts=sum(bool(r['calculated_links']) and not r['initial_fields'] for r in rows),
                               inherited_initial_lifts=sum(bool(r['calculated_links']) and bool(r['initial_fields']) for r in rows),
                               inherited_initial_scales=sum('RelativeScale3D' in r['initial_fields'] for r in rows),
                               inherited_initial_point_links=sum('PointLinks' in r['initial_fields'] for r in rows),
                               calculated_links=sum(len(r['calculated_links']) for r in rows), verified_routes=0),
                  limitations=['Explicit values take priority. Missing scale/PointLinks may use verified native initial settings after checked Blueprint chains, separately recorded in initial_fields. Missing rotation is not filled.',
                               'Coordinates are conditional calculations under an unparented, unshifted root assumption; map frame/runtime state remain unverified.',
                               'No World.Id is assigned by nearest point; preview is level-wide and separate from the navigation graph.'])
    out = root / 'maps/atlas/lift-preview.json'
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    return dict(file=out.name, sha256=hashlib.sha256(out.read_bytes()).hexdigest(), summary=report['summary'])


if __name__ == '__main__':
    print(json.dumps(main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir')))))
