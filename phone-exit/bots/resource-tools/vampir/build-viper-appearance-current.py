"""Choose explicit Viper appearances with current native-model provenance."""
import argparse
import copy
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/viper-appearance-current.json'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'viper-appearance-current-v1'


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(condition, detail):
    if not condition:
        raise ValueError('Current Viper appearance ' + detail)


def retain(inputs, path, expected=None):
    path = Path(path).resolve()
    actual = digest(path)
    require(expected is None or actual == expected, 'retained input changed: ' + path.name)
    if str(path) in inputs:
        require(inputs[str(path)] == actual, 'conflicting retained input')
    inputs[str(path)] = actual
    return path


def snapshot(inputs, root, pointer, category):
    path = Path(pointer['path']).resolve()
    require(path == root / 'code-clues' / category / pointer['sha256'] / 'manifest.json',
            'immutable proof path differs')
    return json.loads(retain(inputs, path, pointer['sha256']).read_bytes())


def definition(context_path, root):
    inputs = {}
    context_path = retain(inputs, context_path)
    context = json.loads(context_path.read_bytes())
    require((context.get('schema'), context.get('recipe'), context.get('source_sha256'),
             context.get('class_type'), context.get('preset_id'), context.get('model_only'),
             context.get('verified_loaded_asset'), context.get('runtime_admitted'))
            == (1, RECIPE, SOURCE, 1, 1, True, False, False), 'context differs')
    resource = snapshot(inputs, root, context['resource_report'], 'release-creation-presets')
    cold = snapshot(inputs, root, context['cold_cdo_report'], 'viper-cold-cdo-current-v1')
    cold_tool = load('verify-viper-cold-cdo-current')
    cold_definition = cold_tool.definition(cold_tool.CONTEXT, root)
    cold_tool.validate(cold, cold_definition)
    for path, sha in cold_definition['inputs'].items():
        retain(inputs, path, sha)
    require(resource.get('resource_only') is True and resource.get('runtime_admitted') is False
            and resource.get('selection') == dict(class_type=1, gender=None, preset_id=1),
            'resource proof scope differs')
    require(resource['source']['sha256'] == '58eb7e06e05d1dae843d4f7c2e0021b311ffcaff3f26da9dd5b80783c6258ac3',
            'resource archive differs')
    retain(inputs, resource['source']['path'], resource['source']['sha256'])
    for name in ('record_index', 'directory_manifest'):
        retain(inputs, resource[name], resource[name + '_sha256'])
    for name in ('extract-release-creation-presets.py', 'decode-canvas-slots.py',
                 'inspect-ui.py', 'decode-package-references.py'):
        path = (HERE / name).resolve()
        require(str(path) in resource['dependencies'], 'resource parser provenance missing')
        retain(inputs, path, resource['dependencies'][str(path)])
    for name in ('build-viper-appearance-current.py', 'verify-viper-cold-cdo-current.py',
                 'audit-client-release.py', 'research-workflow.py'):
        retain(inputs, HERE / name)
    schema_path = HERE / 'knowledge/native-contexts/preset-defaults-11322.json'
    schema = json.loads(retain(inputs, schema_path).read_bytes())
    current = [row for row in schema['descriptors'] if row['name'] != 'UnderlyingType']
    previous = [row for row in resource['schema']['asset'] if row['name'] != 'UnderlyingType']
    require([(row['name'], row['flags'], row['offset']) for row in current]
            == [(row['name'], row['flags'], row['offset']) for row in previous]
            and len(current) == 17, 'serialized field schema differs from current descriptors')
    for package in resource['packages']:
        for part in package['parts']:
            require(part['blob'] == part['sha256'] + Path(part['filename']).suffix,
                    'blob name differs')
            retain(inputs, root / 'code-clues/appearance-resource-blobs' / part['blob'], part['sha256'])
    vectors = {case['default_bytes'] for case in cold['native_cases']}
    require(len(vectors) == 1, 'cold default vector is ambiguous')
    vector = bytes.fromhex(vectors.pop())
    require(len(vector) == 65, 'cold default vector size differs')
    defaults = {row['name']: struct.unpack_from('<i' if index < 9 else '<f' if index < 16 else '<B',
                                              vector, row['offset'] - 0x30)[0]
                for index, row in enumerate(current)}
    packages = {row['package']: row for row in resource['packages']}
    expected = {}
    for link in resource['selected_presets']:
        suffix = link['table'][-1]
        require(suffix in ('F', 'M') and suffix not in expected, 'expected gender suffix differs')
        decoded = packages[link['package']]['decoded']
        expected[suffix] = dict(package=link['package'], class_type=link['class_type'],
                               preset_id=link['preset_id'], decoded=decoded, candidate=project(decoded, defaults))
    selected = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, inputs=inputs,
                    defaults=defaults, expected_appearances=expected)
    return context, resource, defaults, selected


def barrier(selected):
    for path, sha in selected['inputs'].items():
        require(digest(path) == sha, 'retained input changed: ' + Path(path).name)


def project(decoded, defaults):
    require(set(decoded['values']) == set(defaults) == set(decoded['origins']), 'field set differs')
    inferred = sorted(name for name in defaults if decoded['values'][name] is None)
    require(set(inferred) == set(decoded['unresolved']), 'unresolved field list differs')
    values = copy.deepcopy(decoded['values'])
    origins = copy.deepcopy(decoded['origins'])
    for name in inferred:
        values[name] = defaults[name]
        origins[name] = 'explicit_choice_from_current_cold_cdo_model'
    require(all(value is not None for value in values.values()), 'candidate remains incomplete')
    return dict(values=values, origins=origins, inferred_fields=inferred, model_only=True,
                verified_loaded_asset=False, runtime_admitted=False)


def build(context, resource, defaults, root):
    parser = load('extract-release-creation-presets')
    package_parser = load('inspect-ui')
    refs_parser = load('decode-package-references')
    parsed_packages = []
    decoded_by_package = {}
    for package in resource['packages']:
        parts = [(root / 'code-clues/appearance-resource-blobs' / part['blob']).read_bytes()
                 for part in package['parts']]
        parsed = package_parser.exports(*parts)
        refs = refs_parser.references(parts[0], parsed)
        refs['references'] = {str(key): value for key, value in refs['references'].items()}
        require(refs == package['references'] and refs['package_name'] == package['package'],
                'package references differ')
        require(len(parsed['exports']) == 1 and parsed['exports'][0] == package['export'],
                'package export differs')
        export = parsed['exports'][0]
        start = export['offset'] - len(parts[0])
        body = parts[1][start:start + export['size']]
        require(start >= 0 and len(body) == export['size']
                and hashlib.sha256(body).hexdigest() == export['sha256'], 'package body differs')
        if package['package'] in parser.TABLES:
            structures = [row for row in refs['references'].values()
                          if row['name'] == 'RdDataTableRowForCustomizePreset']
            require(len(structures) == 1 and export['type'] == 'DataTable', 'preset row type differs')
            rows = parser.table(body, parsed['names'], refs['references'], structures[0]['index'])
            require(rows == package['rows'], 'preset table rows differ')
            parsed_packages.append(dict(package=package['package'], rows=rows))
        else:
            require(export['type'] == 'NnDataAssetForCustomizePreset'
                    and parser.native_template(refs, export) == package['native_template'],
                    'native class/CDO import differs')
            decoded = parser.asset(body, use_constructor_defaults=False)
            require(decoded == package['decoded'], 'serialized properties differ')
            decoded_by_package[package['package']] = decoded
    links = parser.select_presets(parsed_packages, class_type=context['class_type'],
                                  preset_id=context['preset_id'])
    require(links == resource['selected_presets'] and len(links) == 2
            and {row['package'] for row in links} == set(decoded_by_package),
            'selected asset links differ')
    appearances = {}
    for link in links:
        suffix = link['table'][-1]
        require(suffix in ('F', 'M') and suffix not in appearances, 'gender suffix is ambiguous')
        appearances[suffix] = dict(package=link['package'], class_type=link['class_type'],
                                  preset_id=link['preset_id'],
                                  decoded=decoded_by_package[link['package']],
                                  candidate=project(decoded_by_package[link['package']], defaults))
    return appearances


def validate(report, selected):
    require(report.get('definition') == selected and report.get('recipe') == RECIPE
            and report.get('source_sha256') == SOURCE and report.get('model_only') is True
            and report.get('verified_loaded_asset') is False and report.get('native_execution') is False
            and report.get('native_proofs_reused') is True and report.get('network_used') is False
            and report.get('runtime_admitted') is False and set(report.get('appearances', {})) == {'F', 'M'}
            and report.get('defaults') == selected['defaults']
            and report.get('appearances') == selected['expected_appearances']
            and report.get('limits'), 'report scope differs')
    for row in report['appearances'].values():
        require(row['class_type'] == row['preset_id'] == 1
                and row['candidate'] == project(row['decoded'], report['defaults']),
                'candidate projection differs')


def verify(context_path=CONTEXT, *, root=ROOT):
    root = Path(root).resolve()
    context, resource, defaults, selected = definition(context_path, root)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge/viper-appearance-current-cache' / (key + '.json')
    if cache.is_file():
        pointer = json.loads(cache.read_bytes())
        path = Path(pointer['path']).resolve()
        require(path == root / 'code-clues' / RECIPE / pointer['sha256'] / 'manifest.json'
                and digest(path) == pointer['sha256'], 'cache pointer differs')
        validate(json.loads(path.read_bytes()), selected)
        barrier(selected)
        return dict(report=str(path), sha256=pointer['sha256'], reused=True)
    appearances = build(context, resource, defaults, root)
    barrier(selected)
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=selected,
        defaults=defaults, appearances=appearances, model_only=True, verified_loaded_asset=False,
        native_execution=False, native_proofs_reused=True, network_used=False, runtime_admitted=False,
        limits=['Explicit appearance choice for an unspecified appearance request, using exact F/M resource links.',
                'Serialized values and origins remain intact. Omitted fields are chosen from the current bounded cold-CDO model.',
                'The package does not claim actual loaded-screen appearance, completed engine callbacks, tag/gender byte mapping, producer or wire admission.'])
    validate(report, selected)
    path = load('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    pointer = dict(path=str(path), sha256=digest(path))
    workflow.atomic(cache, workflow.canonical(pointer))
    return dict(report=str(path), sha256=pointer['sha256'], reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    args = parser.parse_args()
    print(json.dumps(verify(args.context, root=args.root)))
