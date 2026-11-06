"""Compile an explicit Viper creation template from current retained proofs."""
import argparse
import copy
import csv
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import io
import json
import math
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
INSTALLED = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'viper-creation-current-v1'
CLASS_BASELINE = '43204e85a3d2c4f5bb11581264688ca7f1b1502206f59d36f70fd1145a55cc2d'
CLASS_CSV = '620725b3322e37b612107286ca60d72908cccfdb32449b6a2e135e4ad3c4c8bc'
CLASS_ARCHIVE = '2f2517ff83865ac13021f96d9babd8407e4fbee512ff29806106844e5d7d7ed3'
FIELDS = ('HairIndex', 'HairColorIndex', 'HeadIndex', 'SkinColorIndex',
          'EyeColorLeftIndex', 'EyeColorRightIndex', 'EyeTexIndex', 'DecalIndex', 'DecalColorIndex')
GROUP_FIELDS = ('Height', 'Chest', 'Pelvis', 'Shape', 'Waist', 'Thigh', 'Head')
GROUP_IDS = dict(zip(GROUP_FIELDS, range(1, 8)))
PARENT_TOOLS = {
    'create-producer-current': 'verify-create-producer-current',
    'create-packets-current': 'verify-create-packets-current',
    'create-result-current': 'verify-create-result-current',
    'create-handler-current': 'verify-create-handler-current',
    'viper-appearance-current': 'build-viper-appearance-current',
}


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
        raise ValueError('Current Viper creation ' + detail)


def retain(inputs, path, expected=None):
    path = Path(path).resolve()
    actual = digest(path)
    require(expected is None or actual == expected, 'retained input changed: ' + path.name)
    require(str(path) not in inputs or inputs[str(path)] == actual, 'conflicting retained input')
    inputs[str(path)] = actual
    return path


def parent_proofs(root, inputs):
    proofs, pointers = {}, {}
    for name, tool_name in PARENT_TOOLS.items():
        tool = load(tool_name)
        if name == 'create-packets-current':
            path, proof, _ = tool.run(root=root)
            result = dict(report=str(path), sha256=digest(path))
        else:
            result = tool.verify(root=root)
            path = Path(result['report']).resolve()
            proof = json.loads(path.read_bytes())
        path = Path(result['report']).resolve()
        require(path == root / 'code-clues' / (name + '-v1') / result['sha256'] / 'manifest.json',
                'parent proof path differs: ' + name)
        retain(inputs, path, result['sha256'])
        require(proof.get('source_sha256') == SOURCE and proof.get('network_used') is False
                and proof.get('runtime_admitted') is False and proof.get('limits'),
                'parent boundary differs: ' + name)
        for dependency, sha in proof['definition']['inputs'].items():
            retain(inputs, dependency, sha)
        proofs[name] = proof
        pointers[name] = dict(path=str(path), sha256=result['sha256'])
    selector_path = HERE / 'knowledge/entry-native-current.json'
    selector = json.loads(retain(inputs, selector_path).read_bytes())
    require(selector.get('source_sha256') == SOURCE, 'class proof selector source differs')
    pointer = selector['proofs']['viper-class-current']
    path = Path(pointer['path']).resolve()
    require(path == root / 'code-clues/viper-class-current-v1' / pointer['sha256'] / 'manifest.json',
            'class proof path differs')
    proof = json.loads(retain(inputs, path, pointer['sha256']).read_bytes())
    require(proof.get('source_sha256') == SOURCE and proof.get('native_execution') is True
            and proof.get('network_used') is False and proof.get('runtime_admitted') is False
            and [len(proof.get(key, [])) for key in ('lookup_cases', 'selection_cases', 'type_cases')] == [27, 16, 6]
            and proof.get('loaded_class_table_verified') is False
            and proof.get('complete_viper_payload_verified') is False,
            'retained class proof boundary differs')
    for dependency, sha in proof['inputs'].items():
        retain(inputs, dependency, sha)
    proofs['viper-class-current'] = proof
    pointers['viper-class-current'] = pointer
    return proofs, pointers


def class_row(root, inputs):
    path = root / 'knowledge/resource-named-baselines-v1' / CLASS_BASELINE / 'manifest.json'
    baseline = json.loads(retain(inputs, path, CLASS_BASELINE).read_bytes())
    require(baseline.get('source', {}).get('sha256') == CLASS_ARCHIVE,
            'Class resource archive differs')
    retain(inputs, baseline['source']['archive_key'], CLASS_ARCHIVE)
    tables = [row for row in baseline['tables'] if row.get('canonical_path') == 'ProjectRED/Content/RED/Data/CSV/Class.csv']
    require(len(tables) == 1 and tables[0].get('state') == 'verified_payload'
            and tables[0].get('sha256') == CLASS_CSV and tables[0].get('rows') == 5,
            'Class resource table differs')
    blob = root / 'knowledge/resource-csv-blobs-v3' / (CLASS_CSV + '.csv')
    require(Path(tables[0]['file']).resolve() == blob, 'Class CSV path differs')
    payload = retain(inputs, blob, CLASS_CSV).read_text(encoding='utf-8-sig')
    reader = csv.DictReader(io.StringIO(payload, newline=''))
    require(reader.fieldnames == tables[0]['header'], 'Class CSV header differs')
    rows = list(reader)
    selected = [row for row in rows if row['Resource'] == 'DarkMage' and row['Type'] == '1']
    require(len(rows) == 5 and len(selected) == 1
            and tuple(selected[0][name] for name in ('Id', 'DefaultGender', 'LobbyCharacterPresetId')) == ('1', '1', '1'),
            'DarkMage class row is absent or ambiguous')
    row = selected[0]
    return dict(resource=row['Resource'], row_id=int(row['Id']), class_type=int(row['Type']),
                gender_byte=int(row['DefaultGender']), preset_id=int(row['LobbyCharacterPresetId']), asset_suffix='F')


def finite_float32(value):
    require(type(value) in (int, float), 'appearance setting is not numeric')
    try:
        number = struct.unpack('<f', struct.pack('<f', value))[0]
    except (OverflowError, struct.error):
        raise ValueError('Current Viper creation appearance exceeds float32') from None
    require(math.isfinite(number), 'appearance setting is not finite')
    return number


def payload_template(selection, appearance):
    values = appearance['candidate']['values']
    integers = [values[name] for name in FIELDS]
    require(all(type(value) is int and 0 <= value <= 255 for value in integers),
            'appearance integer exceeds wire byte')
    require(type(values['VoiceType']) is int and 0 <= values['VoiceType'] <= 255,
            'voice type exceeds wire byte')
    # The native asset property is named Cheat. The UI/rules group is Chest.
    settings = {name: finite_float32(values['Cheat' if name == 'Chest' else name]) for name in GROUP_FIELDS}
    json_values = {str(GROUP_IDS[name]): settings[name] for name in GROUP_FIELDS}
    json_values['VoiceType'] = values['VoiceType']
    return dict(raw_class=selection['row_id'], appearance=[selection['gender_byte'], *integers],
                appearance_text=json.dumps(json_values, ensure_ascii=True, allow_nan=False, separators=(',', ':')),
                raw_flags=[0, 0], items=[])


def definition(*, root=ROOT, installed=INSTALLED):
    root, installed = Path(root).resolve(), Path(installed).resolve()
    inputs = {}
    retain(inputs, installed, SOURCE)
    for name in ('build-viper-creation-current.py', 'audit-client-release.py', 'research-workflow.py'):
        retain(inputs, HERE / name)
    proofs, pointers = parent_proofs(root, inputs)
    selection = class_row(root, inputs)
    producer = proofs['create-producer-current']
    require(producer.get('method') == 'source_transfer' and producer.get('native_proofs_reused') is True
            and producer.get('core_roots') == 15 and producer.get('core_relocations') == 82
            and producer.get('inherited_cases') == dict(producer=37, json=36, class_source=144),
            'producer source transfer differs')
    require(proofs['create-packets-current'].get('native_execution') is True
            and proofs['create-result-current'].get('native_execution') is True
            and proofs['create-handler-current'].get('native_execution') is True,
            'current packet/result proofs are incomplete')
    model = proofs['viper-appearance-current']
    require(model.get('model_only') is True and model.get('verified_loaded_asset') is False
            and model.get('native_proofs_reused') is True and model.get('native_execution') is False,
            'appearance model boundary differs')
    appearance = copy.deepcopy(model['appearances'][selection['asset_suffix']])
    require(appearance['class_type'] == selection['class_type'] and appearance['preset_id'] == selection['preset_id']
            and appearance['candidate'].get('model_only') is True
            and appearance['candidate'].get('verified_loaded_asset') is False
            and appearance['candidate'].get('runtime_admitted') is False,
            'appearance selection differs')
    template = payload_template(selection, appearance)
    selected = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, source=str(installed),
                    inputs=inputs, parents=pointers, selection=selection,
                    appearance_candidate=appearance, payload_template=template)
    barrier(selected)
    return selected


def barrier(selected):
    for path, expected in selected['inputs'].items():
        require(digest(path) == expected, 'retained input changed: ' + Path(path).name)


def build(selected):
    return dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, source=selected['source'],
        definition=selected, inputs=selected['inputs'], parents=selected['parents'],
        selection=selected['selection'], appearance_candidate=selected['appearance_candidate'],
        payload_template=selected['payload_template'], nickname_policy='required_runtime_parameter',
        model_only=True, verified_loaded_asset=False, runtime_admitted=False, native_execution=False,
        native_proofs_reused=True, network_used=False, live_verified=False,
        limits=['Explicit DarkMage/Viper row 1 and female-suffix candidate, using current DefaultGender byte 1 as local choice.',
                'Serialized values, unresolved native defaults and chosen model values retain their separate provenance.',
                'Numeric JSON uses explicit Latin group IDs and finite float32 values. Native JSON byte formatting is not claimed.',
                'Nickname is supplied later. This immutable template grants no send, account mutation, creation retry or runtime admission.',
                'Loaded engine preset, later overrides, screen appearance and live server acceptance remain unverified.'])


def validate(report, selected):
    require(report.get('schema') == 1 and report.get('recipe') == RECIPE
            and report.get('source_sha256') == SOURCE and report.get('source') == selected['source']
            and report.get('definition') == selected and report.get('inputs') == selected['inputs']
            and report.get('parents') == selected['parents'] and report.get('selection') == selected['selection']
            and report.get('appearance_candidate') == selected['appearance_candidate']
            and report.get('payload_template') == selected['payload_template']
            and report.get('nickname_policy') == 'required_runtime_parameter'
            and report.get('model_only') is True and report.get('native_proofs_reused') is True
            and all(report.get(key) is False for key in
                    ('verified_loaded_asset', 'runtime_admitted', 'native_execution', 'network_used', 'live_verified'))
            and report.get('limits'), 'receipt scope differs')


def verify(*, root=ROOT, installed=INSTALLED):
    root = Path(root).resolve()
    selected = definition(root=root, installed=installed)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    if cache.is_file():
        pointer = json.loads(cache.read_bytes())
        path = Path(pointer['path']).resolve()
        require(path == root / 'code-clues' / RECIPE / pointer['sha256'] / 'manifest.json'
                and digest(path) == pointer['sha256'], 'cache pointer differs')
        validate(json.loads(path.read_bytes()), selected)
        barrier(selected)
        return dict(report=str(path), sha256=pointer['sha256'], reused=True)
    report = build(selected)
    validate(report, selected)
    barrier(selected)
    path = load('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    pointer = dict(path=str(path), sha256=digest(path))
    workflow.atomic(cache, workflow.canonical(pointer))
    barrier(selected)
    return dict(report=str(path), sha256=pointer['sha256'], reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(root=args.root)))
