"""Standard-library validation of an immutable one-attempt creation package."""
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re

ROOT = Path('F:/PhoneExit Resources/Vampir')
WORKSPACE = Path(__file__).resolve().parents[3]
INSTALLED = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'bounded-creation-profile-v1'
FACTORY_RECIPE = 'viper-creation-current-v1'
POLICY = 'character-create-current-v1'
OPERATIONS = ['character-create']
SHA = re.compile('[0-9a-f]{64}')
CONSUMERS = (
    'vampir-headless/bounded-creation-profile.py',
    'vampir-shared/vampir_core/bounded_creation_admission.py',
    'vampir-shared/vampir_core/character_create.py',
    'vampir-shared/vampir_core/character_appearance.py',
    'vampir-shared/vampir_core/character_create_result.py',
    'vampir-shared/vampir_core/character_creation_flow.py',
    'vampir-shared/vampir_core/creation_journal.py',
    'vampir-shared/vampir_core/game_login_probe.py',
)


def digest(path, budget):
    if not 0 <= path.stat().st_size <= budget:
        raise ValueError('Bounded creation dependency exceeds its file budget')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _entry_loader(workspace):
    path = workspace / 'phone-exit/bots/vampir-headless/bounded-entry-profile.py'
    spec = importlib.util.spec_from_file_location('bounded_creation_entry_profile', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _json(path, expected, *, budget=2 * 1024 * 1024):
    if not SHA.fullmatch(str(expected)) or digest(path, budget) != expected:
        raise ValueError('Bounded creation retained manifest changed')
    return json.loads(path.read_bytes())


def _payload(value):
    if (not isinstance(value, dict) or set(value) != {'raw_class', 'appearance', 'appearance_text', 'raw_flags', 'items'}
            or type(value['raw_class']) is not int or value['raw_class'] != 1
            or type(value['appearance']) is not list or len(value['appearance']) != 10
            or any(type(number) is not int or not 0 <= number <= 255 for number in value['appearance'])
            or value['appearance'][0] != 1 or value['raw_flags'] != [0, 0] or value['items'] != []
            or not isinstance(value['appearance_text'], str) or len(value['appearance_text']) > 4096):
        raise ValueError('Bounded creation Viper payload template differs')
    try:
        numeric = json.loads(value['appearance_text'])
    except (ValueError, TypeError) as error:
        raise ValueError('Bounded creation appearance JSON differs') from error
    if (not isinstance(numeric, dict) or set(numeric) != {str(number) for number in range(1, 8)} | {'VoiceType'}
            or any(type(numeric[str(number)]) not in (int, float) or not math.isfinite(numeric[str(number)])
                   for number in range(1, 8))
            or type(numeric['VoiceType']) is not int or not 0 <= numeric['VoiceType'] <= 255):
        raise ValueError('Bounded creation appearance numbers differ')


def load_manifest(selector_sha, *, root=ROOT, workspace=WORKSPACE, installed=INSTALLED):
    root, workspace, installed = (Path(value).resolve() for value in (root, workspace, installed))
    if not isinstance(selector_sha, str) or not SHA.fullmatch(selector_sha):
        raise ValueError('Bounded creation requires a full manifest SHA')
    path = root / 'bounded-creation-profiles' / selector_sha / 'manifest.json'
    profile = _json(path, selector_sha)
    if (profile.get('schema') != 1 or profile.get('recipe') != RECIPE
            or profile.get('source_sha256') != SOURCE or profile.get('operations') != OPERATIONS
            or profile.get('policy') != POLICY or profile.get('world_admitted') is not False
            or profile.get('online_verified') is not False or profile.get('creation_admitted') is not True
            or not profile.get('limits')):
        raise ValueError('Bounded creation manifest scope differs')
    inputs = profile.get('inputs')
    if not isinstance(inputs, dict) or not 1 <= len(inputs) <= 2048:
        raise ValueError('Bounded creation dependency set differs')
    for relative in CONSUMERS:
        consumer = workspace / 'phone-exit/bots' / relative
        if inputs.get(str(consumer)) != digest(consumer, 32 * 1024 * 1024):
            raise ValueError('Bounded creation lost a runtime consumer')
    if inputs.get(str(installed)) != SOURCE:
        raise ValueError('Bounded creation lost its exact installed source')
    entry = profile.get('entry')
    factory = profile.get('factory')
    if (not isinstance(entry, dict) or set(entry) != {'path', 'sha256', 'selected_profile'}
            or not SHA.fullmatch(str(entry.get('sha256')))
            or entry['selected_profile'] != 'bounded-entry:' + entry['sha256']
            or Path(entry['path']).resolve() != root / 'bounded-entry-profiles' / entry['sha256'] / 'manifest.json'
            or not isinstance(factory, dict) or set(factory) != {'path', 'sha256'}
            or not SHA.fullmatch(str(factory.get('sha256')))
            or Path(factory['path']).resolve() != root / 'code-clues' / FACTORY_RECIPE / factory['sha256'] / 'manifest.json'):
        raise ValueError('Bounded creation proof pointers differ')
    for pointer in (entry, factory):
        if inputs.get(str(Path(pointer['path']).resolve())) != pointer['sha256']:
            raise ValueError('Bounded creation proof is not retained')
    loader = _entry_loader(workspace)
    extra_archives = {installed.parents[2] / 'Saved/PersistentDownloadDir/Patch/Install' /
        ('pakchunk' + number + '-Windows.pak') for number in ('1', '100')}
    for name, expected in inputs.items():
        dependency = Path(name).resolve()
        if not Path(name).is_absolute() or not SHA.fullmatch(str(expected)):
            raise ValueError('Bounded creation dependency descriptor differs')
        if dependency == Path(entry['path']).resolve():
            budget = 2 * 1024 * 1024
        elif dependency in extra_archives:
            budget = 128 * 1024 * 1024
        elif (dependency.parent == root / 'knowledge/resource-csv-blobs-v3'
                and dependency.suffix == '.csv' and SHA.fullmatch(dependency.stem)
                and dependency.stem == expected):
            budget = 32 * 1024 * 1024
        elif (dependency.parent == root / 'code-clues/appearance-resource-blobs'
                and dependency.suffix in ('.uasset', '.uexp') and SHA.fullmatch(dependency.stem)
                and dependency.stem == expected):
            budget = 32 * 1024 * 1024
        elif dependency.is_relative_to(root / 'release-snapshots') and dependency.name == 'manifest.json':
            budget = 32 * 1024 * 1024
        else:
            budget = loader.input_budget(dependency, root, workspace, installed)
        if digest(dependency, budget) != expected:
            raise ValueError('Bounded creation dependency changed: ' + dependency.name)
    parent = loader.load_manifest(entry['sha256'], root=root, workspace=workspace, installed=installed)
    factory_report = _json(Path(factory['path']), factory['sha256'], budget=32 * 1024 * 1024)
    if (parent['source_sha256'] != SOURCE or factory_report.get('source_sha256') != SOURCE
            or factory_report.get('recipe') != FACTORY_RECIPE or factory_report.get('runtime_admitted') is not False
            or factory_report.get('native_execution') is not False or factory_report.get('native_proofs_reused') is not True
            or factory_report.get('network_used') is not False or factory_report.get('model_only') is not True
            or factory_report.get('verified_loaded_asset') is not False or not factory_report.get('limits')):
        raise ValueError('Bounded creation factory scope differs')
    retained = {**parent['inputs'], **factory_report.get('definition', {}).get('inputs', {})}
    if not retained or any(inputs.get(name) != expected for name, expected in retained.items()):
        raise ValueError('Bounded creation lost a proof dependency')
    _payload(factory_report.get('payload_template'))
    return dict(profile, selected_profile='bounded-create:' + selector_sha,
        manifest_sha256=selector_sha, payload_template=factory_report['payload_template'])
