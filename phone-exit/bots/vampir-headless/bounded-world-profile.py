"""Standard-library validation of one immutable bounded world package."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path('F:/PhoneExit Resources/Vampir')
WORKSPACE = Path(__file__).resolve().parents[3]
INSTALLED = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'bounded-world-profile-v1'
POLICIES = ['game-login-world-v1', 'world-selection-move-v1', 'periodic-ping-v1', 'initial-character-stats-v1', 'character-stat-notifications-v1', 'quest-observation-v1']
OPERATIONS = ['character-select', 'world-entry', 'keep-online']
PROOFS = {'clock-world-current', 'world-results-current', 'initial-stats-current', 'stat-notifications-current', 'quest-observation-current'}
SHA = re.compile('[0-9a-f]{64}')
CONSUMERS = (
    'vampir-headless/bounded-world-profile.py',
    'vampir-headless/bounded-entry-profile.py',
    'vampir-headless/run-bounded-entry.py',
    'vampir-headless/run-bounded-world.py',
    'vampir-headless/game-source-profile.py',
    'vampir-headless/probe-selected-game-login.py',
    'vampir-headless/probe-lobby-sdk-login.py',
    'vampir-shared/vampir_core/bounded_world_admission.py',
    'vampir-shared/vampir_core/bounded_entry_admission.py',
    'vampir-shared/vampir_core/runtime_admission.py',
    'vampir-shared/vampir_core/character_select.py',
    'vampir-shared/vampir_core/character_select_result.py',
    'vampir-shared/vampir_core/selection_flow.py',
    'vampir-shared/vampir_core/world_entry_flow.py',
    'vampir-shared/vampir_core/world_move_start.py',
    'vampir-shared/vampir_core/world_move_start_result.py',
    'vampir-shared/vampir_core/world_move_finish_result.py',
    'vampir-shared/vampir_core/world_reserve_context.py',
    'vampir-shared/vampir_core/session_clock.py',
    'vampir-shared/vampir_core/heartbeat.py',
    'vampir-shared/vampir_core/ping.py',
    'vampir-shared/vampir_core/game_login_probe.py',
    'vampir-shared/vampir_core/game_connection.py',
    'vampir-shared/vampir_core/live_session.py',
    'vampir-shared/vampir_core/stat_change.py',
    'vampir-shared/vampir_core/quest_sync.py',
    'vampir-shared/vampir_core/quest_record.py',
    'vampir-shared/vampir_core/tutorial_update.py',
    'vampir-shared/vampir_core/quest_automation.py',
    'vampir-shared/vampir_core/action_queue.py',
    'vampir-shared/vampir_core/live_session_server.py',
    'vampir-shared/vampir_core/detached_worker.py',
    'vampir-shared/vampir_core/scheduled_worker.py',
    'vampir-shared/vampir_core/receive_stream.py',
    'vampir-shared/vampir_core/send_frame.py',
    'vampir-shared/vampir_core/outbound.py',
    'vampir-shared/vampir_core/socket_send.py',
)


def digest(path, budget):
    path = Path(path)
    if not 0 <= path.stat().st_size <= budget:
        raise ValueError('Bounded world dependency exceeds its file budget')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _json(path, expected, *, budget=2 * 1024 * 1024):
    if not SHA.fullmatch(str(expected)) or digest(path, budget) != expected:
        raise ValueError('Bounded world retained manifest changed')
    return json.loads(path.read_bytes())


def _entry_loader(workspace):
    path = workspace / 'phone-exit/bots/vampir-headless/bounded-entry-profile.py'
    spec = importlib.util.spec_from_file_location('bounded_world_entry_profile', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pointer(value, directory, inputs):
    if (not isinstance(value, dict) or set(value) != {'path', 'sha256'}
            or not SHA.fullmatch(str(value.get('sha256')))):
        raise ValueError('Bounded world proof pointer differs')
    path = directory / value['sha256'] / 'manifest.json'
    if Path(value['path']).resolve() != path or inputs.get(str(path)) != value['sha256']:
        raise ValueError('Bounded world proof is not retained')
    return _json(path, value['sha256'], budget=32 * 1024 * 1024)


def _retained(inputs, required):
    if not isinstance(required, dict) or not required or any(inputs.get(name) != sha for name, sha in required.items()):
        raise ValueError('Bounded world lost a proof dependency')


def _clock_world(proof, root, inputs):
    if (proof.get('schema') != 1 or proof.get('recipe') != 'clock-world-current-v1'
            or proof.get('source_sha256') != SOURCE or proof.get('method') != 'bounded_native'
            or proof.get('native_execution') is not True or proof.get('network_used') is not False
            or proof.get('runtime_admitted') is not False or proof.get('profile_activated') is not False
            or proof.get('cases') != 297 or proof.get('short_prefixes') != 12 or not proof.get('limits')
            or set(proof.get('components', {})) != {'clock', 'producer', 'world', 'result'}):
        raise ValueError('Bounded world Clock/Ping proof scope differs')
    definition = proof.get('definition', {})
    if definition.get('source_sha256') != SOURCE:
        raise ValueError('Bounded world Clock/Ping definition source differs')
    _retained(inputs, definition.get('files'))
    _retained(inputs, definition.get('exports'))
    source = root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe'
    if inputs.get(str(source)) != SOURCE:
        raise ValueError('Bounded world lost the Clock/Ping source snapshot')
    for name, count in (('clock', 24), ('producer', 36), ('world', 201), ('result', 36)):
        pointer = proof['components'][name]
        if (not isinstance(pointer, dict) or set(pointer) != {'path', 'sha256'}
                or not SHA.fullmatch(str(pointer.get('sha256')))):
            raise ValueError('Bounded world Clock/Ping component pointer differs')
        path = Path(pointer['path']).resolve()
        if (not path.is_relative_to(root / 'code-clues') or path.name != 'manifest.json'
                or path.parent.name != pointer['sha256'] or inputs.get(str(path)) != pointer['sha256']):
            raise ValueError('Bounded world Clock/Ping component is not retained')
        component = _json(path, pointer['sha256'], budget=32 * 1024 * 1024)
        if (component.get('source_sha256') != SOURCE or component.get('network_used') is not False
                or component.get('profile_activated') is not False or not component.get('limits')
                or len(component.get('cases', [])) != count
                or (name == 'result' and len(component.get('short', [])) != 12)
                or (name == 'clock' and component.get('lobby_cases') != [])):
            raise ValueError('Bounded world Clock/Ping component scope differs')


def _world_results(proof, inputs):
    compatibility = proof.get('packet_compatibility')
    if (proof.get('schema') != 1 or proof.get('recipe') != 'world-results-current-v1'
            or proof.get('source_sha256') != SOURCE or proof.get('network_used') is not False
            or proof.get('runtime_admitted') is not False or not proof.get('limits')
            or proof.get('compatible_with_portable_codecs') is not True
            or not isinstance(compatibility, dict) or set(compatibility) != {'110', '206'}
            or any(value is not True for value in compatibility.values())):
        raise ValueError('Bounded world result layouts are not admitted')
    _retained(inputs, proof.get('definition', {}).get('inputs'))


def load_manifest(selector_sha, *, root=ROOT, workspace=WORKSPACE, installed=INSTALLED):
    root, workspace, installed = (Path(value).resolve() for value in (root, workspace, installed))
    if not isinstance(selector_sha, str) or not SHA.fullmatch(selector_sha):
        raise ValueError('Bounded world requires a full manifest SHA')
    path = root / 'bounded-world-profiles' / selector_sha / 'manifest.json'
    profile = _json(path, selector_sha)
    if (profile.get('schema') != 1 or profile.get('recipe') != RECIPE
            or profile.get('source_sha256') != SOURCE or profile.get('operations') != OPERATIONS
            or profile.get('policies') != POLICIES or profile.get('world_admitted') is not True
            or profile.get('creation_admitted') is not False or profile.get('online_verified') is not False
            or set(profile.get('proofs', {})) != PROOFS or not profile.get('limits')
            or Path(profile.get('source', '')).resolve() != installed):
        raise ValueError('Bounded world manifest scope differs')
    inputs = profile.get('inputs')
    if not isinstance(inputs, dict) or not 1 <= len(inputs) <= 2048:
        raise ValueError('Bounded world dependency set differs')
    for relative in CONSUMERS:
        consumer = workspace / 'phone-exit/bots' / relative
        if inputs.get(str(consumer)) != digest(consumer, 32 * 1024 * 1024):
            raise ValueError('Bounded world lost a runtime consumer')
    if inputs.get(str(installed)) != SOURCE:
        raise ValueError('Bounded world lost its installed source')
    entry = profile.get('entry')
    if (not isinstance(entry, dict) or set(entry) != {'path', 'sha256', 'selected_profile'}
            or not SHA.fullmatch(str(entry.get('sha256')))
            or entry['selected_profile'] != 'bounded-entry:' + entry['sha256']
            or Path(entry['path']).resolve() != root / 'bounded-entry-profiles' / entry['sha256'] / 'manifest.json'
            or inputs.get(str(Path(entry['path']).resolve())) != entry['sha256']):
        raise ValueError('Bounded world entry pointer differs')
    loader = _entry_loader(workspace)
    entry_path = Path(entry['path']).resolve()
    quests = _pointer(profile['proofs']['quest-observation-current'],root/'code-clues/quest-observation-current-v1',inputs)
    quest_runtime=quests.get('definition',{}).get('runtime_inputs',{})
    _retained(inputs,quest_runtime)
    for name, expected in inputs.items():
        dependency = Path(name).resolve()
        if not Path(name).is_absolute() or not SHA.fullmatch(str(expected)):
            raise ValueError('Bounded world dependency descriptor differs')
        if name in quest_runtime and dependency.is_relative_to(Path(sys.base_prefix).resolve()) and dependency.suffix.lower() in ('.py','.pyd','.dll','.exe'):
            budget=64*1024*1024
        else:
            budget = 2 * 1024 * 1024 if dependency == entry_path else loader.input_budget(dependency, root, workspace, installed)
        if digest(dependency, budget) != expected:
            raise ValueError('Bounded world dependency changed: ' + dependency.name)
    parent = loader.load_manifest(entry['sha256'], root=root, workspace=workspace, installed=installed)
    if parent['source_sha256'] != SOURCE:
        raise ValueError('Bounded world parent source differs')
    _retained(inputs, parent['inputs'])
    clock = _pointer(profile['proofs']['clock-world-current'], root / 'knowledge/clock-world-current-verified', inputs)
    nested = _pointer(profile['proofs']['world-results-current'], root / 'code-clues/world-results-current-v1', inputs)
    _clock_world(clock, root, inputs)
    _world_results(nested, inputs)
    stats = _pointer(profile['proofs']['initial-stats-current'],root/'code-clues/initial-stats-current-v1',inputs)
    if (stats.get('source_sha256')!=SOURCE or stats.get('recipe')!='initial-stats-current-v1'
            or stats.get('initial_projection_verified') is not True or stats.get('known_vital_ids_match') is not True
            or stats.get('runtime_admitted') is not False or stats.get('network_used') is not False
            or stats.get('vital_ids')!={'Level':3,'Hp':4,'MaxHp':5,'Mp':9,'MaxMp':10}):
        raise ValueError('Initial stat proof scope differs')
    _retained(inputs,stats.get('definition',{}).get('inputs'))
    changes = _pointer(profile['proofs']['stat-notifications-current'],root/'code-clues/stat-notifications-current-v1',inputs)
    if (changes.get('source_sha256')!=SOURCE or changes.get('recipe')!='stat-notifications-current-v1'
            or changes.get('notifications_projection_verified') is not True or changes.get('apply_uses_second_value') is not True
            or changes.get('runtime_admitted') is not False or changes.get('network_used') is not False
            or changes.get('vital_ids')!={'Level':3,'Hp':4,'MaxHp':5,'Mp':9,'MaxMp':10}
            or set(changes.get('packet_bindings',{}))!={'321','322'}
            or any(item.get('binding_verified') is not True or item.get('packet_id')!=int(key)
                   for key,item in changes.get('packet_bindings',{}).items())):
        raise ValueError('Stat notification proof scope differs')
    _retained(inputs,changes.get('definition',{}).get('inputs'))
    if (quests.get('source_sha256')!=SOURCE or quests.get('recipe')!='quest-observation-current-v1'
            or quests.get('observation_projection_verified') is not True
            or quests.get('native_execution') is not False or quests.get('native_proofs_reused') is not True
            or quests.get('runtime_admitted') is not False or quests.get('network_used') is not False
            or quests.get('scope')!='last_received_message_only' or quests.get('inherited_native_cases')!=1178
            or quests.get('packet_compatibility')!={'1854':True,'9905':True}
            or quests.get('bounds')!={'1854':dict(max_groups=8,max_quests_per_group=8,max_total_items=72,max_payload_size=2530),
                '9905':dict(max_records=64,max_payload_size=835)}
            or set(quests.get('packet_bindings',{}))!={'1854','9905'}
            or any(item.get('binding_verified') is not True or item.get('packet_id')!=int(key)
                for key,item in quests.get('packet_bindings',{}).items())):
        raise ValueError('Quest observation proof scope differs')
    _retained(inputs,quests.get('definition',{}).get('inputs'))
    return dict(profile, selected_profile='bounded-world:' + selector_sha, manifest_sha256=selector_sha)
