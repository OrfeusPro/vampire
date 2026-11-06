"""Read one immutable source-bound profile for entry through character lists."""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path('F:/PhoneExit Resources/Vampir')
WORKSPACE = Path(__file__).resolve().parents[3]
INSTALLED = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
RECIPE = 'bounded-entry-profile-v1'
POLICIES = ['game-login-current-layout-v1', 'lobby-current-layout-v1', 'lobby-ping-clock-v1']
OPERATIONS = ['cdn', 'lobby', 'character-list']
PROOFS = {'lobby-login-prepare-current', 'lobby-sender-current', 'lobby-results-current'}
SHA = re.compile('[0-9a-f]{64}')


def digest(path, budget):
    path = Path(path)
    if not 0 <= path.stat().st_size <= budget:
        raise ValueError('Bounded entry dependency exceeds its file budget: ' + path.name)
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def input_budget(path, root, workspace, installed):
    if path == installed or path == installed.parents[2] / 'Content/Paks/ProjectRED-Windows.pak':
        return 1024 * 1024 * 1024
    if path == installed.parents[2] / 'Saved/PersistentDownloadDir/Patch/windows.manifestlist':
        return 2 * 1024 * 1024
    python = Path(sys.executable).resolve()
    if path in (python, python.with_name('python3.dll'),
                python.with_name(f'python{sys.version_info.major}{sys.version_info.minor}.dll'),
                Path('C:/Windows/System32/ucrtbase.dll').resolve()):
        return 64 * 1024 * 1024
    if path.is_relative_to(root / 'client-code-snapshots'):
        parts = path.relative_to(root / 'client-code-snapshots').parts
        if len(parts) == 2 and SHA.fullmatch(parts[0]) and parts[1] == 'ProjectRED-Win64-Shipping.exe':
            return 1024 * 1024 * 1024
    folders = ('knowledge', 'ghidra', 'code-clues', 'resource-config-snapshots',
               'sdk-launcher-profiles', 'game-source-candidates-current')
    if any(path.is_relative_to(root / folder) for folder in folders) and path.suffix.lower() in ('.json', '.py', '.ini', '.txt'):
        return 64 * 1024 * 1024
    if path.is_relative_to(workspace / 'phone-exit/bots') and path.suffix.lower() in ('.py', '.json', '.java', '.txt'):
        return 32 * 1024 * 1024
    if path.is_relative_to(workspace / 'phone-exit/.tools/vampir-analysis') and (
            path.suffix.lower() in ('.py', '.dll') or path.name == 'RECORD'):
        return 64 * 1024 * 1024
    raise ValueError('Bounded entry dependency is outside allowed locations')


def load_manifest(selector_sha, *, root=ROOT, workspace=WORKSPACE, installed=INSTALLED):
    root, workspace, installed = (Path(value).resolve() for value in (root, workspace, installed))
    if not isinstance(selector_sha, str) or not SHA.fullmatch(selector_sha):
        raise ValueError('Bounded entry requires a full manifest SHA')
    path = root / 'bounded-entry-profiles' / selector_sha / 'manifest.json'
    if digest(path, 2 * 1024 * 1024) != selector_sha:
        raise ValueError('Bounded entry manifest changed')
    profile = json.loads(path.read_bytes())
    source_sha = profile.get('source_sha256')
    if (profile.get('schema') != 1 or profile.get('recipe') != RECIPE
            or profile.get('operations') != OPERATIONS or profile.get('policies') != POLICIES
            or not SHA.fullmatch(str(source_sha)) or profile.get('online_verified') is not False
            or profile.get('creation_admitted') is not False or profile.get('world_admitted') is not False
            or set(profile.get('proofs', {})) != PROOFS or not profile.get('limits')
            or Path(profile['source']).resolve() != installed):
        raise ValueError('Bounded entry manifest scope differs')
    inputs = profile.get('inputs')
    if not isinstance(inputs, dict) or not 1 <= len(inputs) <= 1024:
        raise ValueError('Bounded entry dependency set differs')
    loader = workspace / 'phone-exit/bots/vampir-headless/bounded-entry-profile.py'
    if inputs.get(str(installed)) != source_sha or inputs.get(str(loader)) != digest(loader, 1024 * 1024):
        raise ValueError('Bounded entry lost its source or loader')
    for name, expected in inputs.items():
        dependency = Path(name).resolve()
        if not Path(name).is_absolute() or not SHA.fullmatch(str(expected)):
            raise ValueError('Bounded entry dependency descriptor differs')
        if digest(dependency, input_budget(dependency, root, workspace, installed)) != expected:
            raise ValueError('Bounded entry dependency changed: ' + dependency.name)
    sdk_sha = profile.get('sdk_profile_sha256')
    if not SHA.fullmatch(str(sdk_sha)):
        raise ValueError('Bounded entry SDK profile is missing')
    sdk_path = root / 'sdk-launcher-profiles' / sdk_sha / 'manifest.json'
    if inputs.get(str(sdk_path)) != sdk_sha:
        raise ValueError('Bounded entry SDK profile is not retained')
    game = profile['game_profile']
    if (game.get('config_prefix') != 'real' or not SHA.fullmatch(str(game.get('config_snapshot_sha256')))
            or not re.fullmatch(r'[A-F0-9]{32}', game.get('compiled_tag', ''))
            or game.get('cdn_url') != 'https://red.gcdn.netmarble.com/red/config/window/real/'
                + game['app_version'].replace('.', '_') + '/config.json'):
        raise ValueError('Bounded entry base game profile differs')
    for identifier, pointer in profile['proofs'].items():
        proof_path = root / 'code-clues' / (identifier + '-v1') / pointer['sha256'] / 'manifest.json'
        if Path(pointer['path']).resolve() != proof_path or inputs.get(str(proof_path)) != pointer['sha256']:
            raise ValueError('Bounded entry proof pointer differs')
        proof = json.loads(proof_path.read_bytes())
        if (proof.get('source_sha256') != source_sha or proof.get('network_used') is not False
                or not proof.get('limits')):
            raise ValueError('Bounded entry proof source or limits differ')
    return dict(profile, selected_profile='bounded-entry:' + selector_sha, manifest_sha256=selector_sha)
