"""Load one explicitly selected immutable SDK Launcher profile and all inputs."""
import hashlib
import json
import locale
from pathlib import Path
import re
import sys


ROOT = Path('F:/PhoneExit Resources/Vampir')
WORKSPACE = Path(__file__).resolve().parents[3]
INSTALLED = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
SHA = re.compile('[0-9a-f]{64}')
MAX_MANIFEST = 2 * 1024 * 1024
MAX_INPUTS = 256
ROLES = frozenset(('defaults', 'override', 'platform', 'start', 'url', 'headers', 'geo', 'nid_base', 'nid_helpers'))


def digest(path, budget):
    path = Path(path)
    if not 0 < path.stat().st_size <= budget:
        raise ValueError('SDK Launcher input exceeds content budget')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def input_budget(path, *, root, workspace, installed):
    path = Path(path).resolve()
    root, workspace, installed = (Path(value).resolve() for value in (root, workspace, installed))
    if path == installed:
        return 512 * 1024 * 1024
    if path == Path(sys.executable).resolve():
        return 32 * 1024 * 1024
    if path == Path('C:/Windows/System32/ucrtbase.dll').resolve():
        return 32 * 1024 * 1024
    if path.is_relative_to(root / 'client-code-snapshots'):
        parts = path.relative_to(root / 'client-code-snapshots').parts
        if len(parts) == 2 and SHA.fullmatch(parts[0]) and parts[1] == 'ProjectRED-Win64-Shipping.exe':
            return 512 * 1024 * 1024
        raise ValueError('SDK Launcher source path differs')
    if any(path.is_relative_to(root / folder) for folder in ('knowledge', 'ghidra', 'code-clues')):
        if path.suffix.lower() in ('.json', '.py'):
            return 64 * 1024 * 1024
    if path.is_relative_to(workspace / 'phone-exit/bots'):
        if path.suffix.lower() in ('.py', '.json', '.txt', '.java'):
            return 16 * 1024 * 1024
    if (path.is_relative_to(workspace / 'phone-exit/.tools/vampir-analysis')
            and path.name == 'RECORD' and path.parent.name.endswith('.dist-info')):
        return 8 * 1024 * 1024
    raise ValueError('SDK Launcher dependency outside allowed paths')


def validate_inputs(inputs, *, root, workspace, installed):
    if not isinstance(inputs, dict) or not 1 <= len(inputs) <= MAX_INPUTS:
        raise ValueError('SDK Launcher dependency count differs')
    for name, expected in inputs.items():
        if not isinstance(name, str) or not Path(name).is_absolute() or not SHA.fullmatch(str(expected)):
            raise ValueError('SDK Launcher dependency declaration differs')
        budget = input_budget(name, root=root, workspace=workspace, installed=installed)
        if digest(name, budget) != expected:
            raise ValueError('SDK Launcher dependency changed')


def validate_evidence(profile, root, workspace):
    evidence = profile.get('evidence')
    if (not isinstance(evidence, dict)
            or set(evidence) != {'native', 'generation', 'launcher', 'launcher_context', 'components'}
            or not isinstance(evidence['components'], dict) or set(evidence['components']) != ROLES):
        raise ValueError('SDK Launcher evidence set differs')
    pointers = [(evidence[name], root / category) for name, category in (
        ('native', 'knowledge/sdk-batch-native-v1'),
        ('generation', 'knowledge/sdk-batch-generated-v1'),
        ('launcher', 'code-clues/launcher-contract-v1'))]
    pointers.extend((pointer, root / 'code-clues') for pointer in evidence['components'].values())
    for pointer, folder in pointers:
        if not isinstance(pointer, dict) or set(pointer) != {'path', 'sha256'}:
            raise ValueError('SDK Launcher evidence pointer differs')
        path = Path(pointer['path']).resolve()
        if (path.name != 'manifest.json' or path.parent.name != pointer['sha256']
                or not path.is_relative_to(folder) or not SHA.fullmatch(str(pointer['sha256']))
                or profile['inputs'].get(str(path)) != pointer['sha256']):
            raise ValueError('SDK Launcher evidence is not pinned')
    context = evidence['launcher_context']
    if not isinstance(context, dict) or set(context) != {'path', 'sha256'}:
        raise ValueError('SDK Launcher context pointer differs')
    path = Path(context['path']).resolve()
    if (not path.is_relative_to(workspace / 'phone-exit/bots/resource-tools/vampir/knowledge/native-contexts')
            or path.suffix != '.json' or not SHA.fullmatch(str(context['sha256']))
            or profile['inputs'].get(str(path)) != context['sha256']
            or str(Path(__file__).resolve()) not in profile['inputs']):
        raise ValueError('SDK Launcher context or loader is not pinned')


def load_manifest(*, profile_sha256, source_sha256, root=ROOT, workspace=WORKSPACE, installed=INSTALLED):
    if not SHA.fullmatch(str(profile_sha256)) or not SHA.fullmatch(str(source_sha256)):
        raise ValueError('SDK Launcher requires explicit full manifest and source SHA')
    root, workspace, installed = (Path(value).resolve() for value in (root, workspace, installed))
    path = root / 'sdk-launcher-profiles' / profile_sha256 / 'manifest.json'
    if digest(path, MAX_MANIFEST) != profile_sha256:
        raise ValueError('SDK Launcher profile changed')
    raw = path.read_bytes()
    if len(raw) > MAX_MANIFEST or hashlib.sha256(raw).hexdigest() != profile_sha256:
        raise ValueError('SDK Launcher profile changed during read')
    profile = json.loads(raw)
    if (profile.get('schema') != 1 or profile.get('recipe') != 'sdk-launcher-runtime-v1'
            or profile.get('source_sha256') != source_sha256
            or Path(profile.get('source', '')).resolve() != installed
            or profile.get('runtime_scope') != 'sdk-launcher-auth'
            or profile.get('supported_auth_flows') != ['launcher']
            or any(profile.get(key) is not False for key in (
                'network_ready', 'game_protocol_verified', 'direct_sdk_operations_verified',
                'active_runtime_settings_verified', 'runtime_admitted', 'profile_activated'))
            or profile.get('native_case_executions') != 3667
            or profile.get('primitive_cases') != {'numeric': 112, 'channels': 176}):
        raise ValueError('SDK Launcher profile source or scope differs')
    inputs = profile.get('inputs')
    if not isinstance(inputs, dict) or inputs.get(str(installed)) != source_sha256:
        raise ValueError('SDK Launcher installed source is not pinned')
    validate_evidence(profile, root, workspace)
    if profile.get('crt_locale') != locale.setlocale(locale.LC_ALL):
        raise ValueError('SDK Launcher CRT locale changed')
    validate_inputs(inputs, root=root, workspace=workspace, installed=installed)
    if digest(path, MAX_MANIFEST) != profile_sha256:
        raise ValueError('SDK Launcher profile changed during validation')
    return profile


def load_profile(kind, *, profile_sha256, source_sha256, root=ROOT, workspace=WORKSPACE, installed=INSTALLED):
    if kind not in ('public_gmc2', 'nid'):
        raise ValueError('Unsupported SDK Launcher profile section')
    profile = load_manifest(profile_sha256=profile_sha256, source_sha256=source_sha256,
                            root=root, workspace=workspace, installed=installed)
    return dict(profile[kind], source=str(Path(installed).resolve()), source_sha256=source_sha256,
                sha256=source_sha256, profile_sha256=profile_sha256,
                active_runtime_settings_verified=False)
