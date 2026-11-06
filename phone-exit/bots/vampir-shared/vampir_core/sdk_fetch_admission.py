"""One explicitly admitted, read-only Fetch; separate from Launcher and world."""
from contextlib import contextmanager
from contextvars import ContextVar
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re

SHA = re.compile('[0-9a-f]{64}')
RECIPE = 'sdk-fetch-read-runtime-v1'
CONTRACT_RECIPE = 'sdk-fetch-current-static-v1'
_active = ContextVar('vampir_sdk_fetch_read', default=None)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def contract_document(pointer, *, root, inputs, source_sha256):
    if type(pointer) is not dict or set(pointer) != {'path', 'sha256'} or not SHA.fullmatch(str(pointer['sha256'])):
        raise ValueError('Fetch contract requires a full immutable pointer')
    path = Path(pointer['path']).resolve()
    if (path.parent.parent != (root / 'code-clues/sdk-fetch-current-static-v1').resolve()
            or path.parent.name != pointer['sha256'] or path.name != 'manifest.json'
            or not 0 < path.stat().st_size <= 8 * 1024 * 1024
            or inputs.get(str(path)) != pointer['sha256'] or digest(path) != pointer['sha256']):
        raise ValueError('Fetch contract identity changed')
    contract = json.loads(path.read_bytes())
    if (contract.get('recipe') != CONTRACT_RECIPE or contract.get('producer') != 'sdk-fetch-current-contract-v1'
            or contract.get('source_sha256') != source_sha256
            or contract.get('contract_subset_verified') is not True
            or contract.get('operation') != 'v1/fetch-player' or contract.get('read_only') is not True
            or contract.get('native_execution') is not False or contract.get('runtime_admitted') is not False):
        raise ValueError('Fetch subset is not verified for this source')
    declared = contract.get('inputs')
    if not isinstance(declared, dict) or not declared or any(inputs.get(k) != v for k, v in declared.items()):
        raise ValueError('Fetch contract inputs are not retained')
    return contract


def validate_inputs(inputs, base, *, root, workspace, installed):
    """Reuse the existing file policy, adding only the exact base SDK manifest."""
    if type(base) is not dict or set(base) != {'path', 'sha256'} or not SHA.fullmatch(str(base['sha256'])):
        raise ValueError('Fetch base SDK pointer differs')
    expected = (root / 'sdk-launcher-profiles' / base['sha256'] / 'manifest.json').resolve()
    if Path(base['path']).resolve() != expected:
        raise ValueError('Fetch base SDK path differs')
    if type(inputs) is not dict or not 1 <= len(inputs) <= 256 or inputs.get(str(expected)) != base['sha256']:
        raise ValueError('Fetch base SDK is not retained')
    if not 0 < expected.stat().st_size <= 2 * 1024 * 1024 or digest(expected) != base['sha256']:
        raise ValueError('Fetch base SDK changed')
    browser_sources = {str((workspace / 'phone-exit/bots/vampir-headless/windows' / name).resolve())
                       for name in ('nid-browser.cs', 'nid-browser.ps1', 'nid-sign-in.js')}
    for name in browser_sources:
        if (not SHA.fullmatch(str(inputs.get(name))) or not 0 < Path(name).stat().st_size <= 2 * 1024 * 1024
                or digest(name) != inputs[name]):
            raise ValueError('Fetch browser helper changed')
    loader = load('fetch_input_file_policy', workspace / 'phone-exit/bots/vampir-headless/sdk-launcher-profile.py')
    loader.validate_inputs({k: v for k, v in inputs.items() if k != str(expected) and k not in browser_sources},
        root=root, workspace=workspace, installed=installed)


def load_manifest(profile_sha256, *, root, workspace, installed):
    root, workspace, installed = (Path(x).resolve() for x in (root, workspace, installed))
    if not SHA.fullmatch(str(profile_sha256)):
        raise ValueError('Fetch requires a full profile SHA')
    path = root / 'sdk-fetch-profiles' / profile_sha256 / 'manifest.json'
    if not 0 < path.stat().st_size <= 2 * 1024 * 1024:
        raise ValueError('Fetch profile exceeds budget')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != profile_sha256:
        raise ValueError('Fetch profile changed')
    profile = json.loads(raw)
    if (profile.get('schema') != 1 or profile.get('recipe') != RECIPE
            or profile.get('operations') != ['v1/fetch-player']
            or profile.get('runtime_scope') != 'sdk-profile-read'
            or profile.get('read_only') is not True
            or profile.get('runtime_admitted') is not False
            or profile.get('game_session_ready') is not False
            or not SHA.fullmatch(str(profile.get('source_sha256')))
            or Path(profile.get('source', '')).resolve() != installed):
        raise ValueError('Fetch profile source or scope differs')
    inputs = profile.get('inputs')
    loader = load('fetch_base_sdk_loader', workspace / 'phone-exit/bots/vampir-headless/sdk-launcher-profile.py')
    base = profile.get('base_sdk_profile')
    validate_inputs(inputs, base, root=root, workspace=workspace, installed=installed)
    if (inputs.get(str(installed)) != profile['source_sha256']
            or inputs.get(str(Path(__file__).resolve())) != digest(__file__)):
        raise ValueError('Fetch source or loader is not retained')
    if type(base) is not dict or set(base) != {'path', 'sha256'} or not SHA.fullmatch(str(base['sha256'])):
        raise ValueError('Fetch base SDK pointer differs')
    expected = root / 'sdk-launcher-profiles' / base['sha256'] / 'manifest.json'
    if Path(base['path']).resolve() != expected.resolve() or inputs.get(str(expected.resolve())) != base['sha256']:
        raise ValueError('Fetch base SDK is not retained')
    base_profile = loader.load_manifest(profile_sha256=base['sha256'], source_sha256=profile['source_sha256'],
        root=root, workspace=workspace, installed=installed)
    if any(inputs.get(k) != v for k, v in base_profile['inputs'].items()):
        raise ValueError('Fetch lost a base SDK dependency')
    contract_document(profile.get('contract'), root=root, inputs=inputs, source_sha256=profile['source_sha256'])
    if digest(path) != profile_sha256:
        raise ValueError('Fetch profile changed during validation')
    return profile


@contextmanager
def scope(profile_sha256, *, root, workspace, installed):
    if _active.get() is not None:
        raise ValueError('One Fetch scope per worker; nested reuse is forbidden')
    from .runtime_admission import _active as world_scope
    from .sdk_launcher_admission import scope as sdk_scope
    if world_scope.get() is not None:
        raise ValueError('Cannot switch an active world worker to Fetch')
    profile = load_manifest(profile_sha256, root=root, workspace=workspace, installed=installed)
    selector = 'sdk-launcher:' + profile['base_sdk_profile']['sha256']
    # Only the existing SDK geo/NID policy is borrowed. Its operation guards stay intact.
    with sdk_scope(selector, root=root, workspace=workspace):
        token = _active.set(dict(profile=profile, selector=selector, used=False))
        try:
            yield copy.deepcopy(profile), selector
        finally:
            _active.reset(token)


def execute_fetch(prepared, provider, *, route=None, progress=None, _execute=None):
    """Consume the single exchange before transport; never retry an unknown result."""
    from .gmc2_context import SdkInputs
    from .nid_sdk_credential import build_nid_sdk_credential
    from .sdk_fetch import plan_nid_sdk_fetch
    from .sdk_sign_in_http import execute_sdk_fetch
    state = _active.get()
    if state is None or state['used'] or not isinstance(prepared, SdkInputs):
        raise ValueError('Fetch requires an unused admitted read scope')
    if prepared.source_sha256 != state['profile']['source_sha256']:
        raise ValueError('Fetch context belongs to another client')
    prepared.check_usage(email=prepared.email, selected_profile=state['selector'], route=route)
    profile, binding = prepared.profile, prepared.binding
    credential = build_nid_sdk_credential(provider)
    plan = plan_nid_sdk_fetch(constants=prepared.constants, credential=credential,
        game_code=profile['game_code'], build_code=profile['build_code'], nm_device_key=binding.nm_device_key,
        device_key=binding.device_key, country_code=profile['country_code'] if route else provider.joined_country_code,
        os_type=profile['os_type'])
    state['used'] = True
    if progress:
        progress('sdk_fetch_player')
    return (_execute or execute_sdk_fetch)(plan, expected_url=plan.url, route=route)
