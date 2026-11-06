"""One separately admitted Fetch/NO DATA/SignUp/SignIn sequence; no world scope."""
from contextlib import contextmanager
from contextvars import ContextVar
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re

SHA = re.compile('[0-9a-f]{64}')
RECIPE = 'sdk-first-profile-runtime-v1'
OPERATIONS = ['v1/fetch-player', 'basic-terms-read', 'individual-terms-read', 'v1/sign-up', 'v1/sign-in']
CONTRACTS = {
    'auth': ('first-sdk-auth-current-v1', 'first-sdk-auth-current-v1'),
    'terms': ('first-sdk-terms-current-v1', 'first-sdk-terms-current-v1'),
    'continuation': ('first-sdk-continuation-current-v1', 'first-sdk-continuation-current-v1'),
}
_active = ContextVar('vampir_sdk_first_profile', default=None)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def pointer_path(pointer, folder, *, root, budget=8 * 1024 * 1024):
    if type(pointer) is not dict or set(pointer) != {'path', 'sha256'} or not SHA.fullmatch(str(pointer['sha256'])):
        raise ValueError('First SDK requires a full immutable pointer')
    expected = (Path(root) / folder / pointer['sha256'] / 'manifest.json').resolve()
    path = Path(pointer['path']).resolve()
    if (path != expected or not 0 < path.stat().st_size <= budget or digest(path) != pointer['sha256']):
        raise ValueError('First SDK immutable evidence changed')
    return path


def contract_document(role, pointer, *, root, inputs, source_sha256):
    folder, recipe = CONTRACTS[role]
    path = pointer_path(pointer, 'code-clues/' + folder, root=root)
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pointer['sha256'] or inputs.get(str(path)) != pointer['sha256']:
        raise ValueError('First SDK contract is not retained')
    report = json.loads(raw)
    if (report.get('recipe') != recipe or report.get('source_sha256') != source_sha256
            or report.get('network_used') is not False or report.get('runtime_admitted') is not False):
        raise ValueError('First SDK contract source or scope differs')
    if role == 'continuation':
        if (report.get('native_execution') is not True or len(report.get('fetch_cases', [])) != 27
                or len(report.get('terms_cases', [])) != 99):
            raise ValueError('First SDK continuation proof is incomplete')
    elif report.get('contract_subset_verified') is not True:
        raise ValueError('First SDK contract subset is not verified')
    declared = report.get('inputs')
    if type(declared) is not dict or not declared or any(inputs.get(k) != v for k, v in declared.items()):
        raise ValueError('First SDK contract inputs are not retained')
    return report


def validate_inputs(inputs, fetch_pointer, *, root, workspace, installed):
    from . import sdk_fetch_admission as fetch
    path = pointer_path(fetch_pointer, 'sdk-fetch-profiles', root=root, budget=2 * 1024 * 1024)
    if type(inputs) is not dict or inputs.get(str(path)) != fetch_pointer['sha256']:
        raise ValueError('First SDK base Fetch is not retained')
    base = fetch.load_manifest(fetch_pointer['sha256'], root=root, workspace=workspace, installed=installed)
    if any(inputs.get(k) != v for k, v in base['inputs'].items()):
        raise ValueError('First SDK lost a Fetch dependency')
    web_helpers = {str((Path(workspace) / 'phone-exit/bots/vampir-headless/windows' / name).resolve())
                   for name in ('verification-browser.cs', 'verification-browser.ps1', 'verification-form.js',
                                'nid-http-diagnostics.cs', 'nid-google-bridge.cs', 'nid-page-status.js')}
    for name in web_helpers:
        if (not SHA.fullmatch(str(inputs.get(name))) or not 0 < Path(name).stat().st_size <= 2 * 1024 * 1024
                or digest(name) != inputs[name]):
            raise ValueError('First SDK verification helper changed')
    fetch.validate_inputs({k: v for k, v in inputs.items() if k != str(path) and k not in web_helpers}, base['base_sdk_profile'],
                          root=root, workspace=workspace, installed=installed)
    return base


def load_manifest(profile_sha256, *, root, workspace, installed):
    root, workspace, installed = (Path(p).resolve() for p in (root, workspace, installed))
    if not SHA.fullmatch(str(profile_sha256)):
        raise ValueError('First SDK requires the full profile SHA')
    path = root / 'sdk-first-profiles' / profile_sha256 / 'manifest.json'
    if not 0 < path.stat().st_size <= 2 * 1024 * 1024:
        raise ValueError('First SDK profile exceeds budget')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != profile_sha256:
        raise ValueError('First SDK profile changed')
    value = json.loads(raw)
    if (value.get('schema') != 1 or value.get('recipe') != RECIPE
            or value.get('runtime_scope') != 'sdk-first-profile' or value.get('operations') != OPERATIONS
            or value.get('terms_policy') != 'strict-no-data-only'
            or type(value.get('max_sequences')) is not int or value.get('max_sequences') != 1
            or value.get('runtime_admitted') is not False or value.get('game_session_ready') is not False
            or not SHA.fullmatch(str(value.get('source_sha256')))
            or Path(value.get('source', '')).resolve() != installed
            or type(value.get('contracts')) is not dict or set(value['contracts']) != set(CONTRACTS)):
        raise ValueError('First SDK profile source or scope differs')
    inputs = value.get('inputs')
    fetch = validate_inputs(inputs, value.get('fetch_profile'), root=root, workspace=workspace, installed=installed)
    if (fetch['source_sha256'] != value['source_sha256'] or value.get('base_sdk_profile') != fetch['base_sdk_profile']
            or inputs.get(str(installed)) != value['source_sha256']
            or inputs.get(str(Path(__file__).resolve())) != digest(__file__)):
        raise ValueError('First SDK source or loader is not retained')
    for role, pointer in value['contracts'].items():
        contract_document(role, pointer, root=root, inputs=inputs, source_sha256=value['source_sha256'])
    if digest(path) != profile_sha256:
        raise ValueError('First SDK profile changed during validation')
    return value


@contextmanager
def scope(profile_sha256, *, root, workspace, installed):
    from .runtime_admission import _active as world_scope
    from .sdk_fetch_admission import _active as fetch_scope
    from .sdk_launcher_admission import scope as sdk_scope
    if _active.get() is not None or fetch_scope.get() is not None or world_scope.get() is not None:
        raise ValueError('First SDK requires its own unused scope')
    profile = load_manifest(profile_sha256, root=root, workspace=workspace, installed=installed)
    selector = 'sdk-launcher:' + profile['base_sdk_profile']['sha256']
    with sdk_scope(selector, root=root, workspace=workspace):
        token = _active.set(dict(profile=profile, selector=selector, used=False, installed=Path(installed)))
        try:
            yield copy.deepcopy(profile), selector
        finally:
            _active.reset(token)


def execute_first_profile(prepared, provider, *, terms_country, terms_locale, basic_filtered,
                          route=None, progress=None, check_account=None,
                          _fetch=None, _terms=None, _signup=None, _signin=None):
    from .gmc2_context import SdkInputs
    from .nid_sdk_credential import build_nid_sdk_credential
    from .sdk_first_login import execute_first_sdk_login
    state = _active.get()
    if state is None or state['used'] or not isinstance(prepared, SdkInputs):
        raise ValueError('First SDK requires an unused admitted sequence')
    if prepared.source_sha256 != state['profile']['source_sha256']:
        raise ValueError('First SDK context belongs to another source')

    def check():
        prepared.check_usage(email=prepared.email, selected_profile=state['selector'], route=route)
        if digest(state['installed']) != prepared.source_sha256:
            raise ValueError('First SDK client changed during the sequence')
        if check_account: check_account()

    check()
    profile, binding = prepared.profile, prepared.binding
    credential = build_nid_sdk_credential(provider)
    inputs = dict(constants=prepared.constants, game_code=profile['game_code'], build_code=profile['build_code'],
        nm_device_key=binding.nm_device_key, device_key=binding.device_key,
        country_code=profile['country_code'] if route else provider.joined_country_code, os_type=profile['os_type'])
    overrides = {name: value for name, value in (
        ('_fetch', _fetch), ('_terms', _terms), ('_signup', _signup), ('_signin', _signin)) if value is not None}
    # Consume before any transport. A failed/unknown SignUp is never retried in this scope.
    state['used'] = True
    return execute_first_sdk_login(credential=credential, inputs=inputs, terms_country=terms_country,
        terms_locale=terms_locale, basic_filtered=basic_filtered, route=route, progress=progress,
        check_context=check, **overrides)
