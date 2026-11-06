"""Publish a source-checked Fetch-only profile; never expand Launcher/world scope."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[3]
ROOT = Path('F:/PhoneExit Resources/Vampir')
INSTALLED = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
BASE_POINTER = HERE / 'knowledge/sdk-launcher-runtime-profile-current.json'
CONSUMERS = (
    'vampir-shared/vampir_core/sdk_fetch_admission.py',
    'vampir-shared/vampir_core/sdk_fetch.py', 'vampir-shared/vampir_core/sdk_sign_in.py',
    'vampir-shared/vampir_core/sdk_sign_in_http.py', 'vampir-shared/vampir_core/nid_sdk_credential.py',
    'vampir-shared/vampir_core/gmc2_context.py', 'vampir-shared/vampir_core/nid_web_context.py',
    'vampir-shared/vampir_core/nid_web_url.py', 'vampir-shared/vampir_core/sdk_config.py',
    'vampir-headless/run-account-sdk-fetch.py', 'vampir-headless/run-nid-sdk-sign-in.py',
    'vampir-headless/nid-browser.py', 'vampir-headless/run-account-entry-diagnostic.py',
    'vampir-headless/verify-account.py',
    'vampir-headless/windows/nid-browser.cs', 'vampir-headless/windows/nid-browser.ps1',
    'vampir-headless/windows/nid-sign-in.js', 'resource-tools/vampir/webview2.lock.json',
    'vampir-shared/vampir_core/account_store.py', 'vampir-shared/vampir_core/device_templates.py',
    'vampir-shared/vampir_core/bot_device_settings.py', 'vampir-shared/vampir_core/device_registry.py',
    'vampir-shared/vampir_core/windows_device_identity.py', 'vampir-headless/sdk-launcher-profile.py',
)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def build(contract_path, *, root=ROOT, workspace=WORKSPACE, installed=INSTALLED, base_pointer=BASE_POINTER):
    root, workspace, installed, contract_path = (Path(x).resolve() for x in (root, workspace, installed, contract_path))
    pointer = json.loads(Path(base_pointer).read_bytes())
    loader = load('fetch_profile_base_validator', workspace / 'phone-exit/bots/vampir-headless/sdk-launcher-profile.py')
    base = loader.load_manifest(profile_sha256=pointer['profile']['sha256'], source_sha256=pointer['source_sha256'],
        root=root, workspace=workspace, installed=installed)
    inputs = dict(base['inputs'])
    inputs[str(Path(pointer['profile']['path']).resolve())] = pointer['profile']['sha256']
    contract = json.loads(contract_path.read_bytes())
    # The registered checker must reproduce the proof before publication.
    checker_path = workspace / 'phone-exit/bots/resource-tools/vampir/inspect-sdk-fetch-current.py'
    checker = load('fetch_contract_validator', checker_path)
    checker.verify_report(contract_path, root=root, workspace=workspace)
    for name, expected in contract['inputs'].items():
        if name in inputs and inputs[name] != expected:
            raise ValueError('Fetch inputs conflict with the base SDK')
        inputs[name] = expected
    for path in [Path(base_pointer).resolve(), Path(__file__).resolve(), checker_path,
                 *[workspace / 'phone-exit/bots' / name for name in CONSUMERS]]:
        inputs[str(path.resolve())] = digest(path)
    inputs[str(contract_path)] = digest(contract_path)
    helper = load('fetch_profile_runtime_validator', workspace / 'phone-exit/bots/vampir-shared/vampir_core/sdk_fetch_admission.py')
    helper.contract_document(dict(path=str(contract_path), sha256=digest(contract_path)), root=root,
        inputs=inputs, source_sha256=base['source_sha256'])
    helper.validate_inputs(inputs, pointer['profile'], root=root, workspace=workspace, installed=installed)
    return dict(schema=1, recipe=helper.RECIPE, source=str(installed), source_sha256=base['source_sha256'],
        runtime_scope='sdk-profile-read', operations=['v1/fetch-player'], read_only=True,
        base_sdk_profile=pointer['profile'], contract=dict(path=str(contract_path), sha256=digest(contract_path)),
        inputs=dict(sorted(inputs.items())), runtime_admitted=False, game_session_ready=False,
        limits=['One read-only Fetch exchange, strict local response subset; no SDK SignUp, Terms, SignIn or game.',
                'Base SDK native proofs and static Fetch subset are distinct; full native callback effects are not executed.'])


def publish(profile, *, root=ROOT):
    raw = (json.dumps(profile, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()
    path = Path(root) / 'sdk-fetch-profiles' / hashlib.sha256(raw).hexdigest() / 'manifest.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() != raw:
        raise ValueError('Immutable Fetch profile differs')
    if not path.exists():
        workflow = load('fetch_atomic_publisher', HERE / 'research-workflow.py')
        workflow.atomic(path, raw)
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract', required=True, type=Path)
    args = parser.parse_args()
    profile = build(args.contract)
    path = publish(profile)
    print(json.dumps(dict(profile=str(path), profile_sha256=path.parent.name, scope='sdk-profile-read')))
