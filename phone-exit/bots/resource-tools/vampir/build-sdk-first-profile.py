"""Publish a separate source-bound first SDK profile; no online or world actions."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[3]
ROOT = Path('F:/PhoneExit Resources/Vampir')
INSTALLED = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
CONSUMERS = ('vampir-shared/vampir_core/sdk_first_profile_admission.py',
             'vampir-shared/vampir_core/sdk_first_login.py', 'vampir-shared/vampir_core/sdk_terms.py',
             'vampir-shared/vampir_core/sdk_terms_http.py', 'vampir-shared/vampir_core/sdk_sign_up_response.py',
             'vampir-shared/vampir_core/sdk_sign_in_response.py', 'vampir-headless/run-account-first-sdk.py',
             'vampir-headless/verify-account.py', 'vampir-headless/nid-mail-code.py',
             'vampir-headless/windows/verification-browser.cs', 'vampir-headless/windows/verification-browser.ps1',
             'vampir-headless/windows/verification-form.js', 'vampir-headless/windows/nid-http-diagnostics.cs',
             'vampir-headless/windows/nid-google-bridge.cs', 'vampir-headless/windows/nid-page-status.js',
             'resource-tools/vampir/knowledge/verification-web-current.json')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def build(fetch_pointer, contracts, *, root=ROOT, workspace=WORKSPACE, installed=INSTALLED):
    root, workspace, installed = (Path(p).resolve() for p in (root, workspace, installed))
    sys.path.insert(0, str(workspace / 'phone-exit/bots/vampir-shared'))
    from vampir_core import sdk_first_profile_admission as admission
    from vampir_core import sdk_fetch_admission as fetch
    fetch_path = admission.pointer_path(fetch_pointer, 'sdk-fetch-profiles', root=root, budget=2 * 1024 * 1024)
    base = fetch.load_manifest(fetch_pointer['sha256'], root=root, workspace=workspace, installed=installed)
    inputs = dict(base['inputs'])
    inputs[str(fetch_path)] = fetch_pointer['sha256']
    if type(contracts) is not dict or set(contracts) != set(admission.CONTRACTS):
        raise ValueError('First SDK requires all three bounded contracts')
    for role, pointer in contracts.items():
        folder, _ = admission.CONTRACTS[role]
        path = admission.pointer_path(pointer, 'code-clues/' + folder, root=root)
        report = json.loads(path.read_bytes())
        if role != 'continuation':
            tool_path = HERE / ('inspect-first-sdk-' + role + '-current.py')
            checker = load('first_sdk_' + role + '_checker', tool_path)
            report = checker.verify_report(path, root=root, workspace=workspace)
            inputs[str(tool_path.resolve())] = digest(tool_path)
        else:
            # This source-bound native result is already recorded by prepare/collect/finish.
            # Check every retained input; do not rerun the 126 unchanged cases.
            for name, expected in report.get('inputs', {}).items():
                if digest(name) != expected: raise ValueError('First SDK continuation input changed')
        for name, expected in report['inputs'].items():
            if name in inputs and inputs[name] != expected:
                raise ValueError('First SDK contracts disagree about a dependency')
            inputs[name] = expected
        inputs[str(path)] = pointer['sha256']
    for path in (Path(__file__).resolve(), *[workspace / 'phone-exit/bots' / name for name in CONSUMERS]):
        inputs[str(path.resolve())] = digest(path)
    admission.validate_inputs(inputs, fetch_pointer, root=root, workspace=workspace, installed=installed)
    for role, pointer in contracts.items():
        admission.contract_document(role, pointer, root=root, inputs=inputs, source_sha256=base['source_sha256'])
    return dict(schema=1, recipe=admission.RECIPE, source=str(installed), source_sha256=base['source_sha256'],
        runtime_scope='sdk-first-profile', operations=admission.OPERATIONS, max_sequences=1,
        terms_policy='strict-no-data-only', fetch_profile=fetch_pointer, base_sdk_profile=base['base_sdk_profile'],
        contracts=contracts, inputs=dict(sorted(inputs.items())), runtime_admitted=False, game_session_ready=False,
        limits=['Only one explicit first SDK sequence; available terms stop before SignUp.',
                'This profile grants no Netmarble registration, lobby, character creation or world capability.'])


def publish(profile, *, root=ROOT):
    raw = (json.dumps(profile, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()
    path = Path(root) / 'sdk-first-profiles' / hashlib.sha256(raw).hexdigest() / 'manifest.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() != raw:
        raise ValueError('Immutable first SDK profile differs')
    if not path.exists():
        load('first_sdk_atomic_publisher', HERE / 'research-workflow.py').atomic(path, raw)
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selector', type=Path, required=True, help='JSON с Fetch и тремя source contracts')
    args = parser.parse_args()
    selector = json.loads(args.selector.read_bytes())
    profile = build(selector['fetch_profile'], selector['contracts'])
    path = publish(profile)
    print(json.dumps(dict(profile=str(path), profile_sha256=path.parent.name, scope='sdk-first-profile')))
