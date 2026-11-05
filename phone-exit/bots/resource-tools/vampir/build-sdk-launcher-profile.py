"""Compose existing SDK native and Launcher proofs into one immutable profile."""
import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[3]
ROOT = Path('F:/PhoneExit Resources/Vampir')
INSTALLED = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
CONTEXT = HERE / 'knowledge/sdk-launcher-runtime-current.json'
LOADER = HERE.parents[1] / 'vampir-headless/sdk-launcher-profile.py'


def load(name, path=None):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path or HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def pin(inputs, path, expected):
    name = str(Path(path).resolve())
    if name in inputs and inputs[name] != expected:
        raise ValueError('SDK Launcher input declarations conflict')
    if digest(name) != expected:
        raise ValueError('SDK Launcher component report changed')
    inputs[name] = expected


def document(pointer, category, root, inputs):
    if not isinstance(pointer, dict) or set(pointer) != {'path', 'sha256'}:
        raise ValueError('SDK Launcher proof pointer differs')
    path = Path(pointer['path']).resolve()
    if (path.parent.parent != (root / category).resolve() or path.name != 'manifest.json'
            or path.parent.name != pointer['sha256']):
        raise ValueError('SDK Launcher proof category differs')
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError('SDK Launcher proof exceeds content budget')
    pin(inputs, path, pointer['sha256'])
    return json.loads(path.read_bytes())


def build(*, root=ROOT, installed=INSTALLED, context_path=CONTEXT):
    root, installed, context_path = (Path(value).resolve() for value in (root, installed, context_path))
    if not 0 < context_path.stat().st_size <= 65536:
        raise ValueError('SDK Launcher context exceeds content budget')
    context_raw = context_path.read_bytes()
    if len(context_raw) > 65536:
        raise ValueError('SDK Launcher context changed during read')
    context = json.loads(context_raw)
    if context.get('schema') != 1:
        raise ValueError('SDK Launcher context schema differs')
    sha = context['source_sha256']
    if digest(installed) != sha:
        raise ValueError('Installed SDK source differs')
    inputs = {str(installed): sha, str(context_path): hashlib.sha256(context_raw).hexdigest()}
    runner = load('sdk-batch-runner')
    native = document(context['native'], 'knowledge/sdk-batch-native-v1', root, inputs)
    generation_path = Path(context['generation']['path']).resolve()
    pin(inputs, generation_path, context['generation']['sha256'])
    generation, definition, roles, audit_template = runner.prepare(root, generation_path)
    if (definition['source_sha256'] != sha or native.get('definition') != definition
            or definition['generation'] != context['generation']):
        raise ValueError('SDK Launcher native definition differs')
    runner.validate_aggregate(root, native, definition, generation, roles, audit_template)
    runner.guard(definition)
    for path, expected in definition['files'].items():
        pin(inputs, path, expected)
    for pointer in list(native['components'].values()) + list(native['component_reports'].values()):
        pin(inputs, pointer['path'], pointer['sha256'])
    runtime = definition['runtime']
    pin(inputs, runtime['executable'], runtime['executable_sha256'])
    pin(inputs, runtime['crt']['path'], runtime['crt']['sha256'])
    distributions = importlib.metadata.distributions(path=[str(HERE.parents[2] / '.tools/vampir-analysis')])
    selected = {distribution.metadata['Name'].lower(): distribution for distribution in distributions
                if distribution.metadata['Name'].lower() in runtime['distributions']}
    for name, expected in runtime['distributions'].items():
        distribution = selected[name]
        if hashlib.sha256(distribution.read_text('RECORD').encode()).hexdigest() != expected['record_sha256']:
            raise ValueError('SDK Launcher analysis runtime metadata changed')
        record = next(file for file in distribution.files if str(file).endswith('.dist-info/RECORD'))
        path = distribution.locate_file(record)
        pin(inputs, path, digest(path))
    launcher = document(context['launcher'], 'code-clues/launcher-contract-v1', root, inputs)
    launcher_context_path = Path(context['launcher_context']['path']).resolve()
    if not launcher_context_path.is_relative_to((HERE / 'knowledge/native-contexts').resolve()):
        raise ValueError('SDK Launcher context outside native declarations')
    pin(inputs, launcher_context_path, context['launcher_context']['sha256'])
    launcher_context = json.loads(launcher_context_path.read_bytes())
    if (launcher.get('schema') != 1 or launcher.get('recipe') != 'launcher-contract-v1'
            or launcher.get('source_sha256') != sha or launcher.get('context') != context['launcher_context']
            or launcher.get('tool_sha256') != digest(HERE / 'audit-launcher-contract.py')
            or launcher_context['target']['source_sha256'] != sha
            or len(launcher.get('functions', [])) != 14 or len(launcher.get('keys', [])) != 10
            or {row['endpoint'] for row in launcher.get('requests', [])} != {'launcher/token', 'launcher/sign-in'}
            or any(launcher.get(key) is not False for key in ('native_execution', 'network_used', 'runtime_admitted', 'profile_activated'))):
        raise ValueError('SDK Launcher static proof differs')
    for pointer in launcher['evidence']:
        pin(inputs, pointer['path'], pointer['sha256'])
    for declaration in (launcher_context['baseline'], launcher_context['target']):
        source = root / 'client-code-snapshots' / declaration['source_sha256'] / 'ProjectRED-Win64-Shipping.exe'
        pin(inputs, source, declaration['source_sha256'])
    for filename in ('build-sdk-launcher-profile.py', 'audit-launcher-contract.py',
                     'audit-launcher-shape-11318.py', 'build-object-zero-init-code.py', 'extract-native-enums.py'):
        pin(inputs, HERE / filename, digest(HERE / filename))
    pin(inputs, LOADER, digest(LOADER))
    loader = load('sdk_launcher_profile_validator', LOADER)
    loader.validate_inputs(inputs, root=root, workspace=WORKSPACE, installed=installed)
    runner.guard(definition)
    if digest(context_path) != hashlib.sha256(context_raw).hexdigest() or digest(installed) != sha:
        raise ValueError('SDK Launcher source or context changed during build')
    return dict(schema=1, recipe='sdk-launcher-runtime-v1', source=str(installed), source_sha256=sha,
                **native['profile_candidate'], evidence=dict(native=context['native'], launcher=context['launcher'],
                    generation=context['generation'], components=native['component_reports'],
                    launcher_context=context['launcher_context']), inputs=dict(sorted(inputs.items())),
                crt_locale=runtime['crt']['locale'], native_case_executions=3667,
                primitive_cases=dict(numeric=112, channels=176), runtime_scope='sdk-launcher-auth',
                supported_auth_flows=['launcher'], direct_sdk_operations_verified=False,
                active_runtime_settings_verified=False, network_ready=False, game_protocol_verified=False,
                runtime_admitted=False, profile_activated=False,
                limits=['Existing 3667 SDK native cases and static Launcher proof are reused after full input checks.',
                        'Runtime composition uses HTTP/browser fixtures. Live authentication and game actions need separate checks.'])


def publish(profile, *, root=ROOT):
    root = Path(root).resolve()
    loader = load('sdk_launcher_profile_publish_validator', LOADER)
    loader.validate_inputs(profile['inputs'], root=root, workspace=WORKSPACE, installed=profile['source'])
    workflow = load('research-workflow')
    raw = workflow.canonical(profile)
    path = root / 'sdk-launcher-profiles' / hashlib.sha256(raw).hexdigest() / 'manifest.json'
    if path.exists() and path.read_bytes() != raw:
        raise ValueError('Immutable SDK Launcher profile differs')
    if not path.exists():
        workflow.atomic(path, raw)
    loader.load_manifest(profile_sha256=path.parent.name, source_sha256=profile['source_sha256'],
                         root=root, workspace=WORKSPACE, installed=profile['source'])
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--installed', type=Path, default=INSTALLED)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    args = parser.parse_args()
    result = build(root=args.root, installed=args.installed, context_path=args.context)
    path = publish(result, root=args.root)
    print(json.dumps(dict(profile=str(path), profile_sha256=path.parent.name,
                          source_sha256=result['source_sha256'], runtime_admitted=False)))
