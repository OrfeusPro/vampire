"""Immutable admission for a single current Viper Create operation."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
WORKSPACE = HERE.parents[3]


def load(name, path=None):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path or HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def publish(*, root=ROOT):
    root = Path(root).resolve()
    entry_tool = load('build-bounded-entry-current')
    entry_pointer = entry_tool.publish(root=root)
    entry = json.loads(Path(entry_pointer['report']).read_bytes())
    factory_pointer = load('build-viper-creation-current').verify(root=root)
    factory_path = Path(factory_pointer['report']).resolve()
    factory = json.loads(factory_path.read_bytes())
    if (factory.get('source_sha256') != entry['source_sha256'] or factory.get('runtime_admitted') is not False
            or factory.get('world_admitted', False) is not False or factory.get('network_used') is not False
            or factory.get('model_only') is not True or factory.get('verified_loaded_asset') is not False):
        raise ValueError('Current Viper factory source or scope differs')
    inputs = dict(entry['inputs'])
    inputs[entry_pointer['report']] = entry_pointer['sha256']
    for name, expected in factory['definition']['inputs'].items():
        if name in inputs and inputs[name] != expected:
            raise ValueError('Current Create profile inputs conflict')
        inputs[name] = expected
    inputs[str(factory_path)] = factory_pointer['sha256']
    files = entry_tool.consumers()
    files |= {Path(__file__).resolve(), HERE / 'build-viper-creation-current.py',
              WORKSPACE / 'phone-exit/bots/vampir-headless/bounded-creation-profile.py',
              WORKSPACE / 'phone-exit/bots/vampir-headless/run-bounded-create.py',
              WORKSPACE / 'phone-exit/bots/vampir-shared/vampir_core/bounded_creation_admission.py'}
    for path in files:
        inputs[str(path.resolve())] = digest(path)
    if any(digest(name) != expected for name, expected in inputs.items()):
        raise ValueError('Current Create profile input changed before publication')
    loader_path = WORKSPACE / 'phone-exit/bots/vampir-headless/bounded-creation-profile.py'
    loader = load('bounded_creation_profile_loader', loader_path)
    for relative in loader.CONSUMERS:
        path = WORKSPACE / 'phone-exit/bots' / relative
        inputs[str(path)] = digest(path)
    profile = dict(schema=1, recipe='bounded-creation-profile-v1', source_sha256=entry['source_sha256'],
        entry=dict(path=entry_pointer['report'], sha256=entry_pointer['sha256'],
                   selected_profile=entry_pointer['selected_profile']),
        factory=dict(path=str(factory_path), sha256=factory_pointer['sha256']), inputs=inputs,
        operations=['character-create'], policy='character-create-current-v1',
        world_admitted=False, creation_admitted=True, online_verified=False,
        limits=['One explicit Viper candidate after an accepted fresh empty list on the same Login connection.',
                'Persistent attempt journal forbids blind retries; selection and world remain separate operations.',
                'Model appearance and Latin keys are explicit choices; no loaded asset or prior online Create claim.'])
    path = load('audit-client-release').save_snapshot(root / 'bounded-creation-profiles', profile)
    sha = digest(path)
    loader.load_manifest(sha, root=root, workspace=WORKSPACE)
    return dict(report=str(path), sha256=sha, selected_profile='bounded-create:' + sha, inputs=len(inputs))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(publish(root=args.root)))
