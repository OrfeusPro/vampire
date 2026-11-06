"""Prepare current world admission only after both complete result layouts agree."""
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
    nested = load('verify-world-results-current').verify(root=root)
    nested_path = Path(nested['report']).resolve()
    results = json.loads(nested_path.read_bytes())
    if results.get('compatible_with_portable_codecs') is not True:
        raise ValueError('Complete current Select110 and Finish206 compatibility is not verified')
    stats = load('verify-initial-stats-current').verify(root=root)
    stats_report = json.loads(Path(stats['report']).read_bytes())
    notifications = load('verify-stat-notifications-current').verify(root=root)
    notifications_report = json.loads(Path(notifications['report']).read_bytes())
    entry_tool = load('build-bounded-entry-current')
    pointer = entry_tool.publish(root=root)
    entry = json.loads(Path(pointer['report']).read_bytes())
    selector = HERE / 'knowledge/entry-native-current.json'
    clock = json.loads(selector.read_bytes())['proofs']['clock-world-current']
    if digest(clock['path']) != clock['sha256']:
        raise ValueError('Current world clock proof changed')
    clock_report = json.loads(Path(clock['path']).read_bytes())
    source = entry['source_sha256']
    if (clock_report['source_sha256'] != source or results['source_sha256'] != source
            or clock_report.get('network_used') is not False or results.get('network_used') is not False):
        raise ValueError('Current world proof source or boundary differs')
    inputs = dict(entry['inputs'])
    def merge(values):
        for name, expected in values.items():
            if name in inputs and inputs[name] != expected:
                raise ValueError('Current world retained inputs conflict')
            inputs[name] = expected
    merge(results['definition']['inputs'])
    merge(stats_report['definition']['inputs'])
    merge(notifications_report['definition']['inputs'])
    clock_definition = clock_report.get('definition', {})
    merge(clock_definition.get('inputs', {}))
    merge(clock_definition.get('files', {}))
    merge(clock_definition.get('exports', {}))
    merge(clock_report.get('files', {}))
    for component in clock_report['components'].values():
        merge({component['path']: component['sha256']})
    merge({pointer['report']: pointer['sha256'], str(nested_path): nested['sha256'],
           clock['path']: clock['sha256'], stats['report']: stats['sha256'],
           notifications['report']: notifications['sha256'], str(selector): digest(selector)})
    loader_path = WORKSPACE / 'phone-exit/bots/vampir-headless/bounded-world-profile.py'
    loader = load('bounded_world_profile_loader', loader_path)
    files = entry_tool.consumers() | {Path(__file__).resolve(), loader_path,
        HERE / 'verify-world-results-current.py',
        WORKSPACE / 'phone-exit/bots/vampir-headless/run-bounded-world.py'}
    files |= {WORKSPACE / 'phone-exit/bots' / name for name in loader.CONSUMERS}
    for path in files:
        inputs[str(path.resolve())] = digest(path)
    if any(digest(name) != expected for name, expected in inputs.items()):
        raise ValueError('Current world profile input changed before publication')
    profile = dict(schema=1, recipe='bounded-world-profile-v1', source_sha256=source, source=entry['source'],
        entry=dict(path=pointer['report'], sha256=pointer['sha256'], selected_profile=pointer['selected_profile']),
        proofs={'clock-world-current': clock,
                'initial-stats-current': dict(path=stats['report'],sha256=stats['sha256']),
                'stat-notifications-current': dict(path=notifications['report'],sha256=notifications['sha256']),
                'world-results-current': dict(path=str(nested_path), sha256=nested['sha256'])},
        inputs=inputs, operations=['character-select', 'world-entry', 'keep-online'],
        policies=['game-login-world-v1', 'world-selection-move-v1', 'periodic-ping-v1', 'initial-character-stats-v1', 'character-stat-notifications-v1'],
        world_admitted=True, creation_admitted=False, online_verified=False,
        limits=['Fresh accepted list resolves the saved character key before selection.',
                'Headless completion and bounded periodic Ping reuse qualified native proofs.',
                'Initial character stats are a world-entry snapshot; admitted 321/322 notifications update the matching owner.',
                'No creation, movement, quests or tutorial admission; explicit Stop or connection failure closes the owner.'])
    path = load('audit-client-release').save_snapshot(root / 'bounded-world-profiles', profile)
    sha = digest(path)
    loader.load_manifest(sha, root=root, workspace=WORKSPACE)
    return dict(report=str(path), sha256=sha, selected_profile='bounded-world:' + sha, inputs=len(inputs))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(publish(root=args.root)))
