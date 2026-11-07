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


def publish(*, root=ROOT, manual_quest_start=False, quest_time_probe=False):
    if (type(manual_quest_start) is not bool or type(quest_time_probe) is not bool
            or (manual_quest_start and quest_time_probe)):
        raise ValueError('Select one explicit quest admission')
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
    quests = load('verify-quest-observation-current').verify(root=root)
    quests_report = json.loads(Path(quests['report']).read_bytes())
    reply = load('verify-quest-reply-current').verify(root=root)
    reply_report = json.loads(Path(reply['report']).read_bytes())
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
    merge(quests_report['definition']['inputs'])
    merge(reply_report['definition']['inputs'])
    clock_definition = clock_report.get('definition', {})
    merge(clock_definition.get('inputs', {}))
    merge(clock_definition.get('files', {}))
    merge(clock_definition.get('exports', {}))
    merge(clock_report.get('files', {}))
    for component in clock_report['components'].values():
        merge({component['path']: component['sha256']})
    merge({pointer['report']: pointer['sha256'], str(nested_path): nested['sha256'],
           clock['path']: clock['sha256'], stats['report']: stats['sha256'],
           notifications['report']: notifications['sha256'], quests['report']: quests['sha256'],
           reply['report']: reply['sha256'], str(selector): digest(selector)})
    loader_path = WORKSPACE / 'phone-exit/bots/vampir-headless/bounded-world-profile.py'
    loader = load('bounded_world_profile_loader', loader_path)
    files = entry_tool.consumers() | {Path(__file__).resolve(), loader_path,
        HERE / 'verify-world-results-current.py',
        WORKSPACE / 'phone-exit/bots/vampir-headless/run-bounded-world.py'}
    consumers = loader.CONSUMERS + (loader.TIME_PROBE_CONSUMERS if quest_time_probe else ())
    files |= {WORKSPACE / 'phone-exit/bots' / name for name in consumers}
    for path in files:
        inputs[str(path.resolve())] = digest(path)
    if any(digest(name) != expected for name, expected in inputs.items()):
        raise ValueError('Current world profile input changed before publication')
    profile = dict(schema=2, recipe='bounded-world-profile-v1', source_sha256=source, source=entry['source'],
        entry=dict(path=pointer['report'], sha256=pointer['sha256'], selected_profile=pointer['selected_profile']),
        proofs={'clock-world-current': clock,
                'initial-stats-current': dict(path=stats['report'],sha256=stats['sha256']),
                'stat-notifications-current': dict(path=notifications['report'],sha256=notifications['sha256']),
                'quest-observation-current': dict(path=quests['report'],sha256=quests['sha256']),
                'quest-reply-current': dict(path=reply['report'],sha256=reply['sha256']),
                'world-results-current': dict(path=str(nested_path), sha256=nested['sha256'])},
        inputs=inputs, operations=['character-select', 'world-entry', 'keep-online'],
        policies=loader.POLICIES + [loader.REPLY_POLICY],
        world_admitted=True, creation_admitted=False, online_verified=False,
        limits=['Fresh accepted list resolves the saved character key before selection.',
                'Headless completion and bounded periodic Ping reuse qualified native proofs.',
                'Initial character stats are a world-entry snapshot; admitted 321/322 notifications update the matching owner.',
                'QuestSync1854 and Tutorial9905 are bounded last received messages, not applied client task state.',
                'QuestUpdateResult1811 is observed for the matching owner; action confirmation requires separate evidence.',
                'No creation, movement, quest actions, dialogue or tutorial advance admission; explicit Stop or connection failure closes the owner.'])
    if manual_quest_start:
        start = load('verify-quest-start-current').verify(root=root)
        start_report = json.loads(Path(start['report']).read_bytes())
        merge(start_report['definition']['inputs'])
        merge({start['report']: start['sha256']})
        profile['schema'] = 3
        profile['proofs']['quest-start-current'] = dict(path=start['report'], sha256=start['sha256'])
        profile['policies'] = profile['policies'] + ['quest-start-manual-v1']
        profile['limits'][-1] = 'One explicitly selected manual QuestStart1803 attempt is admitted; no task updates, movement, completion or retry.'
        if any(digest(name) != expected for name, expected in inputs.items()):
            raise ValueError('Manual QuestStart profile input changed')
    if quest_time_probe:
        time = load('verify-quest-time-current').verify(root=root)
        time_proof = json.loads(Path(time['report']).read_bytes())
        wire_path = root / 'knowledge/quest-wire-native-checks-v1' / loader.TIME_PROBE_WIRE / 'manifest.json'
        if digest(wire_path) != loader.TIME_PROBE_WIRE:
            raise ValueError('Retained Time probe wire proof changed')
        wire = json.loads(wire_path.read_bytes())
        merge(time_proof['definition']['inputs'])
        merge(wire['inputs']['files'])
        merge(wire['inputs']['runtime']['files'])
        merge({item['path']: item['sha256'] for item in wire['exports']})
        merge({time['report']: time['sha256'], str(wire_path): loader.TIME_PROBE_WIRE})
        profile['schema'] = 4
        profile['proofs'].update({'quest-time-current': dict(path=time['report'], sha256=time['sha256']),
            'quest-update-wire-current': dict(path=str(wire_path), sha256=loader.TIME_PROBE_WIRE)})
        profile['policies'].append(loader.TIME_PROBE_POLICY)
        profile['limits'][-1] = ('One explicitly enabled probe sends 1810 for quest 110110 index 0 '
            'using fresh ID206 server target in world 10010. The probe does not establish actor placement or full quest execution.')
        if any(digest(name) != expected for name, expected in inputs.items()):
            raise ValueError('Time probe profile input changed')
    path = load('audit-client-release').save_snapshot(root / 'bounded-world-profiles', profile)
    sha = digest(path)
    loader.load_manifest(sha, root=root, workspace=WORKSPACE)
    return dict(report=str(path), sha256=sha, selected_profile='bounded-world:' + sha, inputs=len(inputs))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    quest = parser.add_mutually_exclusive_group()
    quest.add_argument('--manual-quest-start', action='store_true')
    quest.add_argument('--quest-time-probe', action='store_true')
    args = parser.parse_args()
    print(json.dumps(publish(root=args.root, manual_quest_start=args.manual_quest_start,
                             quest_time_probe=args.quest_time_probe)))
