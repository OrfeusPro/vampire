"""Assemble a separate immutable profile for one bounded character-list entry."""
import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
WORKSPACE = HERE.parents[3]
CONSUMERS = (
    'vampir-headless/bounded-entry-profile.py', 'vampir-headless/game-source-profile.py',
    'vampir-headless/probe-lobby-connection.py', 'vampir-headless/probe-lobby-sdk-login.py',
    'vampir-headless/probe-lobby-version.py', 'vampir-headless/probe-selected-game-login.py',
    'vampir-headless/probe-selected-game-version.py', 'vampir-headless/probe-game-version.py',
    'vampir-headless/run-nid-sdk-sign-in.py', 'vampir-headless/windows-system-inputs.py',
    'vampir-headless/run-bounded-entry.py', 'vampir-headless/verify-account.py',
    'resource-tools/vampir/fetch-public-cdn-config.py',
)
CORE_CONSUMERS = (
    'bounded_entry_admission', 'runtime_admission', 'sdk_launcher_admission', 'lobby_current',
    'lobby_login_probe', 'lobby_version_probe', 'lobby_packets', 'lobby_login_result', 'lobby_login_error',
    'lobby_server_list', 'cdn_config', 'cdn_servers', 'session_clock', 'game_login_probe',
    'game_connection', 'login_packet', 'login_result', 'login_context', 'character_list',
    'selection_flow', 'receive_stream', 'send_frame', 'frame_primitives', 'outbound',
    'game_server_target', 'windows_version',
    'windows_device_identity', 'gmc2_context', 'direct_route', 'socks_route', 'bot_device_settings',
)


def load(name, path=None):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path or HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def consumers():
    core = WORKSPACE / 'phone-exit/bots/vampir-shared/vampir_core'
    pending = [WORKSPACE / 'phone-exit/bots' / name for name in CONSUMERS]
    pending += [core / (name + '.py') for name in CORE_CONSUMERS]
    visited = set()
    while pending:
        path = pending.pop().resolve()
        if path in visited:
            continue
        visited.add(path)
        for node in ast.walk(ast.parse(path.read_text('utf-8'))):
            if not isinstance(node, ast.ImportFrom) or not node.module:
                continue
            if node.module.startswith('vampir_core.'):
                name = node.module.split('.')[1]
            elif node.level == 1 and path.parent == core:
                name = node.module.split('.')[0]
            else:
                continue
            dependency = core / (name + '.py')
            if dependency.is_file():
                pending.append(dependency)
    return visited


def publish(*, root=ROOT):
    root = Path(root).resolve()
    candidate_path, candidate_sha, candidate = load('build-game-candidate-current').publish(root=root)
    inputs = dict(candidate['inputs'])
    inputs[str(candidate_path)] = candidate_sha
    proofs = {}
    for identifier in ('lobby-login-prepare-current', 'lobby-sender-current', 'lobby-results-current'):
        result = load('verify-' + identifier).verify(root=root)
        report = json.loads(Path(result['report']).read_bytes())
        if (report['source_sha256'] != candidate['source_sha256'] or report['network_used'] is not False
                or report['runtime_admitted'] is not False):
            raise ValueError('Bounded entry component scope differs')
        for name, sha in report['definition']['inputs'].items():
            if name in inputs and inputs[name] != sha:
                raise ValueError('Bounded entry proofs have conflicting inputs')
            inputs[name] = sha
        inputs[result['report']] = result['sha256']
        proofs[identifier] = dict(path=result['report'], sha256=result['sha256'])
    for path in consumers() | {Path(__file__).resolve()}:
        inputs[str(path.resolve())] = digest(path)
    patch = Path(candidate['source']).parents[2] / 'Saved/PersistentDownloadDir/Patch/windows.manifestlist'
    inputs[str(patch)] = digest(patch)
    if any(digest(name) != sha for name, sha in inputs.items()):
        raise ValueError('Bounded entry profile input changed before publication')
    loader = load('bounded_entry_profile', WORKSPACE / 'phone-exit/bots/vampir-headless/bounded-entry-profile.py')
    profile = dict(schema=1, recipe=loader.RECIPE, source_sha256=candidate['source_sha256'],
        source=candidate['source'], game_profile=candidate['game_profile'],
        sdk_profile_sha256=candidate['sdk_profile']['sha256'], candidate=dict(path=str(candidate_path), sha256=candidate_sha),
        operations=loader.OPERATIONS, policies=loader.POLICIES, proofs=proofs, inputs=inputs,
        online_verified=False, world_admitted=False, creation_admitted=False,
        limits=['Fresh launcher SDK, direct/explicit SOCKS CDN and lobby, then game Login/character list only.',
                'Recovered base config and explicit local empty owner kind preserve component fixture boundaries.',
                'Source transfer and native semantic evidence do not imply online server acceptance.',
                'No character creation/selection, world-session, quests or stats admission.'])
    path = load('audit-client-release').save_snapshot(root / 'bounded-entry-profiles', profile)
    sha = digest(path)
    loader.load_manifest(sha, root=root, workspace=WORKSPACE)
    return dict(report=str(path), sha256=sha, selected_profile='bounded-entry:' + sha, inputs=len(inputs))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(publish(root=args.root)))
