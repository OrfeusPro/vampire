"""Explicit recovered-base profile for our client; not the game's active cache."""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.sdk_config import prepare_cdn_config_url_ascii
from vampir_core.login_context import bind_game_app_version

ROOT = Path('F:/PhoneExit Resources/Vampir')
SNAPSHOT = '393c0697115ec6beceeb0e822bed0f6907eab83dfe9a47f81e9c7875deff35db'
SOURCE_SHA = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'
PROFILES = {
    'recovered-base': (SNAPSHOT, SOURCE_SHA),
    'recovered-release': ('c67314cea3e6d3f28f98073a6f6346b1fa0233143feb6e18e7e0914a152f4c7d',
        '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'),
}
CANDIDATE = 'candidate-11316'
CURRENT_SHA = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
PROFILES[CANDIDATE] = ('12abc7a1cda6b050250662acab29155092484da595d50c0e93c2ffff42bfb145', CURRENT_SHA)
LATEST_CANDIDATE = 'candidate-11318'
LATEST_SHA = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
LATEST_CANDIDATE_MANIFEST = 'c8c3f905956ce66f2037f8f759b3e45b889ca4dce3032e4a24c04221d835a575'
LATEST_CONFIG = 'f93042b23066af7a5a6dfedaa554f12dc88302e4a9f260da4ced0538db7f5251'
PROFILES[LATEST_CANDIDATE] = (LATEST_CONFIG, LATEST_SHA)
# Source-bound pointer/literal offsets; HEADLESS-RELEASE-WIRE-TAG.md.
WIRE_TAGS = {
    SOURCE_SHA: (185899560, '30ec904901000000', 160487472, 'AC7F34E3AFA91ED417BE86CD45BF18C8'),
    '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e':
        (186362008, '401f964901000000', 160827200, '32283C4C6485307BCF524765A84409C3'),
}
WIRE_TAGS[CURRENT_SHA] = (186353816, '2000964901000000', 160819744, '32283C4C6485307BCF524765A84409C3')
WIRE_TAGS[LATEST_SHA] = (186363544, '2018964901000000', 160827424, '32283C4C6485307BCF524765A84409C3')


@dataclass(frozen=True, slots=True)
class BaseGameProfile:
    app_version: str
    config_prefix: str
    cdn_url: str
    source_snapshot_sha256: str
    active_game_cache_verified: bool = False
    compiled_tag: str = ''
    source_exe_sha256: str = ''
    live_probe_only: bool = False
    bounded_world_probe: bool = False


def verify_file(path, expected):
    with Path(path).open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != expected: raise ValueError('Game profile source changed; refresh extracted evidence')


def verify_compiled_tag(path, source_sha):
    if source_sha not in WIRE_TAGS: raise ValueError('No verified compiled tag for this source')
    pointer_offset, pointer_bytes, literal_offset, tag = WIRE_TAGS[source_sha]
    with Path(path).open('rb') as stream:
        stream.seek(pointer_offset)
        if stream.read(8) != bytes.fromhex(pointer_bytes): raise ValueError('Compiled tag source pointer changed')
        stream.seek(literal_offset)
        if stream.read(33) != (tag + '\0').encode('ascii'): raise ValueError('Compiled tag source literal changed')
    return tag


def load_profile(*, selected_profile, root=ROOT):
    if selected_profile not in PROFILES: raise ValueError('Select a verified recovered profile explicitly')
    snapshot, source_sha = PROFILES[selected_profile]
    if selected_profile == CANDIDATE:
        verify_candidate_evidence(root=root)
    if selected_profile == LATEST_CANDIDATE:
        verify_latest_candidate_evidence(root=root)
    path = Path(root) / 'resource-config-snapshots' / snapshot / 'manifest.json'
    if path.stat().st_size > 2097152: raise ValueError('Game profile manifest exceeds local budget')
    verify_file(path, snapshot)
    manifest = json.loads(path.read_text('utf-8'))
    if manifest['exe_sha256'] != source_sha: raise ValueError('Unsupported game client source')
    verify_file(manifest['source_exe'], source_sha)
    compiled_tag = verify_compiled_tag(manifest['source_exe'], source_sha)
    verify_file(manifest['source_archive']['path'], manifest['archive_sha256'])
    config = next(config for config in manifest['configs'] if config['snapshot_file'] == 'DefaultGame.ini')
    ini = path.parent / 'DefaultGame.ini'
    verify_file(ini, config['payload_sha256'])
    lines = ini.read_text('utf-8-sig').splitlines()
    values = {}
    for row in config['values']:
        if row['section'] != 'NetworkSetting': continue
        line = lines[row['line'] - 1].strip()
        key, separator, value = line.partition('=')
        if not separator or (key.strip(), value.strip()) != (row['key'], row['value']):
            raise ValueError('INI row provenance differs')
        if row['key'] in values: raise ValueError('Ambiguous recovered NetworkSetting')
        values[row['key']] = row['value']
    if values['CdnConfig'] != 'True': raise ValueError('Explicit base profile has no CDN config')
    url = prepare_cdn_config_url_ascii(normal=values['CdnConfigUrl'], qa=values['CdnConfigUrlQA'],
        prefix=values['ConfigPrefix'], app_version=values['AppVersion'], platform_code=2)
    return BaseGameProfile(values['AppVersion'], values['ConfigPrefix'], 'https://' + url, snapshot,
        compiled_tag=compiled_tag, source_exe_sha256=source_sha,
        live_probe_only=selected_profile in (CANDIDATE, LATEST_CANDIDATE),
        bounded_world_probe=selected_profile in (CANDIDATE, LATEST_CANDIDATE))


def verify_latest_candidate_evidence(*, root=ROOT):
    # This helper reads proof data with the standard library only. Native replay,
    # decompilation and analysis modules never run on the login path.
    sys.path.insert(0, str(HERE))
    from game_candidate_evidence import verify_candidate
    return verify_candidate(root=root, workspace=HERE.parents[2], source_sha=LATEST_SHA,
        candidate_sha=LATEST_CANDIDATE_MANIFEST, config_sha=LATEST_CONFIG)


def verify_candidate_evidence(*, root=ROOT):
    """Frozen offline evidence for an explicit read-only live experiment, not promotion."""
    evidence = json.loads((HERE / 'game-candidate-11316.json').read_text('utf-8'))
    if (evidence['source_sha256'] != CURRENT_SHA or
            evidence['capabilities'] != ['version', 'login', 'character-list', 'initial-ping', 'bounded-world-probe'] or
            evidence['live_verified'] is not False):
        raise ValueError('Candidate scope changed')
    required = {'native-archive-wire-checks', 'native-login-prepare-checks',
        'native-version-prepare-checks', 'native-version-result-checks',
        'native-version-result-handler-checks', 'native-login-result-checks',
        'native-waiting-end-checks', 'native-character-list-records-checks',
        'native-character-list-handler-checks', 'login-clock-11316', 'login-ping-11316', 'world-entry-11316'}
    reports = evidence['reports']
    if len(reports) != len(required) or {Path(item['path']).parts[1] for item in reports} != required:
        raise ValueError('Candidate evidence is incomplete')
    for item in evidence['reports']:
        path = Path(root) / item['path']
        verify_file(path, item['sha256'])
        report = json.loads(path.read_text('utf-8'))
        if (report['source_sha256'] != CURRENT_SHA or report['network_used'] is not False
                or report['profile_activated'] is not False):
            raise ValueError('Candidate evidence source or boundary differs')


def bind_profile(version, login, *, selected_profile, root=ROOT):
    profile = load_profile(selected_profile=selected_profile, root=root)
    version, login = bind_game_app_version(version, login, app_version=profile.app_version)
    return version, login, profile


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', choices=list(PROFILES), required=True)
    parser.add_argument('--check', action='store_true', required=True)
    args = parser.parse_args()
    try:
        profile = load_profile(selected_profile=args.profile)
        print(json.dumps(dict(profile=args.profile, app_version=profile.app_version,
            config_prefix=profile.config_prefix, source_snapshot_sha256=profile.source_snapshot_sha256,
            active_game_cache_verified=False, network_attempted=False)))
    except (OSError, ValueError, KeyError, StopIteration, IndexError):
        print(json.dumps(dict(error='source_profile_not_verified')))
        sys.exit(2)
